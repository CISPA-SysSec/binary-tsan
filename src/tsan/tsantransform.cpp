#include "tsantransform.h"

#include <irdb-elfdep>
#include <memory>
#include <algorithm>

#include "simplefile.h"
#include "helper.h"
#include "exceptionhandling.h"

using namespace IRDB_SDK;

TSanTransform::TSanTransform(FileIR_t *file) :
    Transform_t(file),
    functionAnalysis(file)
{ }

TSanTransform::~TSanTransform()
{
    InternalInstrumentationMap instrumentationMap;
    for (const auto &instr : instrumentationAttribution) {
        instrumentationMap.mutable_instrumentation()->insert({instr.instrumentation->getBaseID(), instr.info});
    }

    // TODO: define the filename in the common module
    writeProtobufToFile(instrumentationMap, "tsan-attribution.dat");
}

bool TSanTransform::parseArgs(const std::vector<std::string> &options)
{
    const auto parsedOptions = Options::parseAndProcess(getFileIR(), options);
    if (!parsedOptions.has_value()) {
        return false;
    }
    this->options = parsedOptions.value();
    return true;
}

bool TSanTransform::executeStep()
{
    FileIR_t *ir = getFileIR();
    functionAnalysis.init(options);

    for (auto function : ir->getFunctions()) {
        if (startsWith(function->getName(), "__tsan_func_entry")) {
            std::cout <<"ERROR: this binary is already thread sanitized!"<<std::endl;
            return false;
        }
    }

    registerDependencies();

    ExceptionHandling exceptionHandling(ir, tsanFunctionExit[0].callTarget);

    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init", "__tsan_default_options", "_fini", "__libc_csu_fini",
                                                            "ThisIsNotAFunction", "__gmon_start__", "__do_global_ctors_aux", "__do_global_dtors_aux"};

    findAndMergeFunctions();

    for (Function_t *function : ir->getFunctions()) {
        if (function->getEntryPoint() == nullptr) {
            continue;
        }
        const std::string functionName = function->getName();
        const bool ignoreFunction = std::find(noInstrumentFunctions.begin(), noInstrumentFunctions.end(), functionName) != noInstrumentFunctions.end();
        if (ignoreFunction) {
            continue;
        }
        if (contains(functionName, "@plt")) {
            continue;
        }
        if (options.instrumentOnlyFunctions.size() > 0 && options.instrumentOnlyFunctions.find(functionName) == options.instrumentOnlyFunctions.end()) {
            continue;
        }
        }

        const FunctionInfo info = functionAnalysis.analyseFunction(function);

        // for the stack trace translation
        for (Instruction_t *instruction : function->getInstructions()) {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            if (decoded->isCall()) {
                InstrumentationInfo instrumentationInfo;
                instrumentationInfo.set_original_address(instruction->getAddress()->getVirtualOffset());
                instrumentationInfo.set_function_has_entry_exit(info.addEntryExitInstrumentation);
                Instrumentation im;
                im.instrumentation = instruction;
                im.info = instrumentationInfo;
                instrumentationAttribution.push_back(im);
            }
        }

        // make a copy of the instruction set before changing it
        const std::set<Instruction_t*> instructions = function->getInstructions();

        // instrument all memory operations
        for (Instruction_t *instruction : info.instructionsToInstrument) {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            const DecodedOperandVector_t operands = decoded->getOperands();
            for (const auto &operand : operands) {
                if (operand->isMemory()) {
//                    std::cout <<"Instrument access: "<<instruction->getDisassembly()<<", "<<instruction->getFunction()->getName()<<std::endl;
                    instrumentMemoryAccess(instruction, operand, info);
                    // For instructions like rep movs with two memory operands, only call the handler once.
                    // It is correctly handed in the rep instruction handler.
                    // If the movs instruction occurs without the rep prefix however, add two separate instrumentations
                    if (decoded->hasRelevantRepPrefix() || decoded->hasRelevantRepnePrefix()) {
                        break;
                    }
                }
            }
        }

        // add instrumentation for the annotations
        getFileIR()->assembleRegistry();
        for (Instruction_t *instruction : instructions) {
            if (instruction->getTarget() == nullptr || instruction->getTarget()->getFunction() == nullptr) {
                continue;
            }
            auto targetFunction = instruction->getTarget()->getFunction();
            auto annotationIt = options.annotations.happensBefore.find(targetFunction);
            if (annotationIt == options.annotations.happensBefore.end()) {
                continue;
            }
            std::cout <<"Add instrumentation for annotation at: "<<std::hex<<instruction->getAddress()->getVirtualOffset()<<" "<<disassembly(instruction)<<std::endl;
            instrumentAnnotation(instruction, annotationIt->second, info);
        }

        if (info.addEntryExitInstrumentation && options.instrumentFunctionEntryExit) {
            // TODO: what if the first instruction is atomic and thus removed?
            insertFunctionEntry(function, info.properEntryPoint);
            for (Instruction_t *ret : info.exitPoints) {
                insertFunctionExit(ret);
            }

            getFileIR()->assembleRegistry();

            InstructionInserter inserter(ir, function->getEntryPoint(), functionAnalysis.getInstructionCounter(InstrumentationType::EXCEPTION_HANDLING), options.dryRun);
            exceptionHandling.handleFunction(function, inserter);
        }
        getFileIR()->assembleRegistry();
    }

    functionAnalysis.printStatistics();

    return true;
}

static void mergeFunctions(Function_t *f1, Function_t *f2)
{
    std::cout <<"Merge functions: "<<f1->getName()<<" "<<f2->getName()<<std::endl;
    std::set<Instruction_t*> instructions = f1->getInstructions();
    for (auto i : f2->getInstructions()) {
        i->setFunction(f1);
        instructions.insert(i);
    }
    f1->setInstructions(instructions);
    f2->setInstructions({});
    f2->setEntryPoint(nullptr);
}

void TSanTransform::findAndMergeFunctions()
{
    std::set<Instruction_t*> noPredecessor;
    for (Function_t *function : getFileIR()->getFunctions()) {
        const auto cfg = ControlFlowGraph_t::factory(function);
        for (const auto block : cfg->getBlocks()) {
            if (block->getPredecessors().size() == 0) {
                noPredecessor.insert(block->getInstructions()[0]);
            }
        }
    }
    for (Function_t *function : getFileIR()->getFunctions()) {
        for (Instruction_t *i : function->getInstructions()) {
            const auto decoded = DecodedInstruction_t::factory(i);
            if (decoded->isConditionalBranch() && i->getTarget() != nullptr) {
                if (i->getTarget()->getFunction() != function && i->getTarget()->getFunction() != nullptr) {
                    mergeFunctions(function, i->getTarget()->getFunction());
                    break;
                }
            }
            if (decoded->getMnemonic() == "jmp" && i->getTarget() != nullptr && i->getTarget()->getFunction() != nullptr &&
                    i->getTarget()->getFunction() != function && i->getTarget() != i->getTarget()->getFunction()->getEntryPoint() &&
                    noPredecessor.find(i->getTarget()) == noPredecessor.end()) {

                mergeFunctions(function, i->getTarget()->getFunction());
                break;
            }
        }
    }
    getFileIR()->assembleRegistry();
}

void TSanTransform::insertFunctionEntry(Function_t *function, Instruction_t *insertBefore)
{
    // TODO: is it necessary to save the flags here too? (if yes, then also fix the rsp adjustment)
    FileIR_t *ir = getFileIR();
    const LibraryFunction functionEntry = selectFunctionVersion(insertBefore, tsanFunctionEntry);
    CallerSaveRegisterSet ignoreRegisters = Register::xmmRegisterSet() | functionEntry.preserveRegisters;
    ignoreRegisters &= ~Register::registerSet({functionEntry.argumentRegister});
    const std::vector<std::string> registersToSave = getSaveRegisters(insertBefore, ignoreRegisters);
    InstructionInserter inserter(ir, insertBefore, functionAnalysis.getInstructionCounter(InstrumentationType::ENTRY_EXIT), options.dryRun);

    // for this to work without any additional rsp wrangling, it must be inserted at the very start of the function
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }
    if (registersToSave.size() > 0) {
        const std::string argumentRegister = Register::registerToString(functionEntry.argumentRegister);
        inserter.insertAssembly("mov " + argumentRegister + ", [rsp + " + toHex(registersToSave.size() * ir->getArchitectureBitWidth() / 8) + "]");
    }
    if (options.addTsanCalls) {
        inserter.insertAssembly("call 0", functionEntry.callTarget);
    }
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }

    // jump targets that go to the very beginning of the function must skip the entry instrumentation
    // TODO: recursive tail call to itself
    // TODO: fallthrough to the function entry
    // TODO: endbr instruction might be in the way
    if (options.dryRun) {
        return;
    }
    getFileIR()->assembleRegistry();
    Instruction_t *originalInstruction = inserter.getLastInserted()->getFallthrough();
    for (auto instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (instruction->getTarget() == insertBefore && !decoded->isCall()) {
            instruction->setTarget(originalInstruction);
        }
    }
}

void TSanTransform::insertFunctionExit(Instruction_t *insertBefore)
{
    FileIR_t *ir = getFileIR();
    const LibraryFunction functionExit = selectFunctionVersion(insertBefore, tsanFunctionExit);
    InstructionInserter inserter(ir, insertBefore, functionAnalysis.getInstructionCounter(InstrumentationType::ENTRY_EXIT), options.dryRun);

    const auto decoded = DecodedInstruction_t::factory(insertBefore);
    const bool isSimpleReturn = decoded->isReturn();

    // must be inserted directly before the return instruction
    if (isSimpleReturn) {
        const std::vector<std::string> registersToSave = getSaveRegisters(insertBefore, Register::xmmRegisterSet() | functionExit.preserveRegisters);
        for (std::string reg : registersToSave) {
            inserter.insertAssembly("push " + reg);
        }
        if (options.addTsanCalls) {
            inserter.insertAssembly("call 0", functionExit.callTarget);
        }
        for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
            inserter.insertAssembly("pop " + *it);
        }
    } else {
        // modified by the first insertion
        Instruction_t *callTarget = insertBefore->getTarget();
        // 16 byte stack alignment for function calls
        inserter.insertAssembly("sub rsp, 0x8");
        auto callInstruction = inserter.insertAssembly("call 0", callTarget);

        // set exception handling info
        // cie program: def_cfa: r7 (rsp) ofs 8, cfa_offset 1
        const std::vector<std::string> cieProg = {{0x0c, 0x07, 0x08}, {(char)0x90, 0x01}};
        // fde program: def_cfa: r7 (rsp) ofs 16
        const std::vector<std::string> fdeProg = {{0x0c, 0x07, 0x10}};
        getFileIR()->addEhProgram(callInstruction, 1, -8, 16, 8, cieProg, fdeProg);

        inserter.insertAssembly("add rsp, 0x8");
        inserter.insertAssembly("push rax");
        inserter.insertAssembly("push rcx");
        if (options.addTsanCalls) {
            inserter.insertAssembly("call 0", functionExit.callTarget);
        }
        inserter.insertAssembly("pop rcx");
        inserter.insertAssembly("pop rax");
        inserter.insertAssembly("ret");
        // the original jmp instruction is now unreachable, just leave it
    }
}

void TSanTransform::instrumentAnnotation(IRDB_SDK::Instruction_t *instruction, const std::vector<HappensBeforeAnnotation> &annotations, const FunctionInfo &info)
{
    InstructionInserter inserter(getFileIR(), instruction, functionAnalysis.getInstructionCounter(InstrumentationType::MEMORY_ACCESS), options.dryRun);
    std::vector<HappensBeforeAnnotation> afterAnnotations;
    for (const auto &annotation : annotations) {
        if (annotation.isBefore) {
            const SaveStateInfo saveState = saveStateToStack(inserter, instruction, {}, info);
            if (annotation.registerForPointer != "rdi") {
                inserter.insertAssembly("mov rdi, " + annotation.registerForPointer);
            }
            // TODO: these functions might not be sse safe
            const LibraryFunctionOptions &target = annotation.operation == HappensBeforeOperation::Acquire ? tsanAcquire : tsanRelease;
            inserter.insertAssembly("call 0", target[0].callTarget);
            restoreStateFromStack(saveState, inserter);
        } else {
            afterAnnotations.push_back(annotation);
        }
    }
    if (afterAnnotations.size() == 0) {
        return;
    }

    const auto decoded = DecodedInstruction_t::factory(instruction);
    if (!decoded->isCall()) {
        std::cout <<"WARNING: skipping after annotations for instruction: "<<disassembly(instruction)<<std::endl;
        return;
    }

    for (const auto &annot : afterAnnotations) {
        inserter.insertAssembly("push " + annot.registerForPointer);
    }
    // the stack must be aligned to 16 bytes for a function call
    if (afterAnnotations.size() % 2 == 1) {
        inserter.insertAssembly("sub rsp, 8");
    }
    // TODO: this function must not throw an exception
    inserter.insertAssembly("call 0", afterAnnotations[0].function->getEntryPoint());
    if (afterAnnotations.size() % 2 == 1) {
        inserter.insertAssembly("add rsp, 8");
    }
    // TODO: this does not work if registerForPointer is rax or rdx
    for (auto it = afterAnnotations.rbegin();it!=afterAnnotations.rend();it++) {
        inserter.insertAssembly("pop " + it->registerForPointer);
    }

    for (const auto &annotation : afterAnnotations) {
        const SaveStateInfo saveState = saveStateToStack(inserter, nullptr, {}, info);
        if (annotation.registerForPointer != "rdi") {
            inserter.insertAssembly("mov rdi, " + annotation.registerForPointer);
        }
        // TODO: these functions might not be sse safe
        const LibraryFunctionOptions &target = annotation.operation == HappensBeforeOperation::Acquire ? tsanAcquire : tsanRelease;
        inserter.insertAssembly("call 0", target[0].callTarget);
        restoreStateFromStack(saveState, inserter);
    }

    if (!options.dryRun) {
        auto inserted = inserter.getLastInserted();
        inserted->setFallthrough(inserted->getFallthrough()->getFallthrough());
    }
}

LibraryFunction TSanTransform::selectFunctionVersion(IRDB_SDK::Instruction_t *before, const LibraryFunctionOptions &options) const
{
    // no need for the map lookup
    if (options.size() == 1) {
        return options[0];
    }
    const CallerSaveRegisterSet dead = functionAnalysis.getDeadRegisters(before);
    for (const auto &f : options) {
        if (Register::hasCallerSaveRegister(dead, f.argumentRegister)) {
            return f;
        }
    }
    return options[0];
}

std::vector<std::string> TSanTransform::getSaveRegisters(Instruction_t *instruction, CallerSaveRegisterSet ignoreRegisters)
{
    const CallerSaveRegisterSet dead = functionAnalysis.getDeadRegisters(instruction);
    const CallerSaveRegisterSet registersToSave = ~(dead | ignoreRegisters);
    std::vector<std::string> result;
    for (std::size_t i = 0;i<registersToSave.size();i++) {
        if (registersToSave[i]) {
            const x86_reg reg = Register::getCallerSaveRegisterForIndex(i);
            if (reg != X86_REG_EFLAGS) {
                result.push_back(Register::registerToString(reg));
            }
        }
    }
    return result;
}

static RegisterID getScratchRegister(const std::string &operand, const std::vector<RegisterID> &possibleRegisters)
{
    for (const RegisterID &reg : possibleRegisters) {
        bool hasReg = false;
        for (int opSize : {8, 4, 2, 1}) {
            const std::string regString = toBytes(reg, opSize);
            if (contains(operand, regString)) {
                hasReg = true;
                break;
            }
        }
        if (!hasReg) {
            return reg;
        }
    }
    // if three or more registers are given, this can never happen
    return RegisterID::rn_RAX;
}

static x86_reg stringToReg(const std::string &reg)
{
    // TODO: direct conversion
    return Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(reg));
}

static LibraryFunctionOptions stripPreservedRegisters(const LibraryFunctionOptions &function)
{
    return {LibraryFunction(function[0].callTarget)};
}

std::optional<OperationInstrumentation> TSanTransform::getAtomicInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> &operand,
                                                                                const __tsan_memory_order memoryOrder) const
{
    // possible atomic instructions: ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B, DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG and XOR.
    const uint bytes = operand->getArgumentSizeInBytes();

    const auto decoded = DecodedInstruction_t::factory(instruction);
//    std::cout <<"Found atomic instruction with mnemonic: "<<decoded->getMnemonic()<<std::endl;
    // TODO: 128 bit operations?
    const std::string mnemonic = decoded->getMnemonic();
    const std::string rsiReg = toBytes(RegisterID::rn_RSI, bytes);
    const std::string rdiReg = toBytes(RegisterID::rn_RDI, bytes);
    const std::string rdxReg = toBytes(RegisterID::rn_RDX, bytes);
    const std::string raxReg = toBytes(RegisterID::rn_RAX, bytes);
    const std::string memOrder = toHex(memoryOrder);

    // TODO: if op1 contains the rsp, then it has to be offset
    const auto op0 = decoded->getOperand(0);
    if (!decoded->hasOperand(1)) {
        if (mnemonic == "inc" || mnemonic == "dec") {
            const LibraryFunctionOptions &tsanFunction = mnemonic == "inc" ? tsanAtomicFetchAdd[bytes] : tsanAtomicFetchSub[bytes];
            const LibraryFunctionOptions strippedFunction = stripPreservedRegisters(tsanFunction);
            return OperationInstrumentation({
                    "mov rsi, 1",
                    "mov rdx, " + memOrder,
                    "pushfq",
                    "call 0",
                    "popfq",
                    // create correct flags otherwise created by the original instruction
                    // it is important to use the subregister of rax with the correct size for the overflow flag
                    mnemonic + " " + raxReg
                },
                {strippedFunction}, REMOVE_ORIGINAL_INSTRUCTION, Register::registerSet({X86_REG_EFLAGS}));
        }
        std::cout <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
        return {};
    }
    const auto op1 = decoded->getOperand(1);

    const auto nonMemoryOperand = op0->isMemory() ? op1 : op0;
    const RegisterID scratch = getScratchRegister(nonMemoryOperand->getString(), {RegisterID::rn_R8, RegisterID::rn_R9, RegisterID::rn_R10});
    const std::string scratchReg = toBytes(scratch, 8);
    const bool opHasRdi = contains(nonMemoryOperand->getString(), rdiReg);
    const std::string replacedNonMemoryOperand = opHasRdi ? toBytes(scratch, bytes) : nonMemoryOperand->getString();

    if (mnemonic == "xadd") {
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                "mov rdx, " + memOrder,
                "push " + standard64Bit(replacedNonMemoryOperand),
                "call 0",
                "pop rdi",
                // create correct flags otherwise created by the xadd instruction
                // TODO: preserve other flags
                // TODO: only do this when the flags are alive after the instruction
                "add " + rdiReg + ", " + raxReg,
                "mov " + op1->getString() + ", " + raxReg
            },
            {stripPreservedRegisters(tsanAtomicFetchAdd[bytes])}, REMOVE_ORIGINAL_INSTRUCTION,
            Register::registerSet({stringToReg(standard64Bit(op1->getString())), X86_REG_EFLAGS}));
    }
    // assumption: op0 is memory, op1 is register or constant
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" || mnemonic == "xor") {
        LibraryFunctionOptions f;
        if (mnemonic == "add") {
            f = tsanAtomicFetchAdd[bytes];
        } else if (mnemonic == "sub") {
            f = tsanAtomicFetchSub[bytes];
        } else if (mnemonic == "and") {
            f = tsanAtomicFetchAnd[bytes];
        } else if (mnemonic == "or") {
            f = tsanAtomicFetchOr[bytes];
        } else if (mnemonic == "xor") {
            f = tsanAtomicFetchXor[bytes];
        }
        const LibraryFunctionOptions strippedFunction = stripPreservedRegisters(f);
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                "mov rdx, " + memOrder,
                op1->isRegister() ? "push " + standard64Bit(replacedNonMemoryOperand) : "",
                "call 0",
                op1->isRegister() ? "pop " + standard64Bit(replacedNonMemoryOperand) : "",
                // create correct flags otherwise created by the original instruction
                // TODO: only do this when the flags are alive after the instruction
                mnemonic + " " + raxReg + ", " + replacedNonMemoryOperand
            },
            {strippedFunction}, REMOVE_ORIGINAL_INSTRUCTION, Register::registerSet({X86_REG_EFLAGS}));
    }
    // assumption: op0 is memory, op1 is register
    if (mnemonic == "cmpxchg") {
        // (Slightly modified) documentation of the cmpxchg instruction:
        // Compares the value in the EAX register with the first operand (destination).
        // If the two values are equal, the second operand is loaded into the destination operand.
        // Otherwise, the destination operand is loaded into the EAX register.
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rdxReg + ", " + replacedNonMemoryOperand,
                "mov " + rsiReg + ", " + raxReg,
                "mov rcx, " + memOrder,
                "mov r8, " + toHex(__tsan_memory_order_relaxed),
                "push rax",
                "call 0",
                "pop rsi",
                "cmp " + raxReg + ", " + rsiReg // make sure flags are set correctly (cmpxchg would otherwise set them)
            },
            {stripPreservedRegisters(tsanAtomicCompareExchangeVal[bytes])}, REMOVE_ORIGINAL_INSTRUCTION, Register::registerSet({X86_REG_RAX, X86_REG_EFLAGS}));
    }
    if (mnemonic == "mov") {
        if (op0->isRegister() && op1->isMemory()) {
            return OperationInstrumentation({
                    "mov rsi, " + toHex(__tsan_memory_order_acquire),
                    "call 0",
                    "mov " + op0->getString() + ", " + raxReg
                },
                {stripPreservedRegisters(tsanAtomicLoad[bytes])}, REMOVE_ORIGINAL_INSTRUCTION,
                Register::registerSet({stringToReg(standard64Bit(op0->getString()))}));

        } else if ((op1->isRegister() || op1->isConstant()) && op0->isMemory()) {
            return OperationInstrumentation({
                    opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                    MOVE_OPERAND_RDI,
                    "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                    "mov rdx, " + toHex(__tsan_memory_order_release),
                    "call 0"
                },
                {stripPreservedRegisters(tsanAtomicStore[bytes])}, REMOVE_ORIGINAL_INSTRUCTION, {});
        }
    }
    if (mnemonic == "xchg") {
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                "mov rdx, " + memOrder,
                "call 0",
                "mov " + nonMemoryOperand->getString() + ", " + raxReg
            },
            {stripPreservedRegisters(tsanAtomicExchange[bytes])}, REMOVE_ORIGINAL_INSTRUCTION,
            Register::registerSet({stringToReg(standard64Bit(nonMemoryOperand->getString()))}));
    }
    std::cout <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
//    throw std::invalid_argument("Unhandled atomic instruction");
    return {};
}

std::optional<OperationInstrumentation> TSanTransform::getRepInstrumentation(Instruction_t *instruction, const std::unique_ptr<DecodedInstruction_t> &decoded) const
{
    if (decoded->hasRelevantRepPrefix() || decoded->hasRelevantRepnePrefix()) {
//        std::cout <<"Repeated: "<<instruction->getDisassembly()<<std::endl;

        const std::string repPrefix = decoded->hasRelevantRepPrefix() ? "rep " : "repne ";

        // the rep instructions that use two memory locations at rdi and rsi
        const bool isMovs = startsWith(decoded->getMnemonic(), "movs");
        const bool isCmps = startsWith(decoded->getMnemonic(), "cmps");
        if (isMovs || isCmps) {

            const LibraryFunctionOptions &firstTsanCall = isMovs ? tsanWriteRange : tsanReadRange;
            const std::string originalRdiVal = "rax";
            const std::string originalRsiVal = "rdx";
            return OperationInstrumentation({
                    // store copy of the original rdi and rsi
                    "mov " + originalRdiVal + ", rdi",
                    "mov " + originalRsiVal + ", rsi",
                    // the rep movs/cmps instructions needs registers rcx, rdi, rsi
                    repPrefix + instruction->getDisassembly(),
                    "pushfq",
                    "push rdi",
                    "push rsi",
                    "push rcx",
                    "cmp rdi, " + originalRdiVal,
                    "jl %L1",
                    // make rdi (/rsi) contain the lower of the two pointers
                    "xchg rdi, " + originalRdiVal,
                    "xchg rsi, " + originalRsiVal,
                     // rsi is needed as an argument, store the value away
                    "L1: xchg rsi, " + originalRdiVal,
                    "sub rsi, rdi",
                    "push rsi",
                    "push " + originalRdiVal,
                    "call 0", // tsanWriteRange/tsanReadRange
                    "pop rdi",
                    "pop rsi",
                    "call 0", // tsanReadRange
                    "pop rcx",
                    "pop rsi",
                    MOVE_OPERAND_RDI, // sort of a hack to avoid having it at the beginning
                    "pop rdi",
                    "popfq"
                },
                {stripPreservedRegisters(firstTsanCall), stripPreservedRegisters(tsanReadRange)}, REMOVE_ORIGINAL_INSTRUCTION,
                Register::registerSet({X86_REG_RDI, X86_REG_RSI, X86_REG_RCX, X86_REG_EFLAGS}));
        }

        // the rep instructions that use only one memory location in rsi
        const bool isStos = startsWith(decoded->getMnemonic(), "stos");
        const bool isScas = startsWith(decoded->getMnemonic(), "scas");
        if (isStos || isScas) {
            const LibraryFunctionOptions &firstTsanCall = isStos ? tsanWriteRange : tsanReadRange;
            return OperationInstrumentation({
                    // store copy of the original rdi
                    "mov rsi, rdi",
                    // the rep stos/scas instructions needs registers rcx, rdi
                    repPrefix + instruction->getDisassembly(),
                    "pushfq",
                    "push rdi",
                    "push rcx",
                    "cmp rdi, rsi",
                    "jl %L1",
                    // make rdi contain the lower of the two pointers
                    "xchg rdi, rsi",
                    "L1: sub rsi, rdi",
                    "call 0", // tsanWriteRange/tsanReadRange
                    "pop rcx",
                    "pop rdi",
                    "popfq"
                },
                {stripPreservedRegisters(firstTsanCall)}, REMOVE_ORIGINAL_INSTRUCTION,
                Register::registerSet({X86_REG_RDI, X86_REG_RCX, X86_REG_EFLAGS}));
        }

        std::cout <<"WARNING: unhandled rep instruction: "<<disassembly(instruction)<<std::endl;
    }
    return {};
}

std::optional<OperationInstrumentation> TSanTransform::getConditionalInstrumentation(const std::unique_ptr<DecodedInstruction_t> &decoded,
                                                                                     const std::shared_ptr<DecodedOperand_t> &operand) const
{
    const std::string mnemonic = decoded->getMnemonic();
    const bool isCMov = startsWith(mnemonic, "cmov");
    const bool isSet = startsWith(mnemonic, "set");
    if (isCMov || isSet) {
        const int bytes = operand->getArgumentSizeInBytes();
        const std::string mnemonicStart = isCMov ? "cmov" : "set";
        const std::string conditionalJump = "j" + std::string(mnemonic.begin() + mnemonicStart.size(), mnemonic.end());
        const LibraryFunctionOptions &target = isCMov ? tsanRead[bytes] : tsanWrite[bytes];
        return OperationInstrumentation({
                // this is the easiest way to invert the condition without handling all the different cases
                conditionalJump + " %L1",
                "jmp %L2",
                // needed as a jump target if tsan calls are not added (therefore, the label can not be at the call instruction)
                "L1: xor rax, rax",
                "call 0",
                // just needed as a jump target for the label
                "L2: xor rax, rax"
            },
            {stripPreservedRegisters(target)}, KEEP_ORIGINAL_INSTRUCTION, {});
    }
    return {};
}

TSanTransform::SaveStateInfo TSanTransform::saveStateToStack(InstructionInserter &inserter, Instruction_t *before,
                                                             CallerSaveRegisterSet ignoreRegisters, const FunctionInfo &info)
{
    SaveStateInfo state;

    const bool stackUnsafe = info.stackUnsafe.find(before) != info.stackUnsafe.end() || info.isLeafFunction;

    if (!options.saveXmmRegisters) {
        ignoreRegisters |= Register::xmmRegisterSet();
    }
    std::vector<std::string> registersToSave = getSaveRegisters(before, ignoreRegisters);
    for (const auto &reg : registersToSave) {
        if (startsWith(reg, "xmm")) {
            state.xmmRegistersToSave.push_back(reg);
        } else {
            state.generalPurposeRegistersToSave.push_back(reg);
        }
    }

    bool eflagsAlive = true;
    const CallerSaveRegisterSet deadRegisterSet = functionAnalysis.getDeadRegisters(before);
    eflagsAlive = !Register::hasCallerSaveRegister(deadRegisterSet, X86_REG_EFLAGS);
    state.flagsAreSaved = eflagsAlive && !Register::hasCallerSaveRegister(ignoreRegisters, X86_REG_EFLAGS);

    // TODO: add this only once per function and not at every access
    // honor redzone / general stack unsafe regions
    state.directStackOffset = (stackUnsafe ? 256 : 0) + state.xmmRegistersToSave.size() * 16;
    if (state.directStackOffset > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp - " + toHex(state.directStackOffset) + "]");
    }
    for (std::size_t i = 0;i<state.xmmRegistersToSave.size();i++) {
        inserter.insertAssembly("movdqu [rsp + " + toHex(i * 16) + "], " + state.xmmRegistersToSave[i]);
    }
    if (state.flagsAreSaved) {
        // if this is changed, change the rsp offset in the lea rdi instruction as well
        inserter.insertAssembly("pushfq");
    }
    for (const std::string &reg : state.generalPurposeRegistersToSave) {
        inserter.insertAssembly("push " + reg);
    }

    const int flagSize = state.flagsAreSaved ? 8 : 0;
    state.totalStackOffset = state.directStackOffset + state.generalPurposeRegistersToSave.size() * 8 + flagSize;
    return state;
}

void TSanTransform::restoreStateFromStack(const SaveStateInfo &state, InstructionInserter &inserter)
{
    for (auto it = state.generalPurposeRegistersToSave.rbegin();it != state.generalPurposeRegistersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (state.flagsAreSaved) {
        inserter.insertAssembly("popfq");
    }
    for (std::size_t i = 0;i<state.xmmRegistersToSave.size();i++) {
        inserter.insertAssembly("movdqu " + state.xmmRegistersToSave[i] + ", [rsp + " + toHex(i * 16) + "]");
    }
    if (state.directStackOffset > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp + " + toHex(state.directStackOffset) + "]");
    }
}

static uint instrumentationByteSize(const std::shared_ptr<DecodedOperand_t> &operand)
{
    const uint bytes = operand->getArgumentSizeInBytes();
    // Instructions with 10 byte operands are most likely extended precision floating point operations.
    // For alignment, compilers usually allocate either 12 or 16 byte for them.
    // Since we do not know what is the case, downgrade it to 8 byte.
    // This is correct, but could theoretically miss some rather contrived race conditions.
    if (bytes == 10) {
        return 8;
    }
    return bytes;
}

std::optional<OperationInstrumentation> TSanTransform::getInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand,
                                                           const FunctionInfo &info) const
{
    const auto inferredIt = info.inferredAtomicInstructions.find(instruction);
    const bool isInferredAtomic = inferredIt != info.inferredAtomicInstructions.end();
    const auto decoded = DecodedInstruction_t::factory(instruction);
    // the xchg instruction is always atomic, even without the lock prefix
    const bool isExchange = decoded->getMnemonic() == "xchg";
    const bool atomic = isAtomic(instruction) || isInferredAtomic || isExchange;
    if (atomic) {
        if (options.noInstrumentAtomics) {
            return {};
        }
        const __tsan_memory_order memOrder = isInferredAtomic ? inferredIt->second : __tsan_memory_order_acq_rel;
        auto instrumentation = getAtomicInstrumentation(instruction, operand, memOrder);
        if (instrumentation.has_value()) {
            return instrumentation;
        }
    }

    if (options.atomicsOnly) {
        return {};
    }

    // check for rep string instructions
    auto repInstrumentation = getRepInstrumentation(instruction, decoded);
    if (repInstrumentation.has_value()) {
        return repInstrumentation;
    }

    // check for conditional memory instructions (cmov)
    auto conditionalInstrumentation = getConditionalInstrumentation(decoded, operand);
    if (conditionalInstrumentation.has_value()) {
        return conditionalInstrumentation;
    }

    // For operations that read and write the memory, only emit the write (it is sufficient for race detection)
    const uint bytes = instrumentationByteSize(operand);
    if (operand->isWritten()) {
        return OperationInstrumentation({"call 0"}, {tsanWrite[bytes]}, KEEP_ORIGINAL_INSTRUCTION, {});
    } else {
        return OperationInstrumentation({"call 0"}, {tsanRead[bytes]}, KEEP_ORIGINAL_INSTRUCTION, {});
    }
}

void TSanTransform::instrumentMemoryAccess(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand, const FunctionInfo &info)
{
    const auto decoded = DecodedInstruction_t::factory(instruction);

    InstrumentationInfo instrumentationInfo;
    instrumentationInfo.set_original_address(instruction->getAddress()->getVirtualOffset());
    instrumentationInfo.set_disassembly(disassembly(instruction));
    instrumentationInfo.set_function_has_entry_exit(info.addEntryExitInstrumentation);

    const uint bytes = instrumentationByteSize(operand);
    if (!options.dryRun && (bytes >= tsanRead.size() || bytes >= tsanWrite.size() ||
            (operand->isRead() && tsanRead[bytes][0].callTarget == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes][0].callTarget == nullptr))) {
        std::cout <<"WARNING: memory operation of size "<<bytes<<" is not instrumented: "<<instruction->getDisassembly()<<std::endl;
        return;
    }

    FileIR_t *ir = getFileIR();

    const auto instr = getInstrumentation(instruction, operand, info);
    // could not instrument - command line option or some other problem
    if (!instr) {
        return;
    }
    OperationInstrumentation instrumentation = *instr;

    InstructionInserter inserter(ir, instruction, functionAnalysis.getInstructionCounter(InstrumentationType::MEMORY_ACCESS), options.dryRun);

    std::vector<LibraryFunction> callTargets;
    callTargets.reserve(instrumentation.callTargets.size());
    CallerSaveRegisterSet requiredSaveRegisters;
    for (const auto &target : instrumentation.callTargets) {
        LibraryFunction selectedTarget = selectFunctionVersion(instruction, target);
        bool hasDirectTarget = false;
        if (operand->isMemory() && operand->hasBaseRegister() && !operand->hasIndexRegister() && !operand->hasMemoryDisplacement()) {
            // TODO: direct conversion
            const x86_reg reg = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(operand->getString()));
            for (const LibraryFunction &f : target) {
                if (f.argumentRegister == reg) {
                    selectedTarget = f;
                    hasDirectTarget = true;
                }
            }
        }
        if (!hasDirectTarget) {
            Register::setCallerSaveRegister(requiredSaveRegisters, selectedTarget.argumentRegister);
        }
        requiredSaveRegisters |= ~selectedTarget.preserveRegisters;
        callTargets.push_back(selectedTarget);
    }
    const CallerSaveRegisterSet ignoreRegisters = instrumentation.noSaveRegisters | ~requiredSaveRegisters;
    const SaveStateInfo saveState = saveStateToStack(inserter, instruction, ignoreRegisters, info);

    // the instruction pointer no longer points to the original instruction, make sure that it is not used
    instruction = nullptr;

    if (std::find(instrumentation.instructions.begin(), instrumentation.instructions.end(), MOVE_OPERAND_RDI) == instrumentation.instructions.end()) {
        instrumentation.instructions.insert(instrumentation.instructions.begin(), MOVE_OPERAND_RDI);
    }

    // TODO: aligned vs unaligned read/write?
    std::map<std::string, Instruction_t*> jumpTargetsToResolve;
    std::map<std::string, Instruction_t*> labels;
    for (const auto &assembly : instrumentation.instructions) {
        if (assembly.size() == 0) {
            continue;
        }
        if (assembly == MOVE_OPERAND_RDI) {
            const std::string argumentRegister = Register::registerToString(callTargets[0].argumentRegister);
            if (operand->getString() == argumentRegister) {
                // nothing to do, the address is already in the target register
            } else if (operand->isPcrel()) {
                // The memory displacement is relative the rip at the start of the NEXT instruction
                // The lea instruction should have 7 bytes (if the memory displacement is encoded with 4 byte)
                const auto offset = operand->getMemoryDisplacement() + decoded->length() - 7;
                auto inserted = inserter.insertAssembly("lea " + argumentRegister + ", [rel " + toHex(offset) + "]");
                if (!options.dryRun) {
                    ir->addNewRelocation(inserted, 0, "pcrel");
                }
            } else {
                if (contains(operand->getString(), "rsp")) {
                    inserter.insertAssembly("lea " + argumentRegister + ", [" + operand->getString() + " + " + toHex(saveState.totalStackOffset) + "]");
                } else {
                    inserter.insertAssembly("lea " + argumentRegister + ", [" + operand->getString() + "]");
                }
            }
        } else {

            // TODO: move the jump logic into the instruction inserter
            std::string strippedAssembly = assembly;

            // % precedes a label name for a jump target, for example jge %L1
            const bool isJumpWithLabel = contains(assembly, "%");
            std::string labelName;
            if (isJumpWithLabel) {
                const std::vector<std::string> instrParts = split(assembly, '%');
                if (instrParts.size() != 2) {
                    // TODO: better exception types?
                    throw std::invalid_argument("ERROR: incorrect jump target definition!");
                }
                strippedAssembly = instrParts[0] + " 0";
                labelName = instrParts[1];
            }
            // label definitions include a :, for example L1: test ax, ax
            const bool definesLabel = contains(assembly, ":");
            if (definesLabel) {
                const std::vector<std::string> instrParts = split(assembly, ':');
                if (instrParts.size() != 2) {
                    throw std::invalid_argument("ERROR: incorrect label definition!");
                }
                labelName = instrParts[0];
                strippedAssembly = instrParts[1];
            }

            const bool isCall = contains(strippedAssembly, "call");
            Instruction_t *callTarget = nullptr;
            if (isCall) {
                callTarget = callTargets[0].callTarget;
                callTargets.erase(callTargets.begin());
                if (!options.addTsanCalls) {
                    continue;
                }
            }
            auto inserted = inserter.insertAssembly(strippedAssembly, callTarget);

            if (isJumpWithLabel && !options.dryRun) {
                jumpTargetsToResolve[labelName] = inserted;
            }
            if (definesLabel && !options.dryRun) {
                labels[labelName] = inserted;
            }

            if (isCall && !options.dryRun) {
                Instrumentation im;
                im.instrumentation = inserted;
                im.info = instrumentationInfo;
                instrumentationAttribution.push_back(im);
            }
        }
    }

    // resolve jump targets with labels
    for (auto &[label, instruction] : jumpTargetsToResolve) {
        auto it = labels.find(label);
        if (it == labels.end()) {
            throw std::invalid_argument("ERROR: could not find label!");
        }
        instruction->setTarget(it->second);
    }

    restoreStateFromStack(saveState, inserter);

    if (instrumentation.removeOriginalInstruction == REMOVE_ORIGINAL_INSTRUCTION && !options.dryRun) {
        auto inserted = inserter.getLastInserted();
        inserted->setFallthrough(inserted->getFallthrough()->getFallthrough());
    }
}

LibraryFunctionOptions TSanTransform::createWrapper(Instruction_t *target)
{
    LibraryFunctionOptions result;
    for (x86_reg reg : {X86_REG_RDI, X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11}) {
        auto instruction = addNewAssembly("ret");
        instruction->getAddress()->setFileID(getFileIR()->getFile()->getBaseID());
        instruction->setFunction(target->getFunction());
        auto instructionCounter = functionAnalysis.getInstructionCounter(InstrumentationType::WRAPPER);
        instructionCounter();

        InstructionInserter inserter(getFileIR(), instruction, instructionCounter, options.dryRun);

        FunctionInfo info;
        info.isLeafFunction = false;
        const SaveStateInfo saveState = saveStateToStack(inserter, nullptr, {}, info);

        if (reg != X86_REG_RDI) {
            inserter.insertAssembly("mov rdi, " + Register::registerToString(reg));
        }
        inserter.insertAssembly("mov rsi, [rsp + " + toHex(saveState.totalStackOffset) + "]");
        inserter.insertAssembly("call 0", target);

        restoreStateFromStack(saveState, inserter);

        // this wrapper preserves all registers, even the argument register
        LibraryFunction f(instruction, reg);
        f.preserveRegisters.set();
        result.push_back(f);
    }

    return result;
}

void TSanTransform::registerDependencies()
{
    auto elfDeps = ElfDependencies_t::factory(getFileIR());

    // for shared libraries, it is not necessary (and sometimes harmful) to add this as the executable will also have it
    if (options.addLibTsanDependency) {
        elfDeps->prependLibraryDepedencies("libgcc_s.so.1");
        elfDeps->prependLibraryDepedencies("libstdc++.so.6");
        elfDeps->prependLibraryDepedencies("libm.so.6");
        if (options.useCustomLibTsan) {
            elfDeps->prependLibraryDepedencies("libc.so.6");
            elfDeps->prependLibraryDepedencies("libdl.so.2");
            elfDeps->prependLibraryDepedencies("libpthread.so.0");
            elfDeps->prependLibraryDepedencies(LIBTSANLOCATION);
        } else {
            elfDeps->prependLibraryDepedencies("libtsan.so.0");
        }
    }
    if (options.useWrapperFunctions) {
        tsanFunctionEntry = createWrapper(elfDeps->appendPltEntry("__tsan_func_entry"));
        tsanFunctionExit = createWrapper(elfDeps->appendPltEntry("__tsan_func_exit"));
    } else {
        tsanFunctionEntry = {elfDeps->appendPltEntry("__tsan_func_entry")};
        tsanFunctionExit = {elfDeps->appendPltEntry("__tsan_func_exit")};
    }
    for (int s : {1, 2, 4, 8, 16}) {
        if (options.useWrapperFunctions) {
            tsanWrite[s] = createWrapper(elfDeps->appendPltEntry("__tsan_write" + std::to_string(s) + "_pc"));
            tsanRead[s] = createWrapper(elfDeps->appendPltEntry("__tsan_read" + std::to_string(s) + "_pc"));
        } else {
            tsanWrite[s] = {elfDeps->appendPltEntry("__tsan_write" + std::to_string(s))};
            tsanRead[s] = {elfDeps->appendPltEntry("__tsan_read" + std::to_string(s))};
        }
        tsanAtomicLoad[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_load")};
        tsanAtomicStore[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_store")};
        tsanAtomicExchange[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_exchange")};
        tsanAtomicFetchAdd[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_add")};
        tsanAtomicFetchSub[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_sub")};
        tsanAtomicFetchAnd[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_and")};
        tsanAtomicFetchOr[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_or")};
        tsanAtomicFetchXor[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_xor")};
        tsanAtomicCompareExchangeVal[s] = {elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_compare_exchange_val")};
    }
    tsanReadRange = {elfDeps->appendPltEntry("__tsan_read_range")};
    tsanWriteRange = {elfDeps->appendPltEntry("__tsan_write_range")};
    tsanAcquire = {elfDeps->appendPltEntry("__tsan_acquire")};
    tsanRelease = {elfDeps->appendPltEntry("__tsan_release")};

    getFileIR()->assembleRegistry();
}
