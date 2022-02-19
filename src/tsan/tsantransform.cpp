#include "tsantransform.h"

#include <irdb-elfdep>
#include <memory>
#include <algorithm>

#include "simplefile.h"
#include "helper.h"
#include "deadregisteranalysis.h"
#include "fixedpointanalysis.h"
#include "exceptionhandling.h"

using namespace IRDB_SDK;

TSanTransform::TSanTransform(FileIR_t *file) :
    Transform_t(file)
{
    std::fill(tsanRead.begin(), tsanRead.end(), nullptr);
    std::fill(tsanWrite.begin(), tsanWrite.end(), nullptr);
}

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
    for (const std::string &option : options) {
        // TODO: adjust options
        if (option == "--use-stars") {
            deadRegisterAnalysisType = DeadRegisterAnalysisType::STARS;
        } else if (option == "--no-use-stars") {
            deadRegisterAnalysisType = DeadRegisterAnalysisType::CUSTOM;
        } else if (option == "--dry-run") {
            dryRun = true;
        } else {
            std::cout <<"Unrecognized option: "<<option<<std::endl;
            return false;
        }
    }
    return true;
}

bool TSanTransform::executeStep()
{
    FileIR_t *ir = getFileIR();

    // compute this before any instructions are added
    if (deadRegisterAnalysisType == DeadRegisterAnalysisType::STARS) {
        const auto registerAnalysis = DeepAnalysis_t::factory(ir);
        deadRegisters = registerAnalysis->getDeadRegisters();
    } else {
        deadRegisters = std::make_unique<DeadRegisterMap_t>(DeadRegisterMap_t());
    }

    if (!dryRun) {
        registerDependencies();
    }

    ExceptionHandling exceptionHandling(ir, tsanFunctionExit);

    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init", "__tsan_default_options", "_fini", "__libc_csu_fini"};

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

        // register analysis
        if (deadRegisterAnalysisType == DeadRegisterAnalysisType::CUSTOM) {
            deadRegisters.reset(new DeadRegisterMap_t());

            if (FixedPointAnalysis::canHandle(function)) {
                const auto analysisResult = FixedPointAnalysis::runBackwards<DeadRegisterInstructionAnalysis, DeadRegisterAnalysisCommon>(function);
                for (const auto &[instruction, analysis] : analysisResult) {
                    deadRegisters->insert({instruction, analysis.getDeadRegisters()});
                }
            }
        }

        const FunctionInfo info = functionAnalysis.analyseFunction(ir, function);

        // for the stack frame translation
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

        if (info.addEntryExitInstrumentation) {
            // TODO: what if the first instruction is atomic and thus removed?
            insertFunctionEntry(info.properEntryPoint);
            for (Instruction_t *ret : info.exitPoints) {
                insertFunctionExit(ret);
            }

            getFileIR()->assembleRegistry();

            InstructionInserter inserter(ir, function->getEntryPoint(), functionAnalysis.getInstructionCounter(), dryRun);
            exceptionHandling.handleFunction(function, inserter);
        }
        getFileIR()->assembleRegistry();
    }

    functionAnalysis.printStatistics();

    return true;
}

static std::string toHex(const int num)
{
    std::stringstream result;
    result <<"0x"<<std::hex<<num;
    return result.str();
}

void TSanTransform::insertFunctionEntry(Instruction_t *insertBefore)
{
    // TODO: is it necessary to save the flags here too? (if yes, then also fix the rsp adjustment)
    FileIR_t *ir = getFileIR();
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore);
    InstructionInserter inserter(ir, insertBefore, functionAnalysis.getInstructionCounter(), dryRun);

    // for this to work without any additional rsp wrangling, it must be inserted at the very start of the function
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }
    if (registersToSave.size() > 0) {
        inserter.insertAssembly("mov rdi, [rsp + " + toHex(registersToSave.size() * ir->getArchitectureBitWidth() / 8) + "]");
    }
    inserter.insertAssembly("call 0", tsanFunctionEntry);
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
}

void TSanTransform::insertFunctionExit(Instruction_t *insertBefore)
{
    FileIR_t *ir = getFileIR();
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore);
    InstructionInserter inserter(ir, insertBefore, functionAnalysis.getInstructionCounter(), dryRun);

    const auto decoded = DecodedInstruction_t::factory(insertBefore);
    const bool isSimpleReturn = decoded->isReturn();

    // must be inserted directly before the return instruction
    if (!isSimpleReturn) {
        // if the "return" instruction is something like a jmp (from a tailcall), then there might be function arguments on the stack
        inserter.insertAssembly("sub rsp, 0xff");
    }
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }
    inserter.insertAssembly("call 0", tsanFunctionExit);
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (!isSimpleReturn) {
        inserter.insertAssembly("add rsp, 0xff");
    }
}

std::set<std::string> TSanTransform::getSaveRegisters(Instruction_t *instruction)
{
    std::set<std::string> registersToSave = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"};
    const auto dead = deadRegisters->find(instruction);
    if (dead != deadRegisters->end()) {
        for (RegisterID_t r : dead->second) {
            std::string longName = registerToString(convertRegisterTo64bit(r));
            std::transform(longName.begin(), longName.end(), longName.begin(), ::tolower);
            registersToSave.erase(longName);
        }
    }
    return registersToSave;
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

static std::string replaceRegister(const std::string &operand, const RegisterID original, const RegisterID replace)
{
    for (int opSize : {8, 4, 2, 1}) {
        const std::string origString = toBytes(original, opSize);
        const auto it = operand.find(origString);
        if (it != std::string::npos) {
            const std::string replaceString = toBytes(replace, opSize);
            std::string modified = operand;
            modified.replace(it, it + origString.size(), replaceString);
            return modified;
        }
    }
    return operand;
}

std::optional<OperationInstrumentation> TSanTransform::getAtomicInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> &operand,
                                                                                const __tsan_memory_order memoryOrder) const
{
    // https://wiki.osdev.org/X86-64_Instruction_Encoding
    // possible: ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B, DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG and XOR.
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

    // TODO: maybe just modify the tsan functions to not perform the operation, easier that way?
    // TODO: if op1 contains the rsp, then it has to be offset
    const auto op0 = decoded->getOperand(0);
    if (!decoded->hasOperand(1)) {
        // TODO: handle inc, dec
        std::cout <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
        return {};
    }
    const auto op1 = decoded->getOperand(1);

    const auto nonMemoryOperand = op0->isMemory() ? op1 : op0;
    const RegisterID scratch = getScratchRegister(nonMemoryOperand->getString(), {RegisterID::rn_R8, RegisterID::rn_R9, RegisterID::rn_R10});
    const std::string scratchReg = toBytes(scratch, 8);
    const bool opHasRdi = contains(nonMemoryOperand->getString(), rdiReg);
    const std::string replacedNonMemoryOperand = replaceRegister(nonMemoryOperand->getString(), RegisterID::rn_RDI, scratch);

    if (mnemonic == "xadd") {
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                "mov rdx, " + memOrder,
                "call 0",
                "mov " + op1->getString() + ", " + raxReg
            },
            {tsanAtomicFetchAdd[bytes]}, REMOVE_ORIGINAL_INSTRUCTION,
            {standard64Bit(op1->getString())}, NO_PRESERVE_FLAGS);
    }
    // assumption: op0 is memory, op1 is register or constant
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" || mnemonic == "xor") {
        Instruction_t *f = nullptr;
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
        return OperationInstrumentation({
                opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                MOVE_OPERAND_RDI,
                "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                "mov rdx, " + memOrder,
                "call 0"
            }, // TODO: flags
            {f}, REMOVE_ORIGINAL_INSTRUCTION, {}, NO_PRESERVE_FLAGS);
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
                "mov r8, " + memOrder,
                "push rax",
                "call 0",
                "pop rsi",
                "cmp " + raxReg + ", " + rsiReg // make sure flags are set correctly (cmpxchg would otherwise set them)
            },
            {tsanAtomicCompareExchangeVal[bytes]}, REMOVE_ORIGINAL_INSTRUCTION, {"rax"}, NO_PRESERVE_FLAGS);
    }
    if (mnemonic == "mov") {
        if (op0->isRegister() && op1->isMemory()) {
            return OperationInstrumentation({
                    "mov rsi, " + memOrder,
                    "call 0",
                    "mov " + op0->getString() + ", " + raxReg
                },
                {tsanAtomicLoad[bytes]}, REMOVE_ORIGINAL_INSTRUCTION,
                {standard64Bit(op0->getString())}, PRESERVE_FLAGS);

        } else if ((op1->isRegister() || op1->isConstant()) && op0->isMemory()) {
            return OperationInstrumentation({
                    opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                    MOVE_OPERAND_RDI,
                    "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                    "mov rdx, " + memOrder,
                    "call 0"
                },
                {tsanAtomicStore[bytes]}, REMOVE_ORIGINAL_INSTRUCTION, {}, PRESERVE_FLAGS);
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
            {tsanAtomicExchange[bytes]}, REMOVE_ORIGINAL_INSTRUCTION,
            {standard64Bit(nonMemoryOperand->getString())}, PRESERVE_FLAGS);
    }
    std::cout <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
//    throw std::invalid_argument("Unhandled atomic instruction");
    return {};
}

std::optional<OperationInstrumentation> TSanTransform::getRepInstrumentation(Instruction_t *instruction, const std::unique_ptr<DecodedInstruction_t> &decoded) const
{
    if (decoded->hasRelevantRepPrefix() || decoded->hasRelevantRepnePrefix()) {
        std::cout <<"Repeated: "<<instruction->getDisassembly()<<std::endl;

        const std::string repPrefix = decoded->hasRelevantRepPrefix() ? "rep " : "repne ";

        // the rep instructions that use two memory locations at rdi and rsi
        const bool isMovs = startsWith(decoded->getMnemonic(), "movs");
        const bool isCmps = startsWith(decoded->getMnemonic(), "cmps");
        if (isMovs || isCmps) {

            Instruction_t *firstTsanCall = isMovs ? tsanWriteRange : tsanReadRange;
            const std::string originalRdiVal = "rax";
            const std::string originalRsiVal = "rdx";
            return OperationInstrumentation({
                    // store copy of the original rdi and rsi
                    "mov " + originalRdiVal + ", rdi",
                    "mov " + originalRsiVal + ", rsi",
                    // the rep movs/cmps instructions needs registers rcx, rdi, rsi
                    repPrefix + instruction->getDisassembly(),
                    "pushf",
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
                    "popf"
                },
                {firstTsanCall, tsanReadRange}, REMOVE_ORIGINAL_INSTRUCTION,
                {"rdi", "rsi", "rcx"}, NO_PRESERVE_FLAGS);
        }

        // the rep instructions that use only one memory location in rsi
        const bool isStos = startsWith(decoded->getMnemonic(), "stos");
        const bool isScas = startsWith(decoded->getMnemonic(), "scas");
        if (isStos || isScas) {
            Instruction_t *firstTsanCall = isStos ? tsanWriteRange : tsanReadRange;
            return OperationInstrumentation({
                    // store copy of the original rdi
                    "mov rsi, rdi",
                    // the rep stos/scas instructions needs registers rcx, rdi
                    repPrefix + instruction->getDisassembly(),
                    "pushf",
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
                    "popf"
                },
                {firstTsanCall}, REMOVE_ORIGINAL_INSTRUCTION,
                {"rdi", "rcx"}, NO_PRESERVE_FLAGS);
        }

        std::cout <<"WARNING: unhandled rep instruction: "<<disassembly(instruction)<<std::endl;
    }
    return {};
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

OperationInstrumentation TSanTransform::getInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand,
                                                           const FunctionInfo &info) const
{
    const auto inferredIt = info.inferredAtomicInstructions.find(instruction);
    const bool isInferredAtomic = inferredIt != info.inferredAtomicInstructions.end();
    const auto decoded = DecodedInstruction_t::factory(instruction);
    // the xchg instruction is always atomic, even without the lock prefix
    const bool isExchange = decoded->getMnemonic() == "xchg";
    const bool atomic = isAtomic(instruction) || isInferredAtomic || isExchange;
    if (atomic) {
        const __tsan_memory_order memOrder = isInferredAtomic ? inferredIt->second : __tsan_memory_order_acq_rel;
        auto instrumentation = getAtomicInstrumentation(instruction, operand, memOrder);
        if (instrumentation.has_value()) {
            return *instrumentation;
        }
    }

    // check for rep string instructions
    auto repInstrumentation = getRepInstrumentation(instruction, decoded);
    if (repInstrumentation.has_value()) {
        return *repInstrumentation;
    }

    // For operations that read and write the memory, only emit the write (it is sufficient for race detection)
    const uint bytes = instrumentationByteSize(operand);
    if (operand->isWritten()) {
        return OperationInstrumentation({"call 0"}, {tsanWrite[bytes]}, KEEP_ORIGINAL_INSTRUCTION, {}, PRESERVE_FLAGS);
    } else {
        return OperationInstrumentation({"call 0"}, {tsanRead[bytes]}, KEEP_ORIGINAL_INSTRUCTION, {}, PRESERVE_FLAGS);
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
    if (!dryRun && (bytes >= tsanRead.size() || bytes >= tsanWrite.size() ||
            (operand->isRead() && tsanRead[bytes] == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes] == nullptr))) {
        std::cout <<"WARNING: memory operation of size "<<bytes<<" is not instrumented: "<<instruction->getDisassembly()<<std::endl;
        return;
    }

    FileIR_t *ir = getFileIR();

    std::set<std::string> registersToSave = getSaveRegisters(instruction);

    OperationInstrumentation instrumentation = getInstrumentation(instruction, operand, info);
    for (const std::string &noSaveReg : instrumentation.noSaveRegisters) {
        registersToSave.erase(noSaveReg);
    }

    InstructionInserter inserter(ir, instruction, functionAnalysis.getInstructionCounter(), dryRun);

    bool eflagsAlive = true;

    const auto deadRegisterSet = deadRegisters->find(instruction);
    if (deadRegisterSet != deadRegisters->end()) {
        const auto eflagsIt = std::find(deadRegisterSet->second.begin(), deadRegisterSet->second.end(), rn_EFLAGS);
        eflagsAlive = eflagsIt == deadRegisterSet->second.end();
    }

    // the instruction pointer no longer points to the original instruction, make sure that it is not used
    instruction = nullptr;

    // TODO: add this only once per function and not at every access
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp - " + toHex(info.inferredStackFrameSize) + "]");
    }
    if (instrumentation.preserveFlags == PRESERVE_FLAGS && eflagsAlive) {
        // if this is changed, change the rsp offset in the lea rdi instruction as well
        inserter.insertAssembly("pushf");
    }
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }

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
            if (operand->getString() == "rdi") {
                // nothing to do, the address is already in rdi
            } else if (operand->isPcrel()) {
                // The memory displacement is relative the rip at the start of the NEXT instruction
                // The lea instruction should have 7 bytes (if the memory displacement is encoded with 4 byte)
                const auto offset = operand->getMemoryDisplacement() + decoded->length() - 7;
                auto inserted = inserter.insertAssembly("lea rdi, [rel " + toHex(offset) + "]");
                if (!dryRun) {
                    ir->addNewRelocation(inserted, 0, "pcrel");
                }
            } else {
                if (contains(operand->getString(), "rsp")) {
                    // TODO: is this the correct size for the pushf?
                    const int flagSize = (instrumentation.preserveFlags == PRESERVE_FLAGS && eflagsAlive) ? 4 : 0;
                    const int offset = info.inferredStackFrameSize + registersToSave.size() * ir->getArchitectureBitWidth() / 8 + flagSize;
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + " + " + toHex(offset) + "]");
                } else {
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + "]");
                }
            }
        } else {

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
                callTarget = instrumentation.callTargets[0];
                instrumentation.callTargets.erase(instrumentation.callTargets.begin());
            }
            auto inserted = inserter.insertAssembly(strippedAssembly, callTarget);

            if (isJumpWithLabel) {
                jumpTargetsToResolve[labelName] = inserted;
            }
            if (definesLabel) {
                labels[labelName] = inserted;
            }

            if (isCall && !dryRun) {
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

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (instrumentation.preserveFlags == PRESERVE_FLAGS && eflagsAlive) {
        inserter.insertAssembly("popf");
    }
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp + " + toHex(info.inferredStackFrameSize) + "]");
    }

    if (instrumentation.removeOriginalInstruction == REMOVE_ORIGINAL_INSTRUCTION && !dryRun) {
        auto inserted = inserter.getLastInserted();
        inserted->setFallthrough(inserted->getFallthrough()->getFallthrough());
    }
}

void TSanTransform::registerDependencies()
{
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    elfDeps->prependLibraryDepedencies("libgcc_s.so.1");
    elfDeps->prependLibraryDepedencies("libstdc++.so.6");
    elfDeps->prependLibraryDepedencies("libtsan.so.0");
    tsanFunctionEntry = elfDeps->appendPltEntry("__tsan_func_entry");
    tsanFunctionExit = elfDeps->appendPltEntry("__tsan_func_exit");
    for (int s : {1, 2, 4, 8, 16}) {
        tsanWrite[s] = elfDeps->appendPltEntry("__tsan_write" + std::to_string(s));
        tsanRead[s] = elfDeps->appendPltEntry("__tsan_read" + std::to_string(s));
        tsanAtomicLoad[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_load");
        tsanAtomicStore[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_store");
        tsanAtomicExchange[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_exchange");
        tsanAtomicFetchAdd[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_add");
        tsanAtomicFetchSub[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_sub");
        tsanAtomicFetchAnd[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_and");
        tsanAtomicFetchOr[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_or");
        tsanAtomicFetchXor[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_xor");
        tsanAtomicCompareExchangeVal[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_compare_exchange_val");
    }
    tsanReadRange = elfDeps->appendPltEntry("__tsan_read_range");
    tsanWriteRange = elfDeps->appendPltEntry("__tsan_write_range");

    getFileIR()->assembleRegistry();
}
