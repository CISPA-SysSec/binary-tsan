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
    Transform_t(file),
    functionAnalysis(file)
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
        // should be an absolute path to be useful
        const std::string dumpFunctionsOption = "--dumpFunctionNamesTo=";
        if (startsWith(option, dumpFunctionsOption)) {
            std::string filename = option;
            filename.erase(filename.begin(), filename.begin() + dumpFunctionsOption.size());
            std::cout <<"Dumping function names to: "<<filename<<std::endl;
            FileIR_t *ir = getFileIR();
            ofstream file(filename, ios_base::binary);
            if (!file) {
                std::cout <<"Could not open file!"<<std::endl;
                return false;
            }
            for (Function_t *function : ir->getFunctions()) {
                file <<function->getName()<<std::endl;
            }
            continue;
        }
        // should be an absolute path to be useful
        const std::string instrumentOnlyOption = "--instrumentOnlyFunctions=";
        if (startsWith(option, instrumentOnlyOption)) {
            std::string filename = option;
            filename.erase(filename.begin(), filename.begin() + instrumentOnlyOption.size());
            std::cout <<"Reading filenames from: "<<filename<<std::endl;
            ifstream file(filename);
            if (!file) {
                std::cout <<"Could not open file!"<<std::endl;
                return false;
            }
            std::string line;
            while(getline(file, line)) {
                instrumentOnlyFunctions.insert(line);
            }
            std::cout <<"Loaded "<<instrumentOnlyFunctions.size()<<" functions to instrument"<<std::endl;
            continue;
        }
        if (option == "--register-analysis=stars") {
            deadRegisterAnalysisType = DeadRegisterAnalysisType::STARS;
        } else if (option == "--register-analysis=custom") {
            deadRegisterAnalysisType = DeadRegisterAnalysisType::CUSTOM;
        } else if (option == "--register-analysis=none") {
            deadRegisterAnalysisType = DeadRegisterAnalysisType::NONE;
        } else if (option == "--dry-run") {
            dryRun = true;
        } else if (option == "--atomics-only") {
            atomicsOnly = true;
        } else if (option == "--no-entry-exit") {
            // also includes exception handling
            instrumentFunctionEntryExit = false;
        } else if (option == "--no-add-tsan-calls") {
            addTsanCalls = false;
        } else if (option == "--save-xmm-registers") {
            saveXmmRegisters = true;
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
        auto starsDead = registerAnalysis->getDeadRegisters();
        for (const auto &[instruction, registers] : *starsDead) {
            std::set<x86_reg> capstoneRegs;
            for (const auto reg : registers) {
                // also insert the original register (for eflags etc.)
                capstoneRegs.insert(Register::registerIDToCapstoneRegister(reg));
                const auto largeReg = convertRegisterTo64bit(reg);
                capstoneRegs.insert(Register::registerIDToCapstoneRegister(largeReg));
            }
            deadRegisters[instruction] = capstoneRegs;
        }
    }

    if (!dryRun) {
        registerDependencies();
    }

    ExceptionHandling exceptionHandling(ir, tsanFunctionExit);

    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init", "__tsan_default_options", "_fini", "__libc_csu_fini",
                                                            "ThisIsNotAFunction", "__gmon_start__", "__do_global_ctors_aux", "__do_global_dtors_aux"};

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
        if (instrumentOnlyFunctions.size() > 0 && instrumentOnlyFunctions.find(functionName) == instrumentOnlyFunctions.end()) {
            continue;
        }

        // register analysis
        if (deadRegisterAnalysisType == DeadRegisterAnalysisType::CUSTOM) {
            deadRegisters.clear();

            if (FixedPointAnalysis::canHandle(function)) {
                const auto analysisResult = FixedPointAnalysis::runAnalysis<DeadRegisterInstructionAnalysis, RegisterAnalysisCommon>(function, {});
                for (const auto &[instruction, analysis] : analysisResult) {
                    deadRegisters.insert({instruction, analysis.getDeadRegisters()});
                }
                const auto undefinedResult = FixedPointAnalysis::runAnalysis<UndefinedRegisterInstructionAnalysis, RegisterAnalysisCommon>(function, functionAnalysis.getNoReturnFunctions());
                const bool hasProblem = std::any_of(undefinedResult.begin(), undefinedResult.end(), [](const auto &r) {
                    return r.second.hasProblem();
                });
                if (!hasProblem) {
                    for (const auto &[instruction, analysis] : undefinedResult) {
                        auto it = deadRegisters.find(instruction);
                        for (auto reg : analysis.getDeadRegisters()) {
                            it->second.insert(reg);
                        }
                    }
                } else {
                    std::cout <<"WARNING: undefined register analysis problem in: "<<function->getName()<<std::endl;
                }
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

        if (info.addEntryExitInstrumentation && instrumentFunctionEntryExit) {
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
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore, false);
    InstructionInserter inserter(ir, insertBefore, functionAnalysis.getInstructionCounter(), dryRun);

    // for this to work without any additional rsp wrangling, it must be inserted at the very start of the function
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }
    if (registersToSave.size() > 0) {
        inserter.insertAssembly("mov rdi, [rsp + " + toHex(registersToSave.size() * ir->getArchitectureBitWidth() / 8) + "]");
    }
    if (addTsanCalls) {
        inserter.insertAssembly("call 0", tsanFunctionEntry);
    }
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
}

void TSanTransform::insertFunctionExit(Instruction_t *insertBefore)
{
    FileIR_t *ir = getFileIR();
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore, false);
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
    if (addTsanCalls) {
        inserter.insertAssembly("call 0", tsanFunctionExit);
    }
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (!isSimpleReturn) {
        inserter.insertAssembly("add rsp, 0xff");
    }
}

std::set<std::string> TSanTransform::getSaveRegisters(Instruction_t *instruction, bool addXmmRegisters)
{
    std::set<x86_reg> registersToSave = {X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11};
    if (addXmmRegisters) {
        for (int i = 0;i<16;i++) {
            registersToSave.insert(static_cast<x86_reg>(X86_REG_XMM0 + i));
        }
    }
    const auto dead = deadRegisters.find(instruction);
    if (dead != deadRegisters.end()) {
        for (x86_reg r : dead->second) {
            registersToSave.erase(r);
        }
    }
    std::set<std::string> result;
    for (auto reg : registersToSave) {
        result.insert(Register::registerToString(reg));
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
            Instruction_t *tsanFunction = mnemonic == "inc" ? tsanAtomicFetchAdd[bytes] : tsanAtomicFetchSub[bytes];
            return OperationInstrumentation({
                    "mov rsi, 1",
                    "mov rdx, " + memOrder,
                    "pushf",
                    "call 0",
                    "popf",
                    // create correct flags otherwise created by the original instruction
                    // it is important to use the subregister of rax with the correct size for the overflow flag
                    mnemonic + " " + raxReg
                },
                {tsanFunction}, REMOVE_ORIGINAL_INSTRUCTION, {}, NO_PRESERVE_FLAGS);
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
                op1->isRegister() ? "push " + standard64Bit(replacedNonMemoryOperand) : "",
                "call 0",
                op1->isRegister() ? "pop " + standard64Bit(replacedNonMemoryOperand) : "",
                // create correct flags otherwise created by the original instruction
                // TODO: only do this when the flags are alive after the instruction
                mnemonic + " " + raxReg + ", " + replacedNonMemoryOperand
            },
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
                "mov r8, " + toHex(__tsan_memory_order_relaxed),
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
                    "mov rsi, " + toHex(__tsan_memory_order_acquire),
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
                    "mov rdx, " + toHex(__tsan_memory_order_release),
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
//        std::cout <<"Repeated: "<<instruction->getDisassembly()<<std::endl;

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
        Instruction_t *target = isCMov ? tsanRead[bytes] : tsanWrite[bytes];
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
            {target}, KEEP_ORIGINAL_INSTRUCTION, {}, PRESERVE_FLAGS);
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
        const __tsan_memory_order memOrder = isInferredAtomic ? inferredIt->second : __tsan_memory_order_acq_rel;
        auto instrumentation = getAtomicInstrumentation(instruction, operand, memOrder);
        if (instrumentation.has_value()) {
            return instrumentation;
        }
    }

    if (atomicsOnly) {
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

    std::set<std::string> registersToSave = getSaveRegisters(instruction, saveXmmRegisters);

    const auto instr = getInstrumentation(instruction, operand, info);
    // could not instrument - command line option or some other problem
    if (!instr) {
        return;
    }
    OperationInstrumentation instrumentation = *instr;
    for (const std::string &noSaveReg : instrumentation.noSaveRegisters) {
        registersToSave.erase(noSaveReg);
    }

    std::vector<std::string> xmmRegistersToSave;
    std::vector<std::string> generalPurposeRegistersToSave;
    for (const auto &reg : registersToSave) {
        if (startsWith(reg, "xmm")) {
            xmmRegistersToSave.push_back(reg);
        } else {
            generalPurposeRegistersToSave.push_back(reg);
        }
    }

    InstructionInserter inserter(ir, instruction, functionAnalysis.getInstructionCounter(), dryRun);

    bool eflagsAlive = true;

    const auto deadRegisterSet = deadRegisters.find(instruction);
    if (deadRegisterSet != deadRegisters.end()) {
        const auto eflagsIt = std::find(deadRegisterSet->second.begin(), deadRegisterSet->second.end(), X86_REG_EFLAGS);
        eflagsAlive = eflagsIt == deadRegisterSet->second.end();
    }

    // the instruction pointer no longer points to the original instruction, make sure that it is not used
    instruction = nullptr;

    // TODO: add this only once per function and not at every access
    // honor redzone
    const int stackOffset = (info.isLeafFunction ? 256 : 0) + xmmRegistersToSave.size() * 16;
    if (stackOffset > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp - " + toHex(stackOffset) + "]");
    }
    for (std::size_t i = 0;i<xmmRegistersToSave.size();i++) {
        inserter.insertAssembly("movdqu [rsp + " + toHex(i * 16) + "], " + xmmRegistersToSave[i]);
    }
    if (instrumentation.preserveFlags == PRESERVE_FLAGS && eflagsAlive) {
        // if this is changed, change the rsp offset in the lea rdi instruction as well
        inserter.insertAssembly("pushf");
    }
    for (const std::string &reg : generalPurposeRegistersToSave) {
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
                    const int offset = stackOffset + generalPurposeRegistersToSave.size() * ir->getArchitectureBitWidth() / 8 + flagSize;
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + " + " + toHex(offset) + "]");
                } else {
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + "]");
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
                callTarget = instrumentation.callTargets[0];
                instrumentation.callTargets.erase(instrumentation.callTargets.begin());
                if (!addTsanCalls) {
                    continue;
                }
            }
            auto inserted = inserter.insertAssembly(strippedAssembly, callTarget);

            if (isJumpWithLabel && !dryRun) {
                jumpTargetsToResolve[labelName] = inserted;
            }
            if (definesLabel && !dryRun) {
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

    for (auto it = generalPurposeRegistersToSave.rbegin();it != generalPurposeRegistersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (instrumentation.preserveFlags == PRESERVE_FLAGS && eflagsAlive) {
        inserter.insertAssembly("popf");
    }
    for (std::size_t i = 0;i<xmmRegistersToSave.size();i++) {
        inserter.insertAssembly("movdqu " + xmmRegistersToSave[i] + ", [rsp + " + toHex(i * 16) + "]");
    }
    if (stackOffset > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp + " + toHex(stackOffset) + "]");
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
