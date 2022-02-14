#include "tsantransform.h"

#include <irdb-elfdep>
#include <memory>
#include <algorithm>

#include "simplefile.h"
#include "helper.h"
#include "deadregisteranalysis.h"
#include "fixedpointanalysis.h"

using namespace IRDB_SDK;

class InstructionInserter
{
public:
    InstructionInserter(FileIR_t *file, Instruction_t *insertBefore, Analysis &analysis, bool dryRun) :
        file(file),
        function(insertBefore->getFunction()),
        insertionPoint(insertBefore),
        analysis(analysis),
        dryRun(dryRun)
    { }

    // returns the newly created instruction
    Instruction_t *insertAssembly(const std::string &assembly, Instruction_t *target = nullptr) {
        analysis.countAddInstrumentationInstruction();
        if (dryRun) {
            return nullptr;
        }
        if (!hasInsertedBefore) {
            hasInsertedBefore = true;
            auto in = IRDB_SDK::insertAssemblyBefore(file, insertionPoint, assembly, target);
            in->setFunction(function);
            return in;
        } else {
            insertionPoint = IRDB_SDK::insertAssemblyAfter(file, insertionPoint, assembly, target);
            insertionPoint->setFunction(function);
            return insertionPoint;
        }
    }

    // only valid if at least one instruction has been inserted
    Instruction_t *getLastInserted() const {
        return insertionPoint;
    }

private:
    FileIR_t *file;
    bool hasInsertedBefore = false;
    Function_t *function;
    Instruction_t *insertionPoint;
    Analysis &analysis;
    bool dryRun;
};

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

            const auto analysisResult = FixedPointAnalysis::runBackwards<DeadRegisterInstructionAnalysis, DeadRegisterAnalysisCommon>(function);
            for (const auto &[instruction, analysis] : analysisResult) {
                deadRegisters->insert({instruction, analysis.getDeadRegisters()});
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
                }
            }
        }

        if (info.addEntryExitInstrumentation) {
            // TODO: what if the first instruction is atomic and thus removed?
            insertFunctionEntry(info.properEntryPoint);
            for (Instruction_t *ret : info.exitPoints) {
                insertFunctionExit(ret);
            }
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
    InstructionInserter inserter(ir, insertBefore, functionAnalysis, dryRun);

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
    InstructionInserter inserter(ir, insertBefore, functionAnalysis, dryRun);

    // must be inserted directly before the return instruction
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }
    inserter.insertAssembly("call 0", tsanFunctionExit);
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
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

bool TSanTransform::isRepeated(IRDB_SDK::Instruction_t *instruction)
{
    const auto decoded = DecodedInstruction_t::factory(instruction);
    // some vector instructions have the rep prefix even if they are not repeated
    if (decoded->hasOperand(1) && decoded->getOperand(1)->getArgumentSizeInBytes() == 16) {
        return false;
    }
    return decoded->hasRelevantRepPrefix() || decoded->hasRelevantRepnePrefix();
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

std::optional<OperationInstrumentation> TSanTransform::getAtomicInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand,
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
            tsanAtomicFetchAdd[bytes], true, standard64Bit(op1->getString()), false);
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
            f, true, {}, false);
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
            tsanAtomicCompareExchangeVal[bytes], true, {"rax"}, false);
    }
    if (mnemonic == "mov") {
        if (op0->isRegister() && op1->isMemory()) {
            return OperationInstrumentation({
                    "mov rsi, " + memOrder,
                    "call 0",
                    "mov " + op0->getString() + ", " + raxReg
                },
                tsanAtomicLoad[bytes], true, standard64Bit(op0->getString()), true);
        } else if ((op1->isRegister() || op1->isConstant()) && op0->isMemory()) {
            return OperationInstrumentation({
                    opHasRdi ? "mov " + scratchReg + ", rdi" : "",
                    MOVE_OPERAND_RDI,
                    "mov " + rsiReg + ", " + replacedNonMemoryOperand,
                    "mov rdx, " + memOrder,
                    "call 0"
                },
                tsanAtomicStore[bytes], true, {}, true);
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
            tsanAtomicExchange[bytes], true, {standard64Bit(nonMemoryOperand->getString())}, true);
    }
    std::cout <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
//    throw std::invalid_argument("Unhandled atomic instruction");
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

    // For operations that read and write the memory, only emit the write (it is sufficient for race detection)
    const uint bytes = instrumentationByteSize(operand);
    if (operand->isWritten()) {
        return OperationInstrumentation({"call 0"}, tsanWrite[bytes], false, {}, true);
    } else {
        return OperationInstrumentation({"call 0"}, tsanRead[bytes], false, {}, true);
    }
}

void TSanTransform::instrumentMemoryAccess(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand, const FunctionInfo &info)
{
    InstrumentationInfo instrumentationInfo;
    instrumentationInfo.set_original_address(instruction->getAddress()->getVirtualOffset());
    instrumentationInfo.set_disassembly(disassembly(instruction));
    instrumentationInfo.set_function_has_entry_exit(info.addEntryExitInstrumentation);

    if (isRepeated(instruction)) {
//        std::cout <<"Repeated: "<<instruction->getDisassembly()<<std::endl;
//        throw std::invalid_argument("Repeated!");
    }
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
    if (instrumentation.noSaveRegister.has_value()) {
        registersToSave.erase(instrumentation.noSaveRegister.value());
    }

    InstructionInserter inserter(ir, instruction, functionAnalysis, dryRun);

    // TODO: add this only once per function and not at every access
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp - " + toHex(info.inferredStackFrameSize) + "]");
    }
    // TODO: only when they are needed (the free register analysis might support this)
    if (instrumentation.preserveFlags) {
        // if this is changed, change the rsp offset in the lea rdi instruction as well
        inserter.insertAssembly("pushf");
    }
    for (std::string reg : registersToSave) {
        inserter.insertAssembly("push " + reg);
    }

    if (std::find(instrumentation.instructions.begin(), instrumentation.instructions.end(), MOVE_OPERAND_RDI) == instrumentation.instructions.end()) {
        instrumentation.instructions.insert(instrumentation.instructions.begin(), MOVE_OPERAND_RDI);
    }

    // TODO: instruktionen mit rep prefix
    // TODO: aligned vs unaligned read/write?
    for (const auto &assembly : instrumentation.instructions) {
        if (assembly.size() == 0) {
            continue;
        }
        if (assembly == MOVE_OPERAND_RDI) {
            if (operand->isPcrel()) {
                // The memory displacement is relative the rip at the start of the NEXT instruction
                // The lea instruction should have 7 bytes (if the memory displacement is encoded with 4 byte)
                const auto decoded = DecodedInstruction_t::factory(instruction);
                auto offset = operand->getMemoryDisplacement() + decoded->length() - 7;
                auto inserted = inserter.insertAssembly("lea rdi, [rel " + toHex(offset) + "]");
                if (!dryRun) {
                    ir->addNewRelocation(inserted, 0, "pcrel");
                }
            } else {
                if (contains(operand->getString(), "rsp")) {
                    // TODO: is this the correct size for the pushf?
                    const int flagSize = instrumentation.preserveFlags ? 4 : 0;
                    const int offset = info.inferredStackFrameSize + registersToSave.size() * ir->getArchitectureBitWidth() / 8 + flagSize;
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + " + " + toHex(offset) + "]");
                } else {
                    inserter.insertAssembly("lea rdi, [" + operand->getString() + "]");
                }
            }
        } else {
            const bool isCall = contains(assembly, "call");
            Instruction_t *callTarget = isCall ? instrumentation.callTarget : nullptr;
            auto inserted = inserter.insertAssembly(assembly, callTarget);

            if (isCall && !dryRun) {
                Instrumentation im;
                im.instrumentation = inserted;
                im.info = instrumentationInfo;
                instrumentationAttribution.push_back(im);
            }
        }
    }

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        inserter.insertAssembly("pop " + *it);
    }
    if (instrumentation.preserveFlags) {
        inserter.insertAssembly("popf");
    }
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        inserter.insertAssembly("lea rsp, [rsp + " + toHex(info.inferredStackFrameSize) + "]");
    }

    if (instrumentation.removeOriginalInstruction && !dryRun) {
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

    getFileIR()->assembleRegistry();
}
