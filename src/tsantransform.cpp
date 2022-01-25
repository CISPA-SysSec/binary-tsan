#include "tsantransform.h"

#include <irdb-elfdep>
#include <irdb-cfg>
#include <memory>
#include <algorithm>

using namespace IRDB_SDK;

#define cout ERROR_USE_PRINT_INSTEAD

#define MAKE_INSERT_ASSEMBLY(fileIR, i) Instruction_t *tmp = i; \
    bool hasInsertedBefore = false; \
    const auto insertAssembly = [fileIR, &tmp, &hasInsertedBefore](const std::string assembly, Instruction_t *target = nullptr) { \
        if (!hasInsertedBefore) { \
            hasInsertedBefore = true; \
            insertAssemblyBefore(fileIR, tmp, assembly, target); \
        } else { \
            tmp = insertAssemblyAfter(fileIR, tmp, assembly, target); \
        } \
    };

TSanTransform::TSanTransform() :
    print("../tsan-output")
{
    std::fill(tsanRead.begin(), tsanRead.end(), nullptr);
    std::fill(tsanWrite.begin(), tsanWrite.end(), nullptr);
}

std::string TSanTransform::getStepName(void) const
{
    return "thread sanitizer";
}

int TSanTransform::parseArgs(const vector<std::string>)
{
    return 0;
}

static bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

int TSanTransform::executeStep()
{
    FileIR_t *ir = getMainFileIR();

    // compute this before any instructions are added
    const auto registerAnalysis = DeepAnalysis_t::factory(ir);
    deadRegisters = registerAnalysis->getDeadRegisters();

    registerDependencies();

    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init", "__tsan_default_options"};

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

        const FunctionInfo info = analyseFunction(function);

        const InstructionSet_t instructions = function->getInstructions(); // make a copy
        for (Instruction_t *instruction : instructions) {
            if (info.noInstrumentInstructions.find(instruction) != info.noInstrumentInstructions.end()) {
                continue;
            }
            const auto decoded = DecodedInstruction_t::factory(instruction);
            if (decoded->isBranch() || decoded->isCall()) {
                continue;
            }
            const std::string mnemonic = decoded->getMnemonic();
            if (mnemonic == "lea" || mnemonic == "nop") {
                continue;
            }
            const DecodedOperandVector_t operands = decoded->getOperands();
            for (const auto &operand : operands) {
                if (operand->isMemory() && (operand->isWritten() || operand->isRead())) {
//                    print <<"Instrument access: "<<instruction->getDisassembly()<<", "<<instruction->getFunction()->getName()<<std::endl;
                    instrumentMemoryAccess(instruction, operand, info);
                }
            }
        }

        if (info.exitPoints.size() > 0) {
            // TODO: there might be functions with an important variable location memory read in the jump instruction
            const bool isStub = std::find(info.exitPoints.begin(), info.exitPoints.end(), info.properEntryPoint) != info.exitPoints.end();
            if (!isStub) {
                insertFunctionEntry(info.properEntryPoint);
                for (Instruction_t *ret : info.exitPoints) {
                    insertFunctionExit(ret);
                }
            }
        }
    }
    return 0;
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
    FileIR_t *ir = getMainFileIR();
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore);
    MAKE_INSERT_ASSEMBLY(ir, insertBefore);

    // for this to work without any additional rsp wrangling, it must be inserted at the very start of the function
    for (std::string reg : registersToSave) {
        insertAssembly("push " + reg);
    }
    if (registersToSave.size() > 0) {
        insertAssembly("mov rdi, [rsp + " + toHex(registersToSave.size() * ir->getArchitectureBitWidth() / 8) + "]");
    }
    insertAssembly("call 0", tsanFunctionEntry);
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        insertAssembly("pop " + *it);
    }
}

void TSanTransform::insertFunctionExit(Instruction_t *insertBefore)
{
    FileIR_t *ir = getMainFileIR();
    const std::set<std::string> registersToSave = getSaveRegisters(insertBefore);
    MAKE_INSERT_ASSEMBLY(ir, insertBefore);

    // must be inserted directly before the return instruction
    for (std::string reg : registersToSave) {
        insertAssembly("push " + reg);
    }
    insertAssembly("call 0", tsanFunctionExit);
    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        insertAssembly("pop " + *it);
    }
}

FunctionInfo TSanTransform::analyseFunction(Function_t *function)
{
    FunctionInfo result;
    result.inferredStackFrameSize = inferredStackFrameSize(function);

    result.noInstrumentInstructions = detectStackCanaryInstructions(function);
    result.inferredAtomicInstructions = detectStaticVariableGuards(function);

    result.properEntryPoint = function->getEntryPoint();
    if (contains(result.properEntryPoint->getDisassembly(), "endbr")) {
        result.properEntryPoint = result.properEntryPoint->getFallthrough();
    }

    const auto cfg = ControlFlowGraph_t::factory(function);
    for (const auto block : cfg->getBlocks()) {
        if (!block->getIsExitBlock()) {
            continue;
        }
        Instruction_t *instruction = block->getInstructions().back();
        if (!instruction->isFunctionExit()) {
            continue;
        }
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isCall()) {
            continue;
        }
        // is the exit instruction after functions calls that do not return (for example exit)
        if (contains(instruction->getDisassembly(), "nop")) {
            continue;
        }
        if (!decoded->isReturn()) {
            result.exitPoints.clear();
            break;
        }
        result.exitPoints.push_back(instruction);
    }

    return result;
}

std::set<Instruction_t*> TSanTransform::detectStackCanaryInstructions(Function_t *function) const
{
    const std::string CANARY_CHECK = "fs:[0x28]";

    std::set<Instruction_t*> result;

    Instruction_t *canaryStackWrite = nullptr;

    // find the initial read of the canary value and its corresponding write to stack
    Instruction_t *instruction = function->getEntryPoint();
    for (int i = 0;i<20;i++) {
        const std::string assembly = instruction->getDisassembly();
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (contains(assembly, CANARY_CHECK)) {
            if (decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() && decoded->getOperand(0)->isRegister()) {
                Instruction_t *next = instruction->getFallthrough();
                if (next == nullptr) {
                    print <<"ERROR: unexpected instruction termination"<<std::endl;
                    break;
                }
                const auto nextDecoded = DecodedInstruction_t::factory(next);
                if (!nextDecoded->hasOperand(1) || !nextDecoded->getOperand(1)->isRegister() ||
                        decoded->getOperand(0)->getString() != nextDecoded->getOperand(1)->getString()) {
                    print <<"ERROR: could not find canary stack write!"<<std::endl;
                    break;
                }
                canaryStackWrite = next;
            }
            break;
        }
        if (decoded->isReturn()) {
            break;
        }
        instruction = instruction->getFallthrough();
        if (instruction == nullptr) {
            break;
        }
    }

    // find canary read/writes
    if (canaryStackWrite != nullptr) {
        print <<"Ignore canary instruction: "<<canaryStackWrite->getDisassembly()<<std::endl;
        result.insert(canaryStackWrite);
        const auto decodedWrite = DecodedInstruction_t::factory(canaryStackWrite);

        for (Instruction_t *instruction : function->getInstructions()) {
            const std::string assembly = instruction->getDisassembly();
            const auto decoded = DecodedInstruction_t::factory(instruction);
            const bool isCanaryStackRead = decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() &&
                    decoded->getOperand(1)->getString() == decodedWrite->getOperand(0)->getString();
            if (contains(assembly, CANARY_CHECK) || isCanaryStackRead) {
                print <<"Ignore canary instruction: "<<assembly<<std::endl;
                result.insert(instruction);
                continue;
            }
        }
    }
    return result;
}

static bool isLeafFunction(const Function_t *function)
{
    const auto instructions = function->getInstructions();
    return std::none_of(instructions.begin(), instructions.end(), [](const Instruction_t *i) {
        const auto decoded = DecodedInstruction_t::factory(i);
        return decoded->isCall();
    });
}

int TSanTransform::inferredStackFrameSize(const IRDB_SDK::Function_t *function) const
{
    if (!isLeafFunction(function)) {
        return 0;
    }
    int rwSize = 0;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getMnemonic() != "mov") {
            continue;
        }
        if (!decoded->hasOperand(0) || !decoded->hasOperand(1)) {
            continue;
        }
        const auto op0 = decoded->getOperand(0);
        const auto op1 = decoded->getOperand(1);
        const auto acc = op0->isMemory() ? op0 : op1;
        if (!acc->isMemory()) {
            continue;
        }
        // TODO: rsp based writes
        const std::string opstr = acc->getString();
        const bool isStackPointer = contains(opstr, "rbp") || contains(opstr, "ebp");
        if (!isStackPointer) {
            continue;
        }
        intptr_t offset = static_cast<intptr_t>(acc->getMemoryDisplacement());
        rwSize = std::max(rwSize, static_cast<int>(-offset) + static_cast<int>(acc->getArgumentSizeInBytes()));
    }
    // sanity check
    if (rwSize > 2000) {
        rwSize = 0;
    }
    // add a large offset to be sure
    return rwSize + 256;
}

std::set<std::string> TSanTransform::getSaveRegisters(Instruction_t *instruction)
{
    // TODO: xmm registers??
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

bool TSanTransform::isAtomic(IRDB_SDK::Instruction_t *instruction)
{
    const auto decoded = DecodedInstruction_t::factory(instruction);
    const std::string dataBits = instruction->getDataBits();
    return std::any_of(dataBits.begin(), dataBits.begin() + decoded->getPrefixCount(), [](char c) {
        return static_cast<unsigned char>(c) == 0xF0;
    });
}

static std::string standard64Bit(const std::string &reg)
{
    std::string full = registerToString(convertRegisterTo64bit(strToRegister(reg)));
    std::transform(full.begin(), full.end(), full.begin(), ::tolower);
    return full;
}

static std::string toBytes(RegisterID reg, int bytes)
{
    RegisterID correctBytes;
    if (bytes == 1) {
        correctBytes = convertRegisterTo8bit(reg);
    } else if (bytes == 2) {
        correctBytes = convertRegisterTo16bit(reg);
    } else if (bytes == 4) {
        correctBytes = convertRegisterTo32bit(reg);
    } else if (bytes == 8) {
        correctBytes = convertRegisterTo64bit(reg);
    } else {
        throw std::invalid_argument("Invalid register byte size");
    }
    std::string full = registerToString(correctBytes);
    std::transform(full.begin(), full.end(), full.begin(), ::tolower);
    return full;
}

// returns the name of the function that the instruction calls, or an empty string in all other cases
static std::string targetFunctionName(const Instruction_t *instruction)
{
    const auto lastDecoded = DecodedInstruction_t::factory(instruction);
    if (!lastDecoded->isCall()) {
        return "";
    }
    if (instruction->getTarget() == nullptr) {
        return "";
    }
    const Function_t *callTarget = instruction->getTarget()->getFunction();
    if (callTarget == nullptr) {
        return "";
    }
    return callTarget->getName();
}

std::set<Instruction_t*> TSanTransform::detectStaticVariableGuards(Function_t *function) const
{
    const auto cfg = ControlFlowGraph_t::factory(function);

    // find locations of all static variable guards
    std::set<std::string> guardLocations;
    for (const auto &block : cfg->getBlocks()) {
        const auto instructions = block->getInstructions();
        if (instructions.size() < 2) {
            continue;
        }
        // check if there is a static guard aquire
        const Instruction_t *last = instructions.back();
        const std::string targetName = targetFunctionName(last);
        // TODO: is the name the same for all compilers/compiler versions?
        if (!contains(targetName, "cxa_guard_acquire")) {
            continue;
        }
        // find location of the guard lock variable
        for (int i = int(instructions.size())-2;i>=0;i--) {
            const Instruction_t *instruction = instructions[i];
            const auto decoded = DecodedInstruction_t::factory(instruction);
            if (!decoded->hasOperand(0) || !decoded->getOperand(0)->isRegister()) {
                continue;
            }
            const std::string writtenRegister = standard64Bit(decoded->getOperand(0)->getString());
            if (writtenRegister != "rdi") {
                continue;
            }
            if (!decoded->hasOperand(1) || !decoded->getOperand(1)->isConstant()) {
                break;
            }
            // TODO: this only works if the getString function is consistent
            // if it is created by disecting the disassembly, this is not the case
            // Therefore, make sure that it is a canonical form
            const std::string guardLocation = decoded->getOperand(1)->getString();
            print <<"Found static variable guard location: "<<guardLocation<<std::endl;
            guardLocations.insert(guardLocation);
        }
        if (guardLocations.size() == 0) {
            print <<"WARNING: could not find static variable guard location!"<<std::endl;
        }
    }

    // find all read accesses to the guard variables
    std::set<Instruction_t*> result;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getOperands().size() < 2 || !decoded->getOperand(1)->isMemory()) {
            continue;
        }
        const std::string op1Str = decoded->getOperand(1)->getString();
        const bool isGuardLocation = guardLocations.find(op1Str) != guardLocations.end();
        if (isGuardLocation) {
            print <<"Found static variable guard read: "<<instruction->getDisassembly()<<std::endl;
            result.insert(instruction);
        }
    }
    return result;
}

std::optional<OperationInstrumentation> TSanTransform::getAtomicInstrumentation(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand) const
{
    const uint bytes = operand->getArgumentSizeInBytes();

    const auto decoded = DecodedInstruction_t::factory(instruction);
    print <<"Found atomic instruction with mnemonic: "<<decoded->getMnemonic()<<std::endl;
    // TODO: 128 bit operations?
    const std::string mnemonic = decoded->getMnemonic();
    const std::string rsiReg = toBytes(RegisterID::rn_RSI, bytes);
    const std::string rdxReg = toBytes(RegisterID::rn_RDX, bytes);
    const std::string raxReg = toBytes(RegisterID::rn_RAX, bytes);
    const std::string memOrder = toHex(__tsan_memory_order_acq_rel);

    // TODO: maybe just modify the tsan functions to not perform the operation, easier that way?
    // TODO: if op1 contains the rsp, then it has to be offset
    const auto op0 = decoded->getOperand(0);
    if (!decoded->hasOperand(1)) {
        return {};
    }
    const auto op1 = decoded->getOperand(1);
    // assumption: op0 is memory, op1 is register
    if (mnemonic == "xadd") {
        // TODO: here and below: what if op1->getString() is rdi? It is overwritten
        return OperationInstrumentation({
                "mov " + rsiReg + ", " + op1->getString(),
                "mov rdx, " + memOrder,
                "call 0",
                "mov " + op1->getString() + ", " + raxReg
            },
            tsanAtomicFetchAdd[bytes], true, standard64Bit(op1->getString()), false);
    }
    // assumption: op0 is memory, op1 is register or constant
    if (mnemonic == "add" || mnemonic == "sub") {
        Instruction_t *f = mnemonic == "add" ? tsanAtomicFetchAdd[bytes] : tsanAtomicFetchSub[bytes];
        return OperationInstrumentation({
                "mov " + rsiReg + ", " + op1->getString(),
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
                "mov " + rsiReg + ", " + raxReg,
                "mov " + rdxReg + ", " + op1->getString(),
                "mov rcx, " + memOrder,
                "mov r8, " + memOrder,
                "push rax",
                "call 0",
                "pop rsi",
                "cmp " + raxReg + ", " + rsiReg // make sure flags are set correctly (cmpxchg would otherwise set them)
            },
            tsanAtomicCompareExchangeVal[bytes], true, {"rax"}, false);
    }
    if (mnemonic == "mov" && op0->isRegister() && op1->isMemory()) {
        return OperationInstrumentation({
                // TODO: this memory order is only for the static variable guard instruction
                // this time, we actually know the correct memory order
                "mov rsi, " + toHex(__tsan_memory_order_acquire),
                "call 0",
                "mov " + op0->getString() + ", " + raxReg
            },
            tsanAtomicLoad[bytes], true, standard64Bit(op0->getString()), true);
    }
    print <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
//        throw std::invalid_argument("Unhandled atomic instruction");
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
    const bool atomic = isAtomic(instruction) || info.inferredAtomicInstructions.find(instruction) != info.inferredAtomicInstructions.end();
    if (atomic) {
        auto instrumentation = getAtomicInstrumentation(instruction, operand);
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
    const uint bytes = instrumentationByteSize(operand);
    if (bytes >= tsanRead.size() || bytes >= tsanWrite.size() ||
            (operand->isRead() && tsanRead[bytes] == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes] == nullptr)) {
        print <<"WARNING: memory operation of size "<<bytes<<" is not instrumented: "<<instruction->getDisassembly()<<std::endl;
        return;
    }

    FileIR_t *ir = getMainFileIR();

    std::set<std::string> registersToSave = getSaveRegisters(instruction);

    const OperationInstrumentation instrumentation = getInstrumentation(instruction, operand, info);
    if (instrumentation.noSaveRegister.has_value()) {
        registersToSave.erase(instrumentation.noSaveRegister.value());
    }

    MAKE_INSERT_ASSEMBLY(ir, instruction);

    // TODO: add this only once per function and not at every access
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        insertAssembly("lea rsp, [rsp - " + toHex(info.inferredStackFrameSize) + "]");
    }
    // TODO: only when they are needed (the free register analysis might support this)
    if (instrumentation.preserveFlags) {
        // if this is changed, change the rsp offset in the lea rdi instruction as well
        insertAssembly("pushf");
    }
    for (std::string reg : registersToSave) {
        insertAssembly("push " + reg);
    }

    // TODO: is it possible for things to relative to the rip (position independant code) here?
    insertAssembly("lea rdi, [" + operand->getString() + "]");
    // TODO: integrate into lea instruction
    if (contains(operand->getString(), "rsp")) {
        // TODO: is this the correct size for the pushf?
        const int flagSize = instrumentation.preserveFlags ? 4 : 0;
        const int offset = info.inferredStackFrameSize + registersToSave.size() * ir->getArchitectureBitWidth() / 8 + flagSize;
        insertAssembly("lea rdi, [rdi + " + toHex(offset) + "]");
    }

    // TODO: instruktionen mit rep prefix
    // TODO: aligned vs unaligned read/write?
    for (const auto &assembly : instrumentation.instructions) {
        Instruction_t *callTarget = contains(assembly, "call") ? instrumentation.callTarget : nullptr;
        insertAssembly(assembly, callTarget);
    }

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        insertAssembly("pop " + *it);
    }
    if (instrumentation.preserveFlags) {
        insertAssembly("popf");
    }
    if (info.inferredStackFrameSize > 0) {
        // use lea instead of add/sub to preserve flags
        insertAssembly("lea rsp, [rsp + " + toHex(info.inferredStackFrameSize) + "]");
    }

    if (instrumentation.removeOriginalInstruction) {
        tmp->setFallthrough(tmp->getFallthrough()->getFallthrough());
    }
}

void TSanTransform::registerDependencies()
{
    auto elfDeps = ElfDependencies_t::factory(getMainFileIR());
    elfDeps->prependLibraryDepedencies("libgcc_s.so.1");
    elfDeps->prependLibraryDepedencies("libstdc++.so.6");
    elfDeps->prependLibraryDepedencies("libtsan.so.0");
    tsanInit = elfDeps->appendPltEntry("__tsan_init");
    tsanFunctionEntry = elfDeps->appendPltEntry("__tsan_func_entry");
    tsanFunctionExit = elfDeps->appendPltEntry("__tsan_func_exit");
    for (int s : {1, 2, 4, 8, 16}) {
        tsanWrite[s] = elfDeps->appendPltEntry("__tsan_write" + std::to_string(s));
        tsanRead[s] = elfDeps->appendPltEntry("__tsan_read" + std::to_string(s));
        tsanAtomicLoad[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_load");
        tsanAtomicFetchAdd[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_add");
        tsanAtomicFetchSub[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_sub");
        tsanAtomicCompareExchangeVal[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_compare_exchange_val");
    }

    getMainFileIR()->assembleRegistry();
}
