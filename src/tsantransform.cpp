#include "tsantransform.h"

#include <irdb-elfdep>
#include <memory>
#include <algorithm>

using namespace IRDB_SDK;

#define cout ERROR_USE_PRINT_INSTEAD

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

int TSanTransform::executeStep()
{
    FileIR_t *ir = getMainFileIR();

    // compute this before any instructions are added
    const auto registerAnalysis = DeepAnalysis_t::factory(ir);
    deadRegisters = registerAnalysis->getDeadRegisters();

    registerDependencies();

    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init"};

    for (Function_t *function : ir->getFunctions()) {
        if (function->getEntryPoint() == nullptr) {
            continue;
        }
        const std::string functionName = function->getName();
        const bool ignoreFunction = std::find(noInstrumentFunctions.begin(), noInstrumentFunctions.end(), functionName) != noInstrumentFunctions.end();
        if (ignoreFunction) {
            continue;
        }
        if (function->getInstructions().size() < 3) {
            continue;
        }

        const FunctionInfo info = analyseFunction(function);

        bool hasInstrumented = false;

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
                    print <<"Instrument access: "<<instruction->getDisassembly()<<", "<<instruction->getFunction()->getName()<<std::endl;
                    instrumentMemoryAccess(instruction, operand, info.inferredStackFrameSize);
                    hasInstrumented = true;
                }
            }
        }

        Instruction_t *temp = info.properEntryPoint;
        if (functionName == "main") {
            // TODO: do not overwrite registers
            insertAssemblyBefore(ir, temp, "call 0", tsanInit);
        }
        if (hasInstrumented) {
            // TODO: do not overwrite registers, add missing argument
//            temp = insertAssemblyBefore(ir, temp, "call 0", tsanFunctionEntry);
        }
    }
    return 0;
}

static bool isEntryInstruction(const DecodedInstruction_t *decoded)
{
    if (decoded->getMnemonic() == "endbr64" || decoded->getMnemonic() == "endbr32") {
        return true;
    }
    if (decoded->getDisassembly() == "mov rbp, rsp") {
        return true;
    }
    if (decoded->getMnemonic() == "push") {
        return true;
    }
    return false;
}

static bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

FunctionInfo TSanTransform::analyseFunction(Function_t *function)
{
    FunctionInfo result;
    result.inferredStackFrameSize = inferredStackFrameSize(function);

    Instruction_t *entry = function->getEntryPoint();

    // detect stack canaries
    {
        const std::string CANARY_CHECK = "fs:[0x28]";

        Instruction_t *canaryStackWrite = nullptr;

        // find the initial read of the canary value and its corresponding write to stack
        Instruction_t *instruction = entry;
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
            result.noInstrumentInstructions.insert(canaryStackWrite);
            const auto decodedWrite = DecodedInstruction_t::factory(canaryStackWrite);

            for (Instruction_t *instruction : function->getInstructions()) {
                const std::string assembly = instruction->getDisassembly();
                const auto decoded = DecodedInstruction_t::factory(instruction);
                const bool isCanaryStackRead = decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() &&
                        decoded->getOperand(1)->getString() == decodedWrite->getOperand(0)->getString();
                if (contains(assembly, CANARY_CHECK) || isCanaryStackRead) {
                    print <<"Ignore canary instruction: "<<assembly<<std::endl;
                    result.noInstrumentInstructions.insert(instruction);
                    continue;
                }
            }
        }
    }

    while (true) {
        const auto decoded = DecodedInstruction_t::factory(entry);
        if (decoded->getMnemonic() == "sub" && decoded->getOperand(0)->isRegister() &&
                decoded->getOperand(0)->getString() == "rsp" && decoded->getOperand(1)->isConstant()) {

            result.noInstrumentInstructions.insert(entry);
            entry = entry->getFallthrough();
            break;

        } else if (!isEntryInstruction(decoded.get())) {
            break;
        }

        result.noInstrumentInstructions.insert(entry);
        entry = entry->getFallthrough();
    }

    result.properEntryPoint = entry;

    return result;
}

int TSanTransform::inferredStackFrameSize(const IRDB_SDK::Function_t *function) const
{
    if (function->getStackFrameSize() > 0) {
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
    return rwSize;
}

static std::string toHex(const int num)
{
    std::stringstream result;
    result <<"0x"<<std::hex<<num;
    return result.str();
}

void TSanTransform::instrumentMemoryAccess(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand, int extraStack)
{
    // TODO: 16 byte xmm registers
    const uint bytes = operand->getArgumentSizeInBytes();
    if (bytes >= tsanRead.size() || bytes >= tsanWrite.size() ||
            (operand->isRead() && tsanRead[bytes] == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes] == nullptr)) {
        print <<"WARNING: memory operation of size "<<bytes<<" is not instrumented: "<<instruction->getDisassembly()<<std::endl;
        return;
    }

    FileIR_t *ir = getMainFileIR();

    // TODO: xmm registers??
    std::set<std::string> registersToSave = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"};
    // TODO: is this before or after the instruction??
    const auto dead = deadRegisters->find(instruction);
    if (dead != deadRegisters->end()) {
        for (RegisterID_t r : dead->second) {
            std::string longName = registerToString(convertRegisterTo64bit(r));
            std::transform(longName.begin(), longName.end(), longName.begin(), ::tolower);
            registersToSave.erase(longName);
        }
    }

    Instruction_t *tmp = instruction;
    bool hasInsertedBefore = false;
    const auto insertAssembly = [ir, &tmp, &hasInsertedBefore](const std::string assembly, Instruction_t *target = nullptr) {
        if (!hasInsertedBefore) {
            hasInsertedBefore = true;
            insertAssemblyBefore(ir, tmp, assembly, target);
        } else {
            tmp = insertAssemblyAfter(ir, tmp, assembly, target);
        }
    };

    // TODO: add this only once per function and not at every access
    if (extraStack > 0) {
        insertAssembly("sub rsp, " + toHex(extraStack));
    }
    for (std::string reg : registersToSave) {
        insertAssembly("push " + reg);
    }

    insertAssembly("lea rdi, [" + operand->getString() + "]");
    // TODO: integrate into lea instruction
    if (contains(operand->getString(), "rsp")) {
        insertAssembly("add rdi, " + toHex(extraStack + registersToSave.size() * ir->getArchitectureBitWidth() / 8));
    }

    // TODO: aligned vs unaligned read/write?

    // For operations that read and write the memory, only emit the write (it is sufficient for race detection)
    if (operand->isWritten()) {
        insertAssembly("call 0", tsanWrite[bytes]);
    } else {
        insertAssembly("call 0", tsanRead[bytes]);
    }

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        insertAssembly("pop " + *it);
    }
    if (extraStack > 0) {
        insertAssembly("add rsp, " + toHex(extraStack));
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
    tsanWrite[1] = elfDeps->appendPltEntry("__tsan_write1");
    tsanWrite[2] = elfDeps->appendPltEntry("__tsan_write2");
    tsanWrite[4] = elfDeps->appendPltEntry("__tsan_write4");
    tsanWrite[8] = elfDeps->appendPltEntry("__tsan_write8");
    tsanRead[1] = elfDeps->appendPltEntry("__tsan_read1");
    tsanRead[2] = elfDeps->appendPltEntry("__tsan_read2");
    tsanRead[4] = elfDeps->appendPltEntry("__tsan_read4");
    tsanRead[8] = elfDeps->appendPltEntry("__tsan_read8");

    getMainFileIR()->assembleRegistry();
}
