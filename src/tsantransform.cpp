#include "tsantransform.h"

#include <irdb-elfdep>
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
                    print <<"Instrument access: "<<instruction->getDisassembly()<<", "<<instruction->getFunction()->getName()<<std::endl;
                    instrumentMemoryAccess(instruction, operand, info.inferredStackFrameSize);
                }
            }
        }

        if (functionName == "main") {
            // TODO: do not overwrite registers
//            insertAssemblyBefore(ir, temp, "call 0", tsanInit);
        }
        // TODO: omit these when possible
        if (info.exitPoints.size() > 0) {
            insertFunctionEntry(info.properEntryPoint);
        }
        for (Instruction_t *ret : info.exitPoints) {
            insertFunctionExit(ret);
        }
    }
    return 0;
}

static bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

static std::string toHex(const int num)
{
    std::stringstream result;
    result <<"0x"<<std::hex<<num;
    return result.str();
}

void TSanTransform::insertFunctionEntry(Instruction_t *insertBefore)
{
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

    // detect stack canaries
    {
        const std::string CANARY_CHECK = "fs:[0x28]";

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

    result.properEntryPoint = function->getEntryPoint();
    if (contains(result.properEntryPoint->getDisassembly(), "endbr")) {
        result.properEntryPoint = result.properEntryPoint->getFallthrough();
    }

    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isReturn()) {
            result.exitPoints.push_back(instruction);
        }
    }

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

void TSanTransform::instrumentMemoryAccess(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand, int extraStack)
{
    const uint bytes = operand->getArgumentSizeInBytes();
    if (bytes >= tsanRead.size() || bytes >= tsanWrite.size() ||
            (operand->isRead() && tsanRead[bytes] == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes] == nullptr)) {
        print <<"WARNING: memory operation of size "<<bytes<<" is not instrumented: "<<instruction->getDisassembly()<<std::endl;
        return;
    }

    FileIR_t *ir = getMainFileIR();

    std::set<std::string> registersToSave = getSaveRegisters(instruction);

    bool removeOriginal = false;
    std::vector<std::pair<std::string, Instruction_t*>> atomicInstructionInsert;
    if (isAtomic(instruction)) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        print <<"Found atomic instruction with mnemonic: "<<decoded->getMnemonic()<<std::endl;
        // TODO: correct register sizes
        // TODO: 128 bit operations?
        if (decoded->getMnemonic() == "xadd") {
            if (!decoded->getOperand(0)->isMemory() || !decoded->getOperand(1)->isRegister()) {
                print <<"Bad assumption in atomic xadd!!"<<std::endl;
            } else {
                std::string rsiPart = "rsi";
                std::string raxPart = "rax";
                std::string rdxPart = "rdx";
                // TODO: more byte sizes
                if (decoded->getOperand(1)->getArgumentSizeInBytes() == 4) {
                    rsiPart = "esi";
                    raxPart = "eax";
                    rdxPart = "edx";
                }
                atomicInstructionInsert.push_back({"mov " + rsiPart + ", " + decoded->getOperand(1)->getString(), nullptr});
                // TODO: is this the correct memory order? Can we find out which one is the right one?
                atomicInstructionInsert.push_back({"mov " + rdxPart + ", " + toHex(__tsan_memory_order_acq_rel), nullptr});
                atomicInstructionInsert.push_back({"call 0", tsanAtomicFetchAdd[bytes]});
                atomicInstructionInsert.push_back({"mov " + decoded->getOperand(1)->getString() + ", " + raxPart, nullptr});
                registersToSave.erase(standard64Bit(decoded->getOperand(1)->getString()));

                removeOriginal = true;
            }
        } else {
            print <<"WARNING: can not handle atomic instruction: "<<instruction->getDisassembly()<<std::endl;
        }
    }

    MAKE_INSERT_ASSEMBLY(ir, instruction);

    // TODO: add this only once per function and not at every access
    if (extraStack > 0) {
        insertAssembly("sub rsp, " + toHex(extraStack));
    }
    for (std::string reg : registersToSave) {
        insertAssembly("push " + reg);
    }

    // TODO: is it possible for things to relative to the rip (position independant code) here?
    insertAssembly("lea rdi, [" + operand->getString() + "]");
    // TODO: integrate into lea instruction
    if (contains(operand->getString(), "rsp")) {
        insertAssembly("add rdi, " + toHex(extraStack + registersToSave.size() * ir->getArchitectureBitWidth() / 8));
    }

    // TODO: instruktionen mit rep prefix
    // TODO: aligned vs unaligned read/write?

    if (atomicInstructionInsert.size() > 0) {
        for (const auto &[assembly, target] : atomicInstructionInsert) {
            insertAssembly(assembly, target);
        }
    } else {
        // For operations that read and write the memory, only emit the write (it is sufficient for race detection)
        if (operand->isWritten()) {
            insertAssembly("call 0", tsanWrite[bytes]);
        } else {
            insertAssembly("call 0", tsanRead[bytes]);
        }
    }

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        insertAssembly("pop " + *it);
    }
    if (extraStack > 0) {
        insertAssembly("add rsp, " + toHex(extraStack));
    }

    if (removeOriginal) {
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
        tsanAtomicFetchAdd[s] = elfDeps->appendPltEntry("__tsan_atomic" + std::to_string(s * 8) + "_fetch_add");
    }

    getMainFileIR()->assembleRegistry();
}
