#include "tsantransform.h"

#include <irdb-elfdep>
#include <memory>
#include <algorithm>

using namespace IRDB_SDK;

TSanTransform::TSanTransform()
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

    const InstructionSet_t instructions = ir->getInstructions(); // make a copy
    for (Instruction_t *instruction : instructions) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isBranch() || decoded->isCall()) {
            continue;
        }
        if (instruction->getFunction() == nullptr) {
            continue;
        }
        const std::string functionName = instruction->getFunction()->getName();
        const bool ignoreFunction = std::find(noInstrumentFunctions.begin(), noInstrumentFunctions.end(), functionName) != noInstrumentFunctions.end();
        if (ignoreFunction) {
            continue;
        }
        if (decoded->getMnemonic() == "lea") {
            continue;
        }
        // TODO: instructions that read and write (inc, dec, ...)
        const DecodedOperandVector_t operands = decoded->getOperands();
        for (const auto &operand : operands) {
            if (operand->isMemory() && (operand->isWritten() || operand->isRead())) {
                std::cout <<"Instrument access: "<<instruction->getDisassembly()<<", "<<instruction->getFunction()->getName()<<std::endl;
                instrumentMemoryAccess(instruction, operand);
            }
        }
    }

    for (Function_t *f : ir->getFunctions()) {
        if (f->getName() == "main") {
            insertAssemblyBefore(ir, f->getEntryPoint(),"call 0", tsanInit);
        }
    }
    return 0;
}

void TSanTransform::instrumentMemoryAccess(Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand)
{
    FileIR_t *ir = getMainFileIR();

    std::set<std::string> registersToSave = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9"};
    const auto dead = deadRegisters->find(instruction);
    if (dead != deadRegisters->end()) {
        for (RegisterID_t r : dead->second) {
            const std::string longName = registerToString(convertRegisterTo64bit(r));
            registersToSave.erase(longName);
        }
    }

    Instruction_t *tmp = instruction;
    insertAssemblyBefore(ir, tmp, "push " + *registersToSave.begin());
    for (std::string reg : registersToSave) {
        if (reg != *registersToSave.begin()) {
            tmp = insertAssemblyAfter(ir, tmp, "push " + reg);
        }
    }

    tmp = insertAssemblyAfter(ir, tmp, "lea rdi, [" + operand->getString() + "]");

    const int bytes = operand->getArgumentSizeInBytes();
    if ((operand->isRead() && tsanRead[bytes] == nullptr) ||
            (operand->isWritten() && tsanWrite[bytes] == nullptr)) {
        std::cout <<"ERROR: invalid operand argument size of "<<bytes<<std::endl;
        exit(1);
    }
    if (operand->isRead()) {
        tmp = insertAssemblyAfter(ir, tmp, "call 0", tsanRead[bytes]);
    } else {
        tmp = insertAssemblyAfter(ir, tmp, "call 0", tsanWrite[bytes]);
    }

    for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
        tmp = insertAssemblyAfter(ir, tmp, "pop " + *it);
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
    tsanInit = elfDeps->appendPltEntry("__tsan_func_exit");
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
