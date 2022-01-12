#include "tsantransform.h"

#include <irdb-elfdep>
#include <irdb-deep>
#include <memory>

using namespace IRDB_SDK;

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
    const auto deadRegisters = registerAnalysis->getDeadRegisters();

    const InstructionSet_t instructions = ir->getInstructions(); // make a copy
    std::vector<Instruction_t*> writes;
    for (Instruction_t *instruction : instructions) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        const DecodedOperandVector_t operands = decoded->getOperands();
        for (const auto &operand : operands) {
            if (operand->isWritten() && operand->isMemory() && instruction->getFunction()
                    && instruction->getFunction()->getName() == "main") {
                std::cout <<"Instrument write: "<<instruction->getDisassembly()<<std::endl;
                writes.push_back(instruction);
            }
        }
    }

    auto elfDeps = ElfDependencies_t::factory(ir);
    elfDeps->prependLibraryDepedencies("libgcc_s.so.1");
    elfDeps->prependLibraryDepedencies("libstdc++.so.6");
    elfDeps->prependLibraryDepedencies("libtsan.so.0");
    auto tsanInit = elfDeps->appendPltEntry("__tsan_init");
    auto tsanWrite = elfDeps->appendPltEntry("__tsan_write4");

    Transform_t transform(ir);
    for (Function_t *f : ir->getFunctions()) {
        if (f->getName() == "main") {
            transform.insertAssemblyBefore(f->getEntryPoint(),"call 0", tsanInit);
        }
    }

    for (const auto instruction : writes) {
        std::set<std::string> registersToSave = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9"};
        const auto dead = deadRegisters->find(instruction);
        if (dead != deadRegisters->end()) {
            for (RegisterID_t r : dead->second) {
                const std::string longName = registerToString(convertRegisterTo64bit(r));
                registersToSave.erase(longName);
            }
        }


        Instruction_t *tmp = instruction;
        transform.insertAssemblyBefore(tmp, "push " + *registersToSave.begin());
        for (std::string reg : registersToSave) {
            if (reg != *registersToSave.begin()) {
                tmp = transform.insertAssemblyAfter(tmp, "push " + reg);
            }
        }

        const auto decoded = DecodedInstruction_t::factory(instruction);
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isMemory()) {
                tmp = transform.insertAssemblyAfter(tmp, "lea rdi, [" + operand->getString() + "]");
                break;
            }
        }

        tmp = transform.insertAssemblyAfter(tmp, "call 0", tsanWrite);

        for (auto it = registersToSave.rbegin();it != registersToSave.rend();it++) {
            tmp = transform.insertAssemblyAfter(tmp, "pop " + *it);
        }
    }

    return 0;
}
