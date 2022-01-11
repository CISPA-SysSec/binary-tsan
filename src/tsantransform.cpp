#include "tsantransform.h"

#include <irdb-elfdep>
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
    elfDeps->appendLibraryDepedencies("libtsan.so.0");
    auto tsanWrite = elfDeps->appendPltEntry("__tsan_write4");

    Transform_t transform(ir);
    for (const auto instruction : writes) {
        transform.insertAssemblyBefore(instruction, "call 0");
        instruction->setTarget(tsanWrite);
        const auto decoded = DecodedInstruction_t::factory(instruction);
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isMemory()) {
                transform.insertAssemblyBefore(instruction, "lea rcx, [" + operand->getString() + "]");
                break;
            }
        }
    }
    return 0;
}
