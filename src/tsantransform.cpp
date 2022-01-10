#include "tsantransform.h"

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
            if (operand->isWritten() && operand->isMemory()) {
                std::cout <<instruction->getDisassembly()<<std::endl;
                writes.push_back(instruction);
            }
        }
        if (decoded->isCall()) {
            std::cout <<"Call: "<<instruction->getDisassembly()<<std::endl;
        }
    }
    for (const auto instruction : writes) {
        insertAssemblyBefore(ir, instruction, "nop");
    }
    return 0;
}

void TSanTransform::addTSanFunctions()
{
//    FileIR_t *ir = getMainFileIR();
}
