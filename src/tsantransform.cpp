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

        Instruction_t *tmp = instruction;
        transform.insertAssemblyBefore(tmp," push rdi");
        tmp = transform.insertAssemblyAfter(tmp," push rsi ");
        tmp = transform.insertAssemblyAfter(tmp," push rdx");
        tmp = transform.insertAssemblyAfter(tmp," push rcx ");
        tmp = transform.insertAssemblyAfter(tmp," push r8 ");
        tmp = transform.insertAssemblyAfter(tmp," push r9 ");

        const auto decoded = DecodedInstruction_t::factory(instruction);
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isMemory()) {
                tmp = transform.insertAssemblyAfter(tmp, "lea rcx, [" + operand->getString() + "]");
                break;
            }
        }

        tmp = transform.insertAssemblyAfter(tmp, "call 0", tsanWrite);

        tmp = transform.insertAssemblyAfter(tmp," pop r9");
        tmp = transform.insertAssemblyAfter(tmp," pop r8");
        tmp = transform.insertAssemblyAfter(tmp," pop rcx");
        tmp = transform.insertAssemblyAfter(tmp," pop rdx");
        tmp = transform.insertAssemblyAfter(tmp," pop rsi");
        tmp = transform.insertAssemblyAfter(tmp," pop rdi");
    }
    return 0;
}
