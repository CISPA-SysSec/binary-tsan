#include "instruction.h"

#include "register.h"


Instruction::Instruction(IRDB_SDK::Instruction_t *instruction, csh capstoneHandle) :
    instruction(instruction),
    decoded(IRDB_SDK::DecodedInstruction_t::factory(instruction)),
    disassembly(decoded->getDisassembly())
{
    const std::string instructionData = instruction->getDataBits();
    cs_insn *capstoneDecoded = nullptr;
    const int count = cs_disasm(capstoneHandle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &capstoneDecoded);
    if (count == 0) {
        throw std::invalid_argument("could not disassemble instruction");
    }

    readRegisters = Register::getReadRegisters(capstoneDecoded, true);
    writtenRegisters = Register::getWrittenRegisters(capstoneDecoded);

    cs_free(capstoneDecoded, 1);
}

Function *Instruction::getTargetFunction() const
{
    if (target == nullptr) {
        return nullptr;
    }
    return target->function;
}
