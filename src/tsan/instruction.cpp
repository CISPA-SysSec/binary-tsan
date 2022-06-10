#include "instruction.h"

Instruction::Instruction(IRDB_SDK::Instruction_t *instruction) :
    instruction(instruction),
    decoded(IRDB_SDK::DecodedInstruction_t::factory(instruction)),
    disassembly(instruction->getDisassembly())
{ }
