#include "function.h"

using namespace IRDB_SDK;

Function::Function(const std::vector<Instruction*> &instructions, Instruction *entryPoint, const string &name,
                   Function_t *irdb, const std::unordered_map<Instruction_t*, Instruction*> &instructionMap) :
    instructions(instructions),
    entryPoint(entryPoint),
    name(name),
    irdb(irdb),
    cfg(irdb, instructionMap)
{
    for (auto instruction : instructions) {
        instruction->setFunction(this);
    }
}
