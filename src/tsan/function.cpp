#include "function.h"

using namespace IRDB_SDK;

Function::Function(const std::vector<Instruction *> &instructions, Instruction *entryPoint, const string &name, Function_t *irdb) :
    instructions(instructions),
    entryPoint(entryPoint),
    name(name),
    irdb(irdb)
{ }
