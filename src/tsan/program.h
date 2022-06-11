#ifndef PROGRAM_H
#define PROGRAM_H

#include <irdb-core>
#include <unordered_map>

#include "instruction.h"
#include "function.h"

class Program
{
public:
    Program(IRDB_SDK::FileIR_t *file);

    const std::vector<Function> &getFunctions() const { return functions; }

    // TODO: this should only be public during the refactoring
    Instruction *mapInstruction(IRDB_SDK::Instruction_t *instruction);

private:
    std::vector<Instruction> instructions;
    std::vector<Function> functions;

    std::unordered_map<IRDB_SDK::Instruction_t*, int> instructionIndex;
    std::unordered_map<IRDB_SDK::Function_t*, int> functionIndex;
};

#endif // PROGRAM_H
