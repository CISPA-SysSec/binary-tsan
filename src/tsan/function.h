#ifndef FUNCTION_H
#define FUNCTION_H

#include <irdb-core>

#include "instruction.h"

class Function
{
public:
    Function(const std::vector<Instruction*> &instructions, Instruction *entryPoint, const std::string &name,
             IRDB_SDK::Function_t *irdb);

    const std::set<IRDB_SDK::Instruction_t*>& getInstructions() const { return irdb->getInstructions(); }
    IRDB_SDK::Instruction_t* getEntryPoint() const { return irdb->getEntryPoint(); }
    IRDB_SDK::Function_t* getIRDBFunction() const { return irdb; }

//    const std::vector<Instruction*>& getInstructions() const { return instructions; };
//    Instruction* getEntryPoint() const { return entryPoint; }
    const std::string& getName() const { return name; }

private:
    std::vector<Instruction*> instructions;
    Instruction *entryPoint;
    const std::string name;

    // TODO: only for testing
    IRDB_SDK::Function_t * irdb;
};

#endif // FUNCTION_H
