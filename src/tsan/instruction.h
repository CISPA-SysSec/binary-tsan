#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <irdb-core>

#include "register.h"

class Function;

// wrapper around the IRDB Instruction_t class to store the instruction disassembly etc.
class Instruction
{
public:
    Instruction(IRDB_SDK::Instruction_t *instruction, csh capstoneHandle);
    const std::string& getDisassembly() const { return disassembly; }
    const std::unique_ptr<IRDB_SDK::DecodedInstruction_t>& getDecoded() const { return decoded; }
    IRDB_SDK::Instruction_t* getIRDBInstruction() const { return instruction; }

    Instruction *getFallthrough() const { return fallthrough; }
    Instruction *getTarget() const { return target; }
    Function *getFunction() const { return function; }
    // returns the function of the target instruction, or nullptr if not present
    Function *getTargetFunction() const;
    IRDB_SDK::VirtualOffset_t getVirtualOffset() const { return instruction->getAddress()->getVirtualOffset(); }
    std::string getMnemonic() const { return decoded->getMnemonic(); }
    const std::vector<x86_reg> &getWrittenRegisters() const { return writtenRegisters; }
    const std::vector<x86_reg> &getReadRegisters() const { return readRegisters; }
    bool isCall() const { return decoded->isCall(); }
    bool isBranch() const { return decoded->isBranch(); }
    bool isUnconditionalBranch() const { return decoded->isUnconditionalBranch(); }
    bool isReturn() const { return decoded->isReturn(); }

    void setFallthrough(Instruction *fallthrough) { this->fallthrough = fallthrough; }
    void setTarget(Instruction *target) { this->target = target; }
    void setFunction(Function *function) { this->function = function; }

private:
    IRDB_SDK::Instruction_t *instruction;
    std::unique_ptr<IRDB_SDK::DecodedInstruction_t> decoded;
    const std::string disassembly;
    std::vector<x86_reg> writtenRegisters;
    std::vector<x86_reg> readRegisters;

    Function *function = nullptr;

    Instruction *fallthrough = nullptr;
    Instruction *target = nullptr;
};

#endif // INSTRUCTION_H
