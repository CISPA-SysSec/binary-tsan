#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <irdb-core>

// wrapper around the IRDB Instruction_t class to store the instruction disassembly etc.
class Instruction
{
public:
    Instruction(IRDB_SDK::Instruction_t *instruction);
    const std::string& getDisassembly() const { return disassembly; }
    const IRDB_SDK::DecodedInstruction_t& getDecoded() const { return *decoded.get(); }
    IRDB_SDK::Instruction_t* getIRDBInstruction() const { return instruction; }

    // wrappers for IRDB_SDK::Instruction_t functions
    Instruction *getFallthrough() const { return fallthrough; }
    IRDB_SDK::VirtualOffset_t getVirtualOffset() const { return instruction->getAddress()->getVirtualOffset(); }
    std::string getMnemonic() const { return decoded->getMnemonic(); }

    // helper functions
    void setFallthrough(Instruction *fallthrough) { this->fallthrough = fallthrough; }

private:
    IRDB_SDK::Instruction_t *instruction;
    std::unique_ptr<IRDB_SDK::DecodedInstruction_t> decoded;
    const std::string disassembly;

    Instruction *fallthrough = nullptr;
};

#endif // INSTRUCTION_H
