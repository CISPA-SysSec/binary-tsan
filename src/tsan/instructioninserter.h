#ifndef INSTRUCTIONINSERTER_H
#define INSTRUCTIONINSERTER_H

#include <irdb-core>
#include <irdb-transform>
#include <functional>

#include "instruction.h"

class InstructionInserter
{
public:
    InstructionInserter(IRDB_SDK::FileIR_t *file, Instruction *insertBefore, std::function<void()> instrCounter, bool dryRun) :
        file(file),
        function(insertBefore->getIRDBInstruction()->getFunction()),
        insertionPoint(insertBefore->getIRDBInstruction()),
        insertedInstructionCounter(instrCounter),
        dryRun(dryRun)
    { }

    void setInsertBefore(IRDB_SDK::Instruction_t *instruction) {
        insertionPoint = instruction;
        hasInsertedBefore = false;
    }

    void setInsertAfter(IRDB_SDK::Instruction_t *instruction) {
        insertionPoint = instruction;
        hasInsertedBefore = true;
    }

    // returns the newly created instruction
    IRDB_SDK::Instruction_t *insertAssembly(const std::string &assembly, IRDB_SDK::Instruction_t *target = nullptr) {
        insertedInstructionCounter();
        if (dryRun) {
            return nullptr;
        }
        if (!hasInsertedBefore) {
            hasInsertedBefore = true;
            IRDB_SDK::insertAssemblyBefore(file, insertionPoint, assembly, target);
        } else {
            insertionPoint = IRDB_SDK::insertAssemblyAfter(file, insertionPoint, assembly, target);
        }
        insertionPoint->setFunction(function);
        return insertionPoint;
    }

    // only valid if at least one instruction has been inserted
    IRDB_SDK::Instruction_t *getLastInserted() const {
        return insertionPoint;
    }

private:
    IRDB_SDK::FileIR_t *file;
    bool hasInsertedBefore = false;
    IRDB_SDK::Function_t *function;
    IRDB_SDK::Instruction_t *insertionPoint;
    std::function<void()> insertedInstructionCounter;
    bool dryRun;
};

#endif // INSTRUCTIONINSERTER_H
