#ifndef INSTRUCTIONINSERTER_H
#define INSTRUCTIONINSERTER_H

#include <irdb-core>
#include <irdb-transform>
#include <functional>

#include "instruction.h"
#include "stringhelper.h"

class InstructionCache
{
public:
    static IRDB_SDK::Instruction_t *insertAssemblyBefore(IRDB_SDK::FileIR_t* file, IRDB_SDK::Instruction_t* before, std::string assembly, IRDB_SDK::Instruction_t *target)
    {
        if (startsWith(assembly, "push") || startsWith(assembly, "pop")) {
            const auto it = instructionMap.find(assembly);
            if (it == instructionMap.end()) {
                auto result = IRDB_SDK::insertAssemblyBefore(file, before, assembly, target);
                file->assembleRegistry();
                instructionMap[assembly] = before->getDataBits();
                return result;
            } else {
                return IRDB_SDK::insertDataBitsBefore(file, before, it->second, target);
            }
        }
        return IRDB_SDK::insertAssemblyBefore(file, before, assembly, target);
//        return insertAssemblyBefore(file, before, assembly, target);
    }

    static IRDB_SDK::Instruction_t *insertAssemblyAfter(IRDB_SDK::FileIR_t *file, IRDB_SDK::Instruction_t *after,
                                                  const std::string &assembly, IRDB_SDK::Instruction_t *target)
    {
        if (startsWith(assembly, "push") || startsWith(assembly, "pop")) {
            const auto it = instructionMap.find(assembly);
            if (it == instructionMap.end()) {
                auto result = IRDB_SDK::insertAssemblyAfter(file, after, assembly, target);
                file->assembleRegistry();
                instructionMap[assembly] = result->getDataBits();
                return result;
            } else {
                return IRDB_SDK::insertDataBitsAfter(file, after, it->second, target);
            }
        }
        return IRDB_SDK::insertAssemblyAfter(file, after, assembly, target);
    }

private:
    static std::map<std::string, std::string> instructionMap;
};

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
            InstructionCache::insertAssemblyBefore(file, insertionPoint, assembly, target);
        } else {
            insertionPoint = InstructionCache::insertAssemblyAfter(file, insertionPoint, assembly, target);
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
