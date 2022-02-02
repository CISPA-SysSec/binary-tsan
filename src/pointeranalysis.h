#ifndef POINTERANALYSIS_H
#define POINTERANALYSIS_H

#include <irdb-core>
#include <irdb-util>
#include <map>

// negative id means unknown/invalid
typedef int MemoryLocation;

class PointerAnalysis
{
public:
    // default constructor initializes the analysis for an unknown instruction
    static PointerAnalysis merge(const std::vector<PointerAnalysis> &parts);
    PointerAnalysis afterInstruction(const IRDB_SDK::Instruction_t *instruction) const;
    bool differsFrom(const PointerAnalysis &other) const;

    static PointerAnalysis functionEntry();
    std::map<IRDB_SDK::RegisterID, MemoryLocation> getMemoryLocations() const;

private:
    static std::vector<IRDB_SDK::RegisterID> possibleRegisters();
    static std::vector<IRDB_SDK::RegisterID> callerSaveRegisters();

private:
    std::map<IRDB_SDK::RegisterID, MemoryLocation> registerPointers;
};

#endif // POINTERANALYSIS_H
