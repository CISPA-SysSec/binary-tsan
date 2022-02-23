#ifndef POINTERANALYSIS_H
#define POINTERANALYSIS_H

#include <irdb-core>
#include <irdb-util>
#include <map>

struct MemoryLocation
{
    MemoryLocation(int id, int64_t offset, bool valid = true) : isValid(valid), locationId(id), offset(offset) {}
    MemoryLocation() : isValid(false), locationId(0), offset(0) {}
    bool isValid;
    int locationId;
    int64_t offset;

    bool operator!=(const MemoryLocation &other) const {
        return isValid != other.isValid || locationId != other.locationId || offset != other.offset;
    }
    bool operator==(const MemoryLocation &other) const {
        return !(*this != other);
    }
    bool operator<(const MemoryLocation &other) const {
        return std::tie(isValid, locationId, offset) < std::tie(other.isValid, other.locationId, other.offset);
    }
    static MemoryLocation invalid() { return MemoryLocation(-1, 0, false); }
};

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
