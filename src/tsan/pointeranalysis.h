#ifndef POINTERANALYSIS_H
#define POINTERANALYSIS_H

#include <irdb-core>
#include <irdb-util>
#include <map>
#include <optional>

#include "register.h"
#include "instruction.h"

struct MemoryLocation
{
    MemoryLocation(int64_t id, int64_t offset, bool valid = true) : isValid(valid), locationId(id), offset(offset) {}
    MemoryLocation() : isValid(false), locationId(0), offset(0) {}
    bool isValid;
    int64_t locationId;
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
    PointerAnalysis afterInstruction(const Instruction *instruction) const;
    bool differsFrom(const PointerAnalysis &other) const;

    static PointerAnalysis functionEntry();
    std::map<IRDB_SDK::RegisterID, MemoryLocation> getMemoryLocations() const;

private:
    static std::vector<IRDB_SDK::RegisterID> possibleRegisters();
    static std::vector<IRDB_SDK::RegisterID> callerSaveRegisters();

private:
    std::map<IRDB_SDK::RegisterID, MemoryLocation> registerPointers;
};

struct StackOffsetAnalysisCommon
{
    StackOffsetAnalysisCommon(IRDB_SDK::Instruction_t *functionEntry) :
        functionEntry(functionEntry)
    { }
    IRDB_SDK::Instruction_t *functionEntry;
};

enum class OffsetState
{
    // the initial value indicating that the analysis has not arrived here so far
    UNKNOWN,
    VALUE,
    // indicates that the value is unknowable (at least with this analysis)
    INVALID
};

struct StackOffset
{
    OffsetState state = OffsetState::UNKNOWN;
    // the offset is relative to the rsp at the start of the function
    int offset = 0;

    bool mergeFrom(const StackOffset &other) {
        if (state == OffsetState::UNKNOWN) {
            *this = other;
            return other.state != OffsetState::UNKNOWN;
        } else if (state == OffsetState::INVALID) {
            return false;
        } else { // state == OffsetState::VALUE
            if (other.state == OffsetState::UNKNOWN) {
                return false;
            } else if (other.state == OffsetState::VALUE) {
                // TODO: this does not work for the stack access
                if (offset != other.offset) {
                    state = OffsetState::INVALID;
                    return true;
                }
                return false;
            } else { // other.state == OffsetState::INVALID
                state = OffsetState::INVALID;
                return true;
            }
        }
    }
};

enum StackOperationType
{
    OFFSET_RSP,
    MOVE_RSP_TO_RBP,
    MOVE_RBP_TO_RSP,
    INVALIDATE_RSP,
    // a general write to the rbp
    INVALIDATE_RBP,
    STACK_ACCESS_RSP,
    // could also not be a stack access, depending on rbp value
    STACK_ACCESS_RBP,
    FUNCTION_CALL,
    NONE
};

struct StackOperation
{
    StackOperation(StackOperationType operationType, int offset = 0) :
        operationType(operationType),
        operationOffset(offset)
    { }
    StackOperation() { }

    StackOperationType operationType = StackOperationType::NONE;
    // only for those operations that require it
    int operationOffset = 0;
};

class StackOffsetAnalysis
{
public:
    StackOffsetAnalysis(IRDB_SDK::Instruction_t *instruction, const StackOffsetAnalysisCommon &common);
    // for std::map (should never be called)
    StackOffsetAnalysis() {}

    void print() const;
    // safe for inserting a push instruction before this instruction
    bool isStackSafe() const { return before.rspOffset.state != OffsetState::VALUE || before.minAccessOffset >= before.rspOffset.offset; }
    StackOffset getRspOffset() const { return before.rspOffset; }
    bool isStackLeaked() const { return before.stackLeaked; }

    void updateData();

    // returns true if the data has changed
    bool mergeFrom(const StackOffsetAnalysis &predecessor);

    static bool isForwardAnalysis() { return true; }

    // TODO: check consistency: at a return statement, the offset must be 0

private:
    struct StackInfo {
        StackOffset rspOffset;
        StackOffset rbpOffset;
        int minAccessOffset = 0;

        // this set is not updated by the StackOperation
        // TODO: use a more compact representation for the 64-bit general purpose registers only
        FullRegisterSet containingStackpointer;
        bool stackLeaked = false;
    };
    StackInfo before;
    StackInfo after;

    // the operations that this instruction perform
    StackOperation operation;

    struct RegisterMove {
        RegisterMove(x86_reg from, x86_reg to) : from(from), to(to) { }
        x86_reg from;
        x86_reg to;
    };
    std::optional<RegisterMove> registerMove;
    std::optional<x86_reg> registerKill;
    std::optional<x86_reg> writeToMemory;
};

#endif // POINTERANALYSIS_H
