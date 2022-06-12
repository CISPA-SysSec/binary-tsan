#ifndef DEADREGISTERANALYSIS_H
#define DEADREGISTERANALYSIS_H

#include <irdb-core>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "register.h"
#include "instruction.h"

struct RegisterAnalysisCommon
{
    RegisterAnalysisCommon(const std::map<IRDB_SDK::Function_t*, CallerSaveRegisterSet> &functionWrittenRegisters) :
        functionWrittenRegisters(functionWrittenRegisters)
    { }
    CapstoneHandle capstoneHandle;
    const std::map<IRDB_SDK::Function_t*, CallerSaveRegisterSet> &functionWrittenRegisters;
};

class DeadRegisterInstructionAnalysis
{
public:
    DeadRegisterInstructionAnalysis(Instruction *instruction, const RegisterAnalysisCommon &common);
    // for std::map (should never be called)
    DeadRegisterInstructionAnalysis() {}

    inline void updateData() {
        // assume that values are read first and written afterwards (if one register is read and written)
        before = (after | writtenRegs) & (~readRegs);
    }

    // returns true if the data has changed
    inline bool mergeFrom(const DeadRegisterInstructionAnalysis &successor) {
        const auto prevAfter = after;
        after &= successor.before;
        return after != prevAfter;
    }

    CallerSaveRegisterSet getDeadRegisters() const;

    static bool isForwardAnalysis() { return false; }

private:
    static std::vector<int> registerBitIndices(x86_reg reg);
    static void setBits(std::bitset<47> &bitset, x86_reg reg);

private:
    std::bitset<47> before;
    std::bitset<47> after;

    std::bitset<47> writtenRegs;
    std::bitset<47> readRegs;

    CallerSaveRegisterSet writtenInFunction;
};

class UndefinedRegisterInstructionAnalysis
{
public:
    UndefinedRegisterInstructionAnalysis(Instruction *instruction, const RegisterAnalysisCommon &common);
    // for std::map (should never be called)
    UndefinedRegisterInstructionAnalysis() {}

    inline void updateData() {
        undefinedAfter = (undefinedBefore | makeUndefined) & ~makeDefined;
    }

    // returns true if the data has changed
    inline bool mergeFrom(const UndefinedRegisterInstructionAnalysis &predecessor) {
        const auto prevBefore = undefinedBefore;
        undefinedBefore |= predecessor.undefinedAfter;
        return undefinedBefore != prevBefore;
    }

    CallerSaveRegisterSet getDeadRegisters() const;

    bool hasProblem() const { return (undefinedBefore & readRegs).any(); }

    static bool isForwardAnalysis() { return true; }

private:
    CallerSaveRegisterSet undefinedBefore;
    CallerSaveRegisterSet undefinedAfter;

    CallerSaveRegisterSet makeUndefined;
    CallerSaveRegisterSet makeDefined;
    CallerSaveRegisterSet readRegs;
};

#endif // DEADREGISTERANALYSIS_H
