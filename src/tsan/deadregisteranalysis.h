#ifndef DEADREGISTERANALYSIS_H
#define DEADREGISTERANALYSIS_H

#include <irdb-core>
#include <irdb-util>
#include <capstone/capstone.h>
#include <capstone/x86.h>

struct DeadRegisterAnalysisCommon
{
    DeadRegisterAnalysisCommon() {
        cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle);
        cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(capstoneHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }
    ~DeadRegisterAnalysisCommon() {
        cs_close(&capstoneHandle);
    }

    csh capstoneHandle;
};

class DeadRegisterInstructionAnalysis
{
public:
    DeadRegisterInstructionAnalysis(IRDB_SDK::Instruction_t *instruction, const DeadRegisterAnalysisCommon &common);
    // for std::map (should never be called)
    DeadRegisterInstructionAnalysis() {}

    inline void updateDataBefore() {
        // assume that values are read first and written afterwards (if one register is read and written)
        before = (after | writtenRegs) & (~readRegs);
    }

    // returns true if the data has changed
    inline bool mergeFrom(const DeadRegisterInstructionAnalysis &successor) {
        const auto prevAfter = after;
        after &= successor.before;
        return after != prevAfter;
    }

    std::set<IRDB_SDK::RegisterID> getDeadRegisters() const;

private:
    static std::vector<int> registerBitIndices(x86_reg reg);
    static void setBits(std::bitset<40> &bitset, x86_reg reg);

private:
    std::bitset<40> before;
    std::bitset<40> after;

    std::bitset<40> writtenRegs;
    std::bitset<40> readRegs;
};

#endif // DEADREGISTERANALYSIS_H
