#ifndef REGISTER_H
#define REGISTER_H

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <string>
#include <irdb-util>

using CallerSaveRegisterSet = std::bitset<26>;

using FullRegisterSet = std::bitset<X86_REG_ENDING>;

class CapstoneHandle
{
public:
    CapstoneHandle() {
        cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }
    CapstoneHandle(const CapstoneHandle&) = delete;
    CapstoneHandle(CapstoneHandle&&) = delete;
    ~CapstoneHandle() {
        cs_close(&handle);
    }

    csh handle;
};

namespace Register
{
    // not all register names can be used to encode an assembler instruction (for example eflags), use with care
    std::string registerToString(x86_reg reg);
    x86_reg registerIDToCapstoneRegister(IRDB_SDK::RegisterID reg);

    // all non caller-save registers are ignored
    // subregisters like eax are upgraded to their 64-bit variant (rax)
    void setCallerSaveRegister(CallerSaveRegisterSet &registers, x86_reg reg);
    bool hasCallerSaveRegister(const CallerSaveRegisterSet &registers, x86_reg reg);

    x86_reg getCallerSaveRegisterForIndex(std::size_t index);

    CallerSaveRegisterSet registerSet(const std::vector<x86_reg> &regs);
    CallerSaveRegisterSet xmmRegisterSet();

    x86_reg generalPurposeRegisterTo64Bit(const x86_reg reg);

    std::vector<x86_reg> getWrittenRegisters(cs_insn *decoded);
    std::vector<x86_reg> getReadRegisters(cs_insn *decoded, bool checkFalseReads);
};

#endif // REGISTER_H
