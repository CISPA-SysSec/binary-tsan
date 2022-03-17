#ifndef REGISTER_H
#define REGISTER_H

#include <capstone/x86.h>
#include <string>
#include <irdb-util>

using CallerSaveRegisterSet = std::bitset<26>;

namespace Register
{
    // not all register names can be used to encode an assembler instruction (for example eflags), use with care
    std::string registerToString(x86_reg reg);
    x86_reg registerIDToCapstoneRegister(IRDB_SDK::RegisterID reg);

    // all non caller-save registers are ignored
    // subregisters like eax are upgraded to their 64-bit variant (rax)
    void setCallerSaveRegister(CallerSaveRegisterSet &registers, x86_reg reg);
    bool hasCallerSaveRegister(CallerSaveRegisterSet &registers, x86_reg reg);
};

#endif // REGISTER_H
