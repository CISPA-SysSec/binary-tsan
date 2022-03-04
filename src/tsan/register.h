#ifndef REGISTER_H
#define REGISTER_H

#include <capstone/x86.h>
#include <string>
#include <irdb-util>

namespace Register
{
    // not all register names can be used to encode an assembler instruction (for example eflags), use with care
    std::string registerToString(x86_reg reg);
    x86_reg registerIDToCapstoneRegister(IRDB_SDK::RegisterID reg);
};

#endif // REGISTER_H
