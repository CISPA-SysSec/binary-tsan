#ifndef ATTRIBUTION_H
#define ATTRIBUTION_H

#include <inttypes.h>

struct Attribution {
    uintptr_t instrumentedAddress;
    uintptr_t originalAddress;
    char disassembly[32];
};

#endif // ATTRIBUTION_H
