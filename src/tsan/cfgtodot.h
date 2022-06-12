#ifndef CFGTODOT_H
#define CFGTODOT_H

#include "controlflowgraph.h"

namespace CFGToDot
{
    std::string createDotFromCFG(const ControlFlowGraph &cfg);
};

#endif // CFGTODOT_H
