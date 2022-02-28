#ifndef CFGTODOT_H
#define CFGTODOT_H

#include <irdb-cfg>

namespace CFGToDot
{
    std::string createDotFromCFG(const std::unique_ptr<IRDB_SDK::ControlFlowGraph_t> &cfg);
};

#endif // CFGTODOT_H
