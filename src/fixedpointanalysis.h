#ifndef FIXEDPOINTANALYSIS_H
#define FIXEDPOINTANALYSIS_H

#include <irdb-core>

namespace FixedPointAnalysis
{
    // the analysis template must have the following functions:
    //    static Analysis merge(const std::vector<Analysis> &parts);
    //    Analysis afterInstruction(const IRDB_SDK::Instruction_t *instruction) const;
    //    bool differsFrom(const Analysis &other) const;
    template<typename Analysis>
    std::map<IRDB_SDK::Instruction_t*, Analysis> run(IRDB_SDK::Function_t *function, Analysis atFunctionEntry);

    // TODO: check for memory indirect jumps
    // TODO: check if function entry point exists
    // TODO: check and abort on exceptions in the function
    inline bool isApplicable(IRDB_SDK::Function_t*) { return true; }
};

#endif // FIXEDPOINTANALYSIS_H
