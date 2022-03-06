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
    std::map<IRDB_SDK::Instruction_t*, Analysis> runForward(IRDB_SDK::Function_t *function, Analysis atFunctionEntry);

    template<typename BackwardsInstructionAnalysis, typename BackwardsAnalysisCommon>
    std::map<IRDB_SDK::Instruction_t*, BackwardsInstructionAnalysis> runAnalysis(IRDB_SDK::Function_t *function, const std::set<IRDB_SDK::Function_t*> &noReturnFunctions);

    // TODO: check for syscalls
    // TODO: check if function entry point exists
    // TODO: check and abort on exceptions in the function
    bool canHandle(IRDB_SDK::Function_t*function);
};

#endif // FIXEDPOINTANALYSIS_H
