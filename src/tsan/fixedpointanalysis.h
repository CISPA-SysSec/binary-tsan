#ifndef FIXEDPOINTANALYSIS_H
#define FIXEDPOINTANALYSIS_H

#include <irdb-core>
#include <irdb-cfg>

#include "function.h"

namespace FixedPointAnalysis
{
    // the analysis template must have the following functions:
    //    static Analysis merge(const std::vector<Analysis> &parts);
    //    Analysis afterInstruction(const IRDB_SDK::Instruction_t *instruction) const;
    //    bool differsFrom(const Analysis &other) const;
    template<typename Analysis>
    std::map<Instruction*, Analysis> runForward(const Function &function, Analysis atFunctionEntry);

    template<typename InstructionAnalysis, typename AnalysisCommon>
    std::map<Instruction*, InstructionAnalysis> runAnalysis(
            const ControlFlowGraph &cfg,
            const std::set<std::pair<const BasicBlock*, const BasicBlock*>> &removeEdges,
            const AnalysisCommon &commonData);

    // TODO: check for syscalls
    // TODO: check if function entry point exists
    // TODO: check and abort on exceptions in the function
    // returns {can handle backward analysis, can handle forward analysis}
    std::pair<bool, bool> canHandle(const Function &function);
};

#endif // FIXEDPOINTANALYSIS_H
