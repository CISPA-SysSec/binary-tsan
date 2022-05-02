#ifndef OPTIONS_H
#define OPTIONS_H

#include "annotations.h"

enum class DeadRegisterAnalysisType {
    STARS,
    CUSTOM,
    NONE
};

struct Options
{
    DeadRegisterAnalysisType deadRegisterAnalysisType = DeadRegisterAnalysisType::CUSTOM;
    bool dryRun = false;
    bool atomicsOnly = false;
    bool instrumentFunctionEntryExit = true;
    // whether to actually call the thread sanitizer; for benchmarking purposes
    bool addTsanCalls = true;
    // if it contains at least one element, instrument only those functions
    std::set<std::string> instrumentOnlyFunctions;
    bool saveXmmRegisters = false;
    bool addLibTsanDependency = true;
    bool useUndefinedRegisterAnalysis = true;
    bool noInstrumentAtomics = false;
    bool useCustomLibTsan = true;
    bool useWrapperFunctions = false;
    bool instrumentStackAccess = true;
    Annotations annotations;

    static void printOptionsHelp();
    static std::optional<Options> parseAndProcess(IRDB_SDK::FileIR_t *ir, const std::vector<std::string> &options);
};

#endif // OPTIONS_H
