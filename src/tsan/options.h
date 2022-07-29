#ifndef OPTIONS_H
#define OPTIONS_H

#include "annotations.h"

#include <fstream>
#include <memory>

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
    bool useMemoryProfiler = false;
    bool useHeuristics = true;
    std::shared_ptr<std::ofstream> dumpInstrumentedInstructions;
    Annotations annotations;
    std::string writeCFGFunctionName;

    static void printOptionsHelp();
    static std::optional<Options> parseAndProcess(IRDB_SDK::FileIR_t *ir, const std::vector<std::string> &options);
};

#endif // OPTIONS_H
