#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <irdb-core>
#include <map>
#include <set>
#include <functional>
#include <irdb-deep>

#include "register.h"
#include "options.h"
#include "function.h"
#include "program.h"

struct FunctionInfo {
    // the first instruction not doing stack frame stuff etc.
    Instruction *properEntryPoint;
    // the first instructions of the stack cleanups
    std::vector<Instruction*> exitPoints;
    // all instructions with memory accesses that should be instrumented
    std::set<Instruction*> instructionsToInstrument;
    bool isLeafFunction;
    std::set<Instruction*> stackUnsafe;
    // instruction like guard variable reads that count as atomic by thread sanitizer standards
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferredAtomicInstructions;
    bool addEntryExitInstrumentation;
};

enum class InstrumentationType
{
    MEMORY_ACCESS,
    ENTRY_EXIT,
    EXCEPTION_HANDLING,
    WRAPPER
};

class Analysis
{
public:
    Analysis(IRDB_SDK::FileIR_t *ir);
    void init(const Options &options);
    void analyseProgram(const Program &program);

    FunctionInfo analyseFunction(const Function &function, Program &program);
    void printStatistics() const;
    std::function<void()> getInstructionCounter(InstrumentationType type);
    CallerSaveRegisterSet getDeadRegisters(Instruction *instruction) const;

private:
    std::set<Instruction*> detectStaticVariableGuards(const Function &function) const;
    std::set<Instruction*> detectStackCanaryInstructions(const Function &function) const;
    std::map<Instruction*, __tsan_memory_order> inferAtomicInstructions(const Function &function, const std::set<IRDB_SDK::Instruction_t*> &spinLockInstructions) const;
    bool isDataConstant(IRDB_SDK::FileIR_t *ir, Instruction *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand);
    std::set<IRDB_SDK::Instruction_t *> findSpinLocks(const Function &function, Program &program) const;
    std::set<const Function*> findNoReturnFunctions(const Program &program) const;
    void computeFunctionRegisterWrites(const Program &program);
    void findWrittenRegistersRecursive(const Function *function, std::set<const Function *> &visited);
    void updateDeadRegisters(const Function &function);
    bool isNoReturnCall(Instruction *instruction) const;
    void computeMaxFunctionArguments(const Program &program);

private:
    IRDB_SDK::FileIR_t *ir;
    Options options;

    std::set<const Function*> noReturnFunctions;
    std::map<const Function*, CallerSaveRegisterSet> functionWrittenRegisters;
    std::map<const Function*, int> maxFunctionArguments;

    std::map<IRDB_SDK::Instruction_t*, CallerSaveRegisterSet> deadRegisters;

    // statistics

    // functions
    std::size_t totalAnalysedFunctions = 0;
    std::size_t entryExitInstrumentedFunctions = 0;
    std::size_t canDoRegisterAnalysisFunctions = 0;

    // instructions
    std::size_t totalAnalysedInstructions = 0;
    std::size_t memoryInstrumentationInstructions = 0;
    std::size_t entryExitInstrumentationInstructions = 0;
    std::size_t exceptionInstrumentationInstructions = 0;
    std::size_t wrapperInstrumentationInstructions = 0;
    std::size_t totalInstrumentedInstructions = 0;
    // instructions that were not instrumented
    std::size_t totalNotInstrumented = 0;
    std::size_t stackCanaryInstructions = 0;
    std::size_t stackLocalVariables = 0;
    std::size_t constantMemoryRead = 0;
    std::size_t stackMemory = 0;
    // atomics
    std::size_t prefixAtomics = 0;
    std::size_t pointerInferredAtomics = 0;
    std::size_t staticVariableGuards = 0;
    std::size_t spinLocks = 0;
};

#endif // ANALYSIS_H
