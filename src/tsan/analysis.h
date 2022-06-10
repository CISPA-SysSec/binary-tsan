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

struct FunctionInfo {
    // the first instruction not doing stack frame stuff etc.
    IRDB_SDK::Instruction_t *properEntryPoint;
    // the first instructions of the stack cleanups
    std::vector<IRDB_SDK::Instruction_t*> exitPoints;
    // all instructions with memory accesses that should be instrumented
    std::set<IRDB_SDK::Instruction_t*> instructionsToInstrument;
    bool isLeafFunction;
    std::set<IRDB_SDK::Instruction_t*> stackUnsafe;
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

    FunctionInfo analyseFunction(const Function &function);
    void printStatistics() const;
    std::function<void()> getInstructionCounter(InstrumentationType type);
    CallerSaveRegisterSet getDeadRegisters(IRDB_SDK::Instruction_t *instruction) const;

private:
    std::set<IRDB_SDK::Instruction_t*> detectStaticVariableGuards(const Function &function) const;
    std::set<IRDB_SDK::Instruction_t*> detectStackCanaryInstructions(const Function &function) const;
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferAtomicInstructions(const Function &function, const std::set<IRDB_SDK::Instruction_t*> &spinLockInstructions) const;
    bool isDataConstant(IRDB_SDK::FileIR_t *ir, IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand);
    std::set<IRDB_SDK::Instruction_t *> findSpinLocks(IRDB_SDK::ControlFlowGraph_t *cfg) const;
    std::set<IRDB_SDK::Function_t*> findNoReturnFunctions() const;
    void computeFunctionRegisterWrites();
    void findWrittenRegistersRecursive(IRDB_SDK::Function_t *function, std::set<IRDB_SDK::Function_t*> &visited, CapstoneHandle &capstone);
    void updateDeadRegisters(const Function &function);
    bool isNoReturnCall(IRDB_SDK::Instruction_t *instruction) const;
    void computeMaxFunctionArguments();

private:
    IRDB_SDK::FileIR_t *ir;
    Options options;

    std::set<IRDB_SDK::Function_t*> noReturnFunctions;
    std::map<IRDB_SDK::Function_t*, CallerSaveRegisterSet> functionWrittenRegisters;
    std::map<IRDB_SDK::Function_t*, int> maxFunctionArguments;

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
    std::size_t pointerInferredAtomics = 0;
    std::size_t staticVariableGuards = 0;
    std::size_t spinLocks = 0;
};

#endif // ANALYSIS_H
