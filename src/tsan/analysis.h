#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <irdb-core>
#include <map>
#include <set>
#include <functional>
#include <irdb-deep>

// from tsan-interface-atomic.h, do not change
typedef enum {
    __tsan_memory_order_relaxed = 0,
    __tsan_memory_order_consume = 1,
    __tsan_memory_order_acquire = 2,
    __tsan_memory_order_release = 3,
    __tsan_memory_order_acq_rel = 4,
    __tsan_memory_order_seq_cst = 5
} __tsan_memory_order;

struct FunctionInfo {
    // the first instruction not doing stack frame stuff etc.
    IRDB_SDK::Instruction_t *properEntryPoint;
    // the first instructions of the stack cleanups
    std::vector<IRDB_SDK::Instruction_t*> exitPoints;
    // all instructions with memory accesses that should be instrumented
    std::set<IRDB_SDK::Instruction_t*> instructionsToInstrument;
    bool isLeafFunction;
    // instruction like guard variable reads that count as atomic by thread sanitizer standards
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferredAtomicInstructions;
    bool addEntryExitInstrumentation;
};

class Analysis
{
public:
    Analysis(IRDB_SDK::FileIR_t *ir);

    FunctionInfo analyseFunction(IRDB_SDK::Function_t *function);
    void printStatistics() const;
    std::function<void()> getInstructionCounter() { return [this](){ instrumentationInstructions++; }; }
    void countAddInstrumentationInstruction() { instrumentationInstructions++; }

private:
    std::set<IRDB_SDK::Instruction_t*> detectStaticVariableGuards(IRDB_SDK::Function_t *function) const;
    std::set<IRDB_SDK::Instruction_t*> detectStackCanaryInstructions(IRDB_SDK::Function_t *function) const;
    bool doesStackLeaveFunction(IRDB_SDK::Function_t *function) const;
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferAtomicInstructions(IRDB_SDK::Function_t *function, const std::set<IRDB_SDK::Instruction_t*> &spinLockInstructions) const;
    bool isDataConstant(IRDB_SDK::FileIR_t *ir, IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand);
    std::set<IRDB_SDK::Instruction_t *> findSpinLocks(IRDB_SDK::ControlFlowGraph_t *cfg) const;
    std::set<IRDB_SDK::Function_t*> findNoReturnFunctions() const;

private:
    IRDB_SDK::FileIR_t *ir;

    std::set<IRDB_SDK::Function_t*> noReturnFunctions;

    // statistics

    // functions
    std::size_t totalAnalysedFunctions = 0;
    std::size_t entryExitInstrumentedFunctions = 0;
    std::size_t unwindFunctions = 0;
    std::size_t canDoRegisterAnalysisFunctions = 0;

    // instructions
    std::size_t totalAnalysedInstructions = 0;
    std::size_t instrumentationInstructions = 0;
    std::size_t totalInstrumentedInstructions = 0;
    // instructions that were not instrumented
    std::size_t totalNotInstrumented = 0;
    std::size_t stackCanaryInstructions = 0;
    std::size_t stackLocalVariables = 0;
    std::size_t constantMemoryRead = 0;
    std::size_t threadLocalMemory = 0;
    // atomics
    std::size_t pointerInferredAtomics = 0;
    std::size_t staticVariableGuards = 0;
    std::size_t spinLocks = 0;
};

#endif // ANALYSIS_H
