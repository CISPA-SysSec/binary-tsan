#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <irdb-core>
#include <map>
#include <set>

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
    // the instructions used for construction and cleanup of the stack
    std::set<IRDB_SDK::Instruction_t*> noInstrumentInstructions;
    // non zero only if the size is not present in the Function_t class and could be inferred
    int inferredStackFrameSize = 0;
    // instruction like guard variable reads that count as atomic by thread sanitizer standards
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferredAtomicInstructions;
    bool addEntryExitInstrumentation;
    bool stackLeavesFunction;
};

class Analysis
{
public:
    FunctionInfo analyseFunction(IRDB_SDK::Function_t *function);

private:
    std::set<IRDB_SDK::Instruction_t*> detectStaticVariableGuards(IRDB_SDK::Function_t *function) const;
    std::set<IRDB_SDK::Instruction_t*> detectStackCanaryInstructions(IRDB_SDK::Function_t *function) const;
    bool doesStackLeaveFunction(IRDB_SDK::Function_t *function) const;
    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> inferAtomicInstructions(IRDB_SDK::Function_t *function) const;
    int inferredStackFrameSize(const IRDB_SDK::Function_t *function) const;
};

#endif // ANALYSIS_H
