#ifndef TSANTRANSFORM_H
#define TSANTRANSFORM_H

#include <irdb-transform>
#include <irdb-core>
#include <irdb-deep>
#include <array>
#include <fstream>
#include <optional>

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
    std::set<IRDB_SDK::Instruction_t*> inferredAtomicInstructions;
};

struct OperationInstrumentation
{
    OperationInstrumentation(const std::vector<std::string> &i, IRDB_SDK::Instruction_t *c, bool r,
                             const std::optional<std::string> &n, bool p) :
        instructions(i),
        callTarget(c),
        removeOriginalInstruction(r),
        noSaveRegister(n),
        preserveFlags(p)
    {}

    // just the instructions for the tsan function call.
    // the memory access location is already loaded into rdi
    std::vector<std::string> instructions;
    // is used as the target for any instruction that includes "call"
    IRDB_SDK::Instruction_t *callTarget;
    bool removeOriginalInstruction;
    // if present, do not save and restore this register to/from the stack
    std::optional<std::string> noSaveRegister;
    // whether or not to preserve the flags to the stack prior to the instrumentation
    bool preserveFlags;
};

class TSanTransform : public IRDB_SDK::Transform_t {
public:
    TSanTransform(IRDB_SDK::FileIR_t * file);

    bool parseArgs(const std::vector<std::string> &options);
    bool executeStep();

private:
    void registerDependencies();
    void instrumentMemoryAccess(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand, const FunctionInfo &info);
    int inferredStackFrameSize(const IRDB_SDK::Function_t *function) const;
    void insertFunctionEntry(IRDB_SDK::Instruction_t *insertBefore);
    void insertFunctionExit(IRDB_SDK::Instruction_t *insertBefore);
    std::set<std::string> getSaveRegisters(IRDB_SDK::Instruction_t *instruction);
    static bool isAtomic(IRDB_SDK::Instruction_t *instruction);
    static bool isRepeated(IRDB_SDK::Instruction_t *instruction);
    static bool isDataConstant(IRDB_SDK::FileIR_t *ir, IRDB_SDK::Instruction_t *instruction,
                               const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand);
    OperationInstrumentation getInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand,
                                                const FunctionInfo &info) const;
    std::optional<OperationInstrumentation> getAtomicInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand) const;
    std::set<IRDB_SDK::Instruction_t*> detectStaticVariableGuards(IRDB_SDK::Function_t *function) const;
    std::set<IRDB_SDK::Instruction_t*> detectStackCanaryInstructions(IRDB_SDK::Function_t *function) const;
    bool doesStackLeaveFunction(IRDB_SDK::Function_t *function) const;

private:
    mutable std::ofstream print;

    // options
    bool useStarsAnalysis = false;

    std::unique_ptr<IRDB_SDK::DeadRegisterMap_t> deadRegisters;
    FunctionInfo analyseFunction(IRDB_SDK::Function_t *function);

    // tsan functions
    IRDB_SDK::Instruction_t *tsanInit;
    // void(void*)
    IRDB_SDK::Instruction_t *tsanFunctionEntry;
    // void()
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanRead;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanWrite;
    // atomics
    // int(int*, __tsan_memory_order)
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicLoad;
    // int(int*, int, __tsan_memory_order)
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicFetchAdd;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicFetchSub;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicFetchAnd;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicFetchOr;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicFetchXor;
    // int(int*, int, int, __tsan_memory_order, __tsan_memory_order)
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicCompareExchangeVal;

    const std::string MOVE_OPERAND_RDI = "__move_operand_to_rdi";
};

#endif // TSANTRANSFORM_H
