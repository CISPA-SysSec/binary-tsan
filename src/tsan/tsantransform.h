#ifndef TSANTRANSFORM_H
#define TSANTRANSFORM_H

#include <irdb-transform>
#include <irdb-core>
#include <irdb-deep>
#include <array>
#include <fstream>
#include <optional>

#include "protobuf/instrumentationmap.pb.h"
#include "analysis.h"

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
    virtual ~TSanTransform();

    bool parseArgs(const std::vector<std::string> &options);
    bool executeStep();

private:
    void registerDependencies();
    void instrumentMemoryAccess(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand, const FunctionInfo &info);
    void insertFunctionEntry(IRDB_SDK::Instruction_t *insertBefore);
    void insertFunctionExit(IRDB_SDK::Instruction_t *insertBefore);
    std::set<std::string> getSaveRegisters(IRDB_SDK::Instruction_t *instruction);
    static bool isRepeated(IRDB_SDK::Instruction_t *instruction);
    OperationInstrumentation getInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand,
                                                const FunctionInfo &info) const;
    std::optional<OperationInstrumentation> getAtomicInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand,
                                                                     const __tsan_memory_order memoryOrder) const;

private:
    struct Instrumentation {
        IRDB_SDK::Instruction_t *instrumentation;
        InstrumentationInfo info;
    };

    // options
    bool useStarsAnalysis = false;
    bool dryRun = false;

    std::unique_ptr<IRDB_SDK::DeadRegisterMap_t> deadRegisters;

    Analysis functionAnalysis;

    std::vector<Instrumentation> instrumentationAttribution;

    // tsan functions
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
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicStore;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanAtomicExchange;
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
