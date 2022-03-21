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
#include "register.h"
#include "annotations.h"
#include "helper.h"

enum RemoveOption {
    REMOVE_ORIGINAL_INSTRUCTION,
    KEEP_ORIGINAL_INSTRUCTION
};

enum PreserveFlagsOption {
    PRESERVE_FLAGS,
    NO_PRESERVE_FLAGS
};

struct OperationInstrumentation
{
    OperationInstrumentation(const std::vector<std::string> &i, std::vector<IRDB_SDK::Instruction_t*> c, RemoveOption r,
                             const std::vector<std::string> &n, PreserveFlagsOption p) :
        instructions(i),
        callTargets(c),
        removeOriginalInstruction(r),
        noSaveRegisters(n),
        preserveFlags(p)
    {}

    // just the instructions for the tsan function call.
    // the memory access location is already loaded into rdi
    std::vector<std::string> instructions;
    // is used as the target for any instruction that includes "call"
    std::vector<IRDB_SDK::Instruction_t*> callTargets;
    RemoveOption removeOriginalInstruction;
    // if present, do not save and restore this register to/from the stack
    std::vector<std::string> noSaveRegisters;
    // whether or not to preserve the flags to the stack prior to the instrumentation
    PreserveFlagsOption preserveFlags;
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
    void insertFunctionEntry(IRDB_SDK::Function_t *function, IRDB_SDK::Instruction_t *insertBefore);
    void insertFunctionExit(IRDB_SDK::Instruction_t *insertBefore);
    std::set<std::string> getSaveRegisters(IRDB_SDK::Instruction_t *instruction, bool addXmmRegisters);
    std::optional<OperationInstrumentation> getInstrumentation(IRDB_SDK::Instruction_t *instruction,
                                                                const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand,
                                                                const FunctionInfo &info) const;
    std::optional<OperationInstrumentation> getAtomicInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand,
                                                                     const __tsan_memory_order memoryOrder) const;
    std::optional<OperationInstrumentation> getRepInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decoded) const;
    std::optional<OperationInstrumentation> getConditionalInstrumentation(const std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decoded,
                                                                          const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand) const;
    void instrumentAnnotation(IRDB_SDK::Instruction_t *instruction, const std::vector<HappensBeforeAnnotation> &annotations, const FunctionInfo &info);

    struct SaveStateInfo {
        std::vector<std::string> xmmRegistersToSave;
        std::vector<std::string> generalPurposeRegistersToSave;
        int directStackOffset;
        // the number of bytes between the rsp before and after saving the registers
        int totalStackOffset;
        bool flagsAreSaved;
    };
    SaveStateInfo saveStateToStack(InstructionInserter &inserter, IRDB_SDK::Instruction_t *before, bool preserveFlags,
                                   const std::vector<std::string> &ignoreRegisters, const FunctionInfo &info);
    void restoreStateFromStack(const SaveStateInfo &state, InstructionInserter &inserter);

private:
    struct Instrumentation {
        IRDB_SDK::Instruction_t *instrumentation;
        InstrumentationInfo info;
    };

    // options
    enum class DeadRegisterAnalysisType {
        STARS,
        CUSTOM,
        NONE
    };
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
    bool useUndefinedRegisterAnalysis = false;
    bool noInstrumentAtomics = false;
    bool useCustomLibTsan = true;
    Annotations annotations;

    std::map<IRDB_SDK::Instruction_t*, CallerSaveRegisterSet> deadRegisters;

    Analysis functionAnalysis;

    std::vector<Instrumentation> instrumentationAttribution;

    // tsan functions
    // void(void*)
    IRDB_SDK::Instruction_t *tsanFunctionEntry;
    // void()
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    // void(void*)
    std::array<IRDB_SDK::Instruction_t*, 17> tsanRead;
    std::array<IRDB_SDK::Instruction_t*, 17> tsanWrite;
    // void(void*, unsigned long)
    IRDB_SDK::Instruction_t *tsanReadRange;
    IRDB_SDK::Instruction_t *tsanWriteRange;
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
    // void(int*)
    IRDB_SDK::Instruction_t *tsanAcquire;
    IRDB_SDK::Instruction_t *tsanRelease;

    const std::string MOVE_OPERAND_RDI = "__move_operand_to_rdi";
};

#endif // TSANTRANSFORM_H
