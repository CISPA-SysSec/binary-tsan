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

struct LibraryFunction
{
    LibraryFunction(IRDB_SDK::Instruction_t *target, x86_reg reg = X86_REG_RDI) :
        callTarget(target),
        argumentRegister(reg)
        // no registers are preserved,
    { }
    IRDB_SDK::Instruction_t *callTarget;
    x86_reg argumentRegister;
    CallerSaveRegisterSet preserveRegisters;
};

using LibraryFunctionOptions = std::vector<LibraryFunction>;

struct OperationInstrumentation
{
    OperationInstrumentation(const std::vector<std::string> &i, std::vector<LibraryFunctionOptions> c, RemoveOption r,
                             CallerSaveRegisterSet n) :
        instructions(i),
        callTargets(c),
        removeOriginalInstruction(r),
        noSaveRegisters(n)
    { }

    // just the instructions for the tsan function call.
    // the memory access location is already loaded into rdi
    std::vector<std::string> instructions;
    // is used as the target for any instruction that includes "call"
    std::vector<LibraryFunctionOptions> callTargets;
    RemoveOption removeOriginalInstruction;
    // do not save and restore these register to/from the stack
    CallerSaveRegisterSet noSaveRegisters;
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
    std::vector<std::string> getSaveRegisters(IRDB_SDK::Instruction_t *instruction, CallerSaveRegisterSet ignoreRegisters);
    std::optional<OperationInstrumentation> getInstrumentation(IRDB_SDK::Instruction_t *instruction,
                                                                const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand,
                                                                const FunctionInfo &info) const;
    std::optional<OperationInstrumentation> getAtomicInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand,
                                                                     const __tsan_memory_order memoryOrder) const;
    std::optional<OperationInstrumentation> getRepInstrumentation(IRDB_SDK::Instruction_t *instruction, const std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decoded) const;
    std::optional<OperationInstrumentation> getConditionalInstrumentation(const std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decoded,
                                                                          const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand) const;
    void instrumentAnnotation(IRDB_SDK::Instruction_t *instruction, const std::vector<HappensBeforeAnnotation> &annotations, const FunctionInfo &info);
    LibraryFunctionOptions createWrapper(IRDB_SDK::Instruction_t *target);
    LibraryFunction selectFunctionVersion(IRDB_SDK::Instruction_t *before, const LibraryFunctionOptions &options) const;
    void findAndMergeFunctions();

    struct SaveStateInfo {
        std::vector<std::string> xmmRegistersToSave;
        std::vector<std::string> generalPurposeRegistersToSave;
        int directStackOffset;
        // the number of bytes between the rsp before and after saving the registers
        int totalStackOffset;
        bool flagsAreSaved;
    };
    SaveStateInfo saveStateToStack(InstructionInserter &inserter, IRDB_SDK::Instruction_t *before,
                                   CallerSaveRegisterSet ignoreRegisters, const FunctionInfo &info);
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
    bool useUndefinedRegisterAnalysis = true;
    bool noInstrumentAtomics = false;
    bool useCustomLibTsan = true;
    bool useWrapperFunctions = false;
    Annotations annotations;

    std::map<IRDB_SDK::Instruction_t*, CallerSaveRegisterSet> deadRegisters;

    Analysis functionAnalysis;

    std::vector<Instrumentation> instrumentationAttribution;

    // tsan functions
    // void(void*)
    LibraryFunctionOptions tsanFunctionEntry;
    // void()
    LibraryFunctionOptions tsanFunctionExit;
    // void(void*)
    std::array<LibraryFunctionOptions, 17> tsanRead;
    std::array<LibraryFunctionOptions, 17> tsanWrite;
    // void(void*, unsigned long)
    LibraryFunctionOptions tsanReadRange;
    LibraryFunctionOptions tsanWriteRange;
    // atomics
    // int(int*, __tsan_memory_order)
    std::array<LibraryFunctionOptions, 17> tsanAtomicLoad;
    // int(int*, int, __tsan_memory_order)
    std::array<LibraryFunctionOptions, 17> tsanAtomicStore;
    std::array<LibraryFunctionOptions, 17> tsanAtomicExchange;
    // int(int*, int, __tsan_memory_order)
    std::array<LibraryFunctionOptions, 17> tsanAtomicFetchAdd;
    std::array<LibraryFunctionOptions, 17> tsanAtomicFetchSub;
    std::array<LibraryFunctionOptions, 17> tsanAtomicFetchAnd;
    std::array<LibraryFunctionOptions, 17> tsanAtomicFetchOr;
    std::array<LibraryFunctionOptions, 17> tsanAtomicFetchXor;
    // int(int*, int, int, __tsan_memory_order, __tsan_memory_order)
    std::array<LibraryFunctionOptions, 17> tsanAtomicCompareExchangeVal;
    // void(int*)
    LibraryFunctionOptions tsanAcquire;
    LibraryFunctionOptions tsanRelease;

    const std::string MOVE_OPERAND_RDI = "__move_operand_to_rdi";
};

#endif // TSANTRANSFORM_H
