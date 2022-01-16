#ifndef TSANTRANSFORM_H
#define TSANTRANSFORM_H

#include <irdb-transform>
#include <irdb-core>
#include <irdb-deep>
#include <array>
#include <fstream>

struct FunctionInfo {
    // the first instruction not doing stack frame stuff etc.
    IRDB_SDK::Instruction_t *properEntryPoint;
    // the first instructions of the stack cleanups
    std::vector<IRDB_SDK::Instruction_t*> exitPoints;
    // the instructions used for construction and cleanup of the stack
    std::set<IRDB_SDK::Instruction_t*> noInstrumentInstructions;
    // non zero only if the size is not present in the Function_t class and could be inferred
    int inferredStackFrameSize = 0;
};

class TSanTransform : public IRDB_SDK::TransformStep_t {
public:
    TSanTransform();
    std::string getStepName(void) const override;
    int parseArgs(const std::vector<std::string> stepArgs) override;
    int executeStep() override;

private:
    void registerDependencies();
    void instrumentMemoryAccess(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand, int extraStack);
    int inferredStackFrameSize(const IRDB_SDK::Function_t *function) const;
    void insertFunctionEntry(IRDB_SDK::Instruction_t *insertBefore);
    void insertFunctionExit(IRDB_SDK::Instruction_t *insertBefore);
    std::set<std::string> getSaveRegisters(IRDB_SDK::Instruction_t *instruction);

private:
    mutable std::ofstream print;

    std::unique_ptr<IRDB_SDK::DeadRegisterMap_t> deadRegisters;
    FunctionInfo analyseFunction(IRDB_SDK::Function_t *function);

    // tsan functions
    IRDB_SDK::Instruction_t *tsanInit;
    // void(void*)
    IRDB_SDK::Instruction_t *tsanFunctionEntry;
    // void()
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    std::array<IRDB_SDK::Instruction_t*, 9> tsanRead;
    std::array<IRDB_SDK::Instruction_t*, 9> tsanWrite;
};

#endif // TSANTRANSFORM_H
