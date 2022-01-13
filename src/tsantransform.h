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
};

class TSanTransform : public IRDB_SDK::TransformStep_t {
public:
    TSanTransform();
    std::string getStepName(void) const override;
    int parseArgs(const std::vector<std::string> stepArgs) override;
    int executeStep() override;

private:
    void registerDependencies();
    void instrumentMemoryAccess(IRDB_SDK::Instruction_t *instruction, const std::shared_ptr<IRDB_SDK::DecodedOperand_t> operand);

private:
    std::ofstream print;

    std::unique_ptr<IRDB_SDK::DeadRegisterMap_t> deadRegisters;
    FunctionInfo analyseFunction(IRDB_SDK::Function_t *function);

    // tsan functions
    IRDB_SDK::Instruction_t *tsanInit;
    IRDB_SDK::Instruction_t *tsanFunctionEntry;
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    std::array<IRDB_SDK::Instruction_t*, 8> tsanRead;
    std::array<IRDB_SDK::Instruction_t*, 8> tsanWrite;
};

#endif // TSANTRANSFORM_H
