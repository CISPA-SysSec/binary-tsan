#ifndef TSANTRANSFORM_H
#define TSANTRANSFORM_H

#include <irdb-transform>
#include <irdb-core>
#include <irdb-deep>
#include <array>

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
    std::unique_ptr<IRDB_SDK::DeadRegisterMap_t> deadRegisters;

    // tsan functions
    IRDB_SDK::Instruction_t *tsanInit;
    IRDB_SDK::Instruction_t *tsanFunctionEntry;
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    std::array<IRDB_SDK::Instruction_t*, 8> tsanRead;
    std::array<IRDB_SDK::Instruction_t*, 8> tsanWrite;
};

#endif // TSANTRANSFORM_H
