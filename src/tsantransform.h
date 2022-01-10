#ifndef TSANTRANSFORM_H
#define TSANTRANSFORM_H

#include <irdb-transform>
#include <irdb-core>

class TSanTransform : public IRDB_SDK::TransformStep_t {
public:
    std::string getStepName(void) const override;
    int parseArgs(const std::vector<std::string> stepArgs) override;
    int executeStep() override;

private:
    void addTSanFunctions();
};

#endif // TSANTRANSFORM_H
