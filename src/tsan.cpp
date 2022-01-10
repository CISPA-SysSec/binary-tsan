#include <iostream>
#include <irdb-transform>
#include <irdb-core>

#include <memory>

using namespace IRDB_SDK;

class TSanTransform : public TransformStep_t {
public:
    string getStepName(void) const override {
        return "thread sanitizer";
    }

    int parseArgs(const vector<string> step_args) override {
        return 0;
    }

    int executeStep() override {
        return 0;
    }
};

extern "C" std::shared_ptr<IRDB_SDK::TransformStep_t> getTransformStep(void)
{
    std::cout <<"Hello world!"<<std::endl;
    return std::shared_ptr<IRDB_SDK::TransformStep_t>(new TSanTransform());
}
