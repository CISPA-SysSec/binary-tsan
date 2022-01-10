#include <iostream>
#include <irdb-util>
#include <irdb-core>

#include "tsantransform.h"

extern "C" std::shared_ptr<IRDB_SDK::TransformStep_t> getTransformStep(void)
{
    return std::shared_ptr<IRDB_SDK::TransformStep_t>(new TSanTransform());
}
