#include "instructionmap.h"

#include <cstring>

#include "simplefile.h"
#include "protobuf/instrumentationmap.pb.h"

using namespace IRDB_SDK;
using namespace Zipr_SDK;

void InstructionMap::doCallbackLinkingEnd()
{
    InternalInstrumentationMap internalMap;
    readProtobufFromFile(internalMap, "tsan-attribution.dat");

    InstrumentationMap resultMap;
    for (const auto &[instruction, addr] : instructionLocations) {
        const RangeAddress_t endAddr = addr + instruction->getDataBits().size() - 1;
        auto it = internalMap.instrumentation().find(instruction->getBaseID());
        if (it != internalMap.instrumentation().end()) {
            InstrumentationInfo info = it->second;
            if (instruction->getFunction() != nullptr) {
                info.set_function_name(instruction->getFunction()->getName());
            }
            resultMap.mutable_instrumentation()->insert({endAddr, info});
        } else {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            // TODO: if original address is 0, the instruction is an instrumentation instruction
            if (decoded->isCall()) {
                InstrumentationInfo info;
                info.set_original_address(instruction->getAddress()->getVirtualOffset());
                if (instruction->getFunction() != nullptr) {
                    info.set_function_name(instruction->getFunction()->getName());
                }
                resultMap.mutable_instrumentation()->insert({endAddr, info});
            }
        }
    }

    writeProtobufToFile(resultMap, "tsan-instrumentation-info.dat");
}

extern "C" ZiprPluginInterface_t* GetPluginInterface(Zipr_t* zipr)
{
    return new InstructionMap(zipr->getFileIR(), zipr->getLocationMap());
}
