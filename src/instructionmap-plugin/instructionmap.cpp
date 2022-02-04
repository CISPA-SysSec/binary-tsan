#include "instructionmap.h"

#include <cstring>

#include "simplefile.h"
#include "attribution.h"

using namespace IRDB_SDK;
using namespace Zipr_SDK;

void InstructionMap::doCallbackLinkingEnd()
{
    std::vector<Attribution> instrumentationAttribution = readSimpleDataFromFile<Attribution>("tsan-attribution.dat");

    std::map<DatabaseID_t, Attribution> attributionMap;
    for (const auto &attribution : instrumentationAttribution) {
        attributionMap[attribution.instrumentedAddress] = attribution;
    }

    std::vector<Attribution> instrumentationLocation;
    for (const auto &[instruction, addr] : instructionLocations) {
        auto it = attributionMap.find(instruction->getBaseID());
        if (it != attributionMap.end()) {
            const RangeAddress_t endAddr = addr + instruction->getDataBits().size() - 1;
            Attribution a = it->second;
            a.instrumentedAddress = endAddr;
            instrumentationLocation.push_back(a);
        } else {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            if (decoded->isCall()) {
                const RangeAddress_t endAddr = addr + instruction->getDataBits().size() - 1;
                Attribution a;
                a.instrumentedAddress = endAddr;
                a.originalAddress = instruction->getAddress()->getVirtualOffset();
                a.disassembly[0] = 0;
                instrumentationLocation.push_back(a);
            }
        }
    }

    writeSimpleDataToFile(instrumentationLocation, "tsan-instrumentation-attribution.dat");
    writeSimpleDataToFile(instrumentationLocation, "../tsan-instrumentation-attribution.dat");
}

extern "C" ZiprPluginInterface_t* GetPluginInterface(Zipr_t* zipr)
{
    return new InstructionMap(zipr->getFileIR(), zipr->getLocationMap());
}
