#include "instructionmap.h"

void InstructionMap::doCallbackLinkingEnd()
{
    std::cout <<"Write instruction map:"<<std::endl;
    for (const auto &[instruction, addr] : instructionLocations) {
        std::cout <<instruction->getDisassembly()<<" "<<instruction->getAddress()<<" "<<addr<<std::endl;
    }
}

extern "C" Zipr_SDK::ZiprPluginInterface_t* GetPluginInterface(Zipr_SDK::Zipr_t* zipr_object)
{
    IRDB_SDK::FileIR_t *p_firp = zipr_object->getFileIR();
    Zipr_SDK::InstructionLocationMap_t *p_fil = zipr_object->getLocationMap();
    return new InstructionMap(p_firp, p_fil, zipr_object);
}
