#ifndef INSTRUCTIONMAP_H
#define INSTRUCTIONMAP_H

#include <zipr-sdk>

class InstructionMap : public Zipr_SDK::ZiprPluginInterface_t
{
public:
    InstructionMap(IRDB_SDK::FileIR_t *file,
                   Zipr_SDK::InstructionLocationMap_t *locationMap,
                   Zipr_SDK::Zipr_t *zipr) :
        instructionLocations(*locationMap) {}

    virtual std::string toString() override { return "tsan instruction map"; }

    virtual void doCallbackLinkingEnd() override;

private:
    Zipr_SDK::InstructionLocationMap_t &instructionLocations;
};

#endif // INSTRUCTIONMAP_H
