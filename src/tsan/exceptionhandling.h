#ifndef EXCEPTIONHANDLING_H
#define EXCEPTIONHANDLING_H

#include <irdb-core>

#include "helper.h"
#include "function.h"

class ExceptionHandling
{
public:
    ExceptionHandling(IRDB_SDK::FileIR_t *ir, IRDB_SDK::Instruction_t *tsanFunctionExit);

    void handleFunction(const Function &function, InstructionInserter &inserter);

private:
    bool hasEmptyCallSite(const Function &function) const;
    IRDB_SDK::Instruction_t *findUnwindResume() const;
    IRDB_SDK::Relocation_t *findPersonalityRelocation() const;

private:

    struct EhProgramHolder
    {
        EhProgramHolder(const IRDB_SDK::EhProgram_t* orig) :
            caf(orig->getCodeAlignmentFactor()),
            daf(orig->getDataAlignmentFactor()),
            rr(orig->getReturnRegNumber()),
            ptrsize(orig->getPointerSize()),
            cieProgram(orig->getCIEProgram()),
            fdeProgram(orig->getFDEProgram()),
            relocs(orig->getRelocations())
        { }

        uint8_t caf;
        int8_t daf;
        int8_t rr;
        uint8_t ptrsize;
        IRDB_SDK::EhProgramListing_t cieProgram;
        IRDB_SDK::EhProgramListing_t fdeProgram;
        IRDB_SDK::RelocationSet_t relocs;

        bool operator<(const EhProgramHolder &b) const
        {
            return tie( this->caf, this->daf, this->rr, this->ptrsize, this->cieProgram, this->fdeProgram, this->relocs ) <
                   tie( b.caf, b.daf, b.rr, b.ptrsize, b.cieProgram, b.fdeProgram, b.relocs ) ;
        }
    };

    std::map<EhProgramHolder, IRDB_SDK::Instruction_t*> ehProgramToLandingPad;

    IRDB_SDK::FileIR_t *file;
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    IRDB_SDK::Instruction_t *unwindResume;
    IRDB_SDK::Relocation_t *personalityRelocation;
};

#endif // EXCEPTIONHANDLING_H
