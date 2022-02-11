#ifndef EXCEPTIONHANDLING_H
#define EXCEPTIONHANDLING_H

#include <irdb-core>

class ExceptionHandling
{
public:
    ExceptionHandling(IRDB_SDK::FileIR_t *ir, IRDB_SDK::Instruction_t *tsanFunctionExit);

    void handleFunction(IRDB_SDK::Function_t *function);

private:
    bool hasExistingCallSite(IRDB_SDK::Function_t *function) const;
    IRDB_SDK::Instruction_t *findUnwindResume() const;
    IRDB_SDK::Relocation_t *findPersonalityRelocation() const;

private:
    IRDB_SDK::FileIR_t *file;
    IRDB_SDK::Instruction_t *tsanFunctionExit;
    IRDB_SDK::Instruction_t *unwindResume;
    IRDB_SDK::Relocation_t *personalityRelocation;
};

#endif // EXCEPTIONHANDLING_H
