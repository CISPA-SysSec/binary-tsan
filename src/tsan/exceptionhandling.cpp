#include "exceptionhandling.h"

#include <irdb-transform>
#include <algorithm>
#include <iostream>
#include <string>

#include "helper.h"

using namespace IRDB_SDK;

ExceptionHandling::ExceptionHandling(FileIR_t *ir, Instruction_t *tsanFunctionExit) :
    file(ir),
    tsanFunctionExit(tsanFunctionExit),
    unwindResume(findUnwindResume()),
    personalityRelocation(findPersonalityRelocation())
{
    // TODO: check if this really means that there are no landing pads anywhere
    if (unwindResume == nullptr || personalityRelocation == nullptr) {
        std::cout <<"This binary does not seem to have exceptions"<<std::endl;
    }
}

void ExceptionHandling::handleFunction(Function_t *function, InstructionInserter &inserter)
{
//    std::cout <<function->getName()<<std::endl;

    if (!hasEmptyCallSite(function)) {
        std::cout <<"Function "<<function->getName()<<" already has an exception callsite!"<<std::endl;
        return;
    }
    if (unwindResume == nullptr || personalityRelocation == nullptr) {
        return;
    }

    const auto instructions = function->getInstructions();

    // create eh landing pad code
    Instruction_t *insertPoint = function->getEntryPoint();

    if (insertPoint->getFallthrough() == nullptr) {
        return;
    }

    inserter.setInsertAfter(insertPoint);
    inserter.insertAssembly("jmp 0", insertPoint->getFallthrough());

    // set eh callsite for all instructions
    for (Instruction_t *instruction : instructions) {
        if (instruction->getEhProgram() == nullptr) {
            continue;
        }
        if (instruction->getEhCallSite() != nullptr && instruction->getEhCallSite()->getLandingPad() != nullptr) {
            continue;
        }

        const EhProgramHolder program(instruction->getEhProgram());
        auto it = ehProgramToLandingPad.find(program);

        // TODO: test if registers are restored correctly
        Instruction_t *landingPad;
        if (it == ehProgramToLandingPad.end()) {

            // additional offset for stack redzone
            landingPad = inserter.insertAssembly("sub rsp, 0x100");
            inserter.insertAssembly("push rax");
            inserter.insertAssembly("call 0", tsanFunctionExit);
            inserter.insertAssembly("pop rdi");
            inserter.insertAssembly("add rsp, 0x100");
            Instruction_t *unwindCall = inserter.insertAssembly("call 0", unwindResume);
            // never reached, but the call instruction needs a fallthrough
            inserter.insertAssembly("ret");

            auto unwindResumeCallSite = file->addEhCallSite(unwindCall, 255, nullptr);
            unwindResumeCallSite->setHasCleanup(true);

            auto unwindResumeEhProg = file->copyEhProgram(*instruction->getEhProgram());
            if (unwindCall != nullptr) { // dry-run
                unwindCall->setEhProgram(unwindResumeEhProg);
            }

            ehProgramToLandingPad[program] = landingPad;
        } else {
            landingPad = it->second;
        }
//        std::cout <<"call site: "<<disassembly(instruction)<<std::endl;

        // TODO: clean up excess eh programs
        auto newEhProg = file->copyEhProgram(*instruction->getEhProgram());
        newEhProg->setRelocations({personalityRelocation});
        instruction->setEhProgram(newEhProg);

        auto callSite = file->addEhCallSite(instruction, 255, landingPad);
        callSite->setHasCleanup(true);
    }
}

bool ExceptionHandling::hasEmptyCallSite(Function_t *function) const
{
    const auto instructions = function->getInstructions();
    return std::any_of(instructions.begin(), instructions.end(), [](const auto i) {
        return i->getEhCallSite() == nullptr || i->getEhCallSite()->getLandingPad() == nullptr;
    });
}

IRDB_SDK::Relocation_t *ExceptionHandling::findPersonalityRelocation() const
{
    // in a normal binary, the cxx personality should be unique, so just find the first reference to it
    for (auto instruction : file->getInstructions()) {
        if (instruction->getEhCallSite() != nullptr && instruction->getEhProgram() != nullptr) {
           return *instruction->getEhProgram()->getRelocations().begin();
        }
    }
    return nullptr;
}

Instruction_t *ExceptionHandling::findUnwindResume() const
{
    const auto functions = file->getFunctions();
    auto it = std::find_if(functions.begin(), functions.end(), [](const auto f) {
        return f->getName() == "_Unwind_Resumepart1@plt";
    });
    return it != functions.end() ? (*it)->getEntryPoint() : nullptr;
}
