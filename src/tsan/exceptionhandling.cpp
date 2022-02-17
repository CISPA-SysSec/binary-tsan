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
{ }

static Instruction_t *findFunctionByName(FileIR_t *file, const std::string &name)
{
    const auto functions = file->getFunctions();
    auto it = std::find_if(functions.begin(), functions.end(), [&name](const auto f) {
        return f->getName() ==name;
    });
    return it != functions.end() ? (*it)->getEntryPoint() : nullptr;
}

void ExceptionHandling::handleFunction(Function_t *function, InstructionInserter &inserter)
{
    std::cout <<function->getName()<<std::endl;

    // TODO: additional check if file has exceptions at all
    if (!hasEmptyCallSite(function)) {
        std::cout <<"Function "<<function->getName()<<" already has an exception callsite!"<<std::endl;
        return;
    }
    // TODO: does this function work??
    if (!function->getUseFramePointer()) {
        std::cout <<"Function "<<function->getName()<<" does not use the frame pointer!"<<std::endl;
        return;
    }
    if (unwindResume == nullptr || personalityRelocation == nullptr) {
        std::cout <<"This binary does not seem to have exceptions"<<std::endl;
        return;
    }

    const auto instructions = function->getInstructions();

    // create eh landing pad code
    Instruction_t *insertPoint = function->getEntryPoint()->getFallthrough();
    inserter.setInsertAfter(insertPoint);
    inserter.insertAssembly("jmp 0", insertPoint->getFallthrough());

    Instruction_t *landingPad = inserter.insertAssembly("sub rsp, 0x110");
    inserter.insertAssembly("push rax");
    inserter.insertAssembly("call 0", tsanFunctionExit);
    auto printTest = findFunctionByName(file, "_Z4testv");
    if (printTest != nullptr) {
        inserter.insertAssembly("call 0", printTest);
    }
    inserter.insertAssembly("pop rdi");
    inserter.insertAssembly("sub rsp, 0x110");
    Instruction_t *unwindCall = inserter.insertAssembly("call 0", unwindResume);
    // never reached, but the call instruction needs a fallthrough
    inserter.insertAssembly("ret");

    auto unwindResumeCallSite = file->addEhCallSite(unwindCall, 255, nullptr);
    unwindResumeCallSite->setHasCleanup(true);

    // cie program: def_cfa: r7 (rsp) ofs 8, cfa_offset 1
    const std::vector<std::string> cieProg = {{0x0c, 0x07, 0x08}, {(char)0x90, 0x01}};

    // fde program: cfa_offset 2, def_cfa: r6 (rbp) ofs 16
    const std::vector<std::string> fdeProg = {{(char)0x86, 0x02}, {0x0c, 0x06, 0x10}};

    // TODO: does this also need a personality relocation?
    // TODO: do not duplicate
    auto unwindResumeEhProg = file->addEhProgram(unwindCall, 1, -8, 16, 8, cieProg, fdeProg);
    unwindCall->setEhProgram(unwindResumeEhProg);

    // set eh callsite for all instructions
    for (Instruction_t *instruction : instructions) {
        if (instruction->getEhProgram() == nullptr) {
            continue;
        }
        if (instruction->getEhCallSite() != nullptr && instruction->getEhCallSite()->getLandingPad() != nullptr) {
            continue;
        }
        std::cout <<"call site: "<<disassembly(instruction)<<std::endl;

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
