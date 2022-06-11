#include "program.h"

Program::Program(IRDB_SDK::FileIR_t *file)
{
    // ensure that the instruction addresses stay stable
    instructions.reserve(file->getInstructions().size());
    instructionIndex.reserve(file->getInstructions().size());

    for (auto instruction : file->getInstructions()) {
        instructionIndex.insert({instruction, instructions.size()});
        instructions.emplace_back(instruction);
    }

    for (auto &instruction : instructions) {
        auto irdbInstruction = instruction.getIRDBInstruction();
        instruction.setTarget(mapInstruction(irdbInstruction->getTarget()));
        instruction.setFallthrough(mapInstruction(irdbInstruction->getFallthrough()));
    }

    functions.reserve(file->getFunctions().size());
    functionIndex.reserve(file->getFunctions().size());

    for (auto function : file->getFunctions()) {
        std::vector<Instruction*> functionInstructions;
        functionInstructions.reserve(function->getInstructions().size());
        for (auto instruction : function->getInstructions()) {
            functionInstructions.push_back(mapInstruction(instruction));
        }
        Instruction *entryPoint = mapInstruction(function->getEntryPoint());
        functions.emplace_back(functionInstructions, entryPoint, function->getName(), function);
    }
}

Instruction *Program::mapInstruction(IRDB_SDK::Instruction_t *instruction)
{
    if (instruction == nullptr) {
        return nullptr;
    }
    return &instructions[instructionIndex[instruction]];
}
