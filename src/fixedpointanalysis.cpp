#include "fixedpointanalysis.h"

#include <irdb-cfg>

using namespace IRDB_SDK;

template<typename Analysis>
struct InstructionInfo {
    std::vector<IRDB_SDK::Instruction_t*> predecessors;
    std::vector<IRDB_SDK::Instruction_t*> successors;
    Analysis before;
    Analysis after;
};

template<typename Analysis>
std::map<Instruction_t *, Analysis> FixedPointAnalysis::run(Function_t *function, Analysis atFunctionEntry)
{
    std::map<Instruction_t*, InstructionInfo<Analysis>> instructionData;
    const auto cfg = ControlFlowGraph_t::factory(function);
    for (const auto block : cfg->getBlocks()) {
        const auto &instructions = block->getInstructions();
        for (std::size_t i = 0;i<instructions.size();i++) {
            InstructionInfo<Analysis> info;
            if (i == 0) {
                for (const auto pred : block->getPredecessors()) {
                    info.predecessors.push_back(pred->getInstructions().back());
                }
            } else {
                info.predecessors.push_back(instructions[i-1]);
            }
            if (i == instructions.size()-1) {
                for (const auto pred : block->getSuccessors()) {
                    info.successors.push_back(pred->getInstructions()[0]);
                }
            } else {
                info.successors.push_back(instructions[i+1]);
            }
            instructionData[instructions[i]] = info;
        }
    }

    auto entry = function->getEntryPoint();

    std::set<Instruction_t*> work;
    work.insert(function->getInstructions().begin(), function->getInstructions().end());
    while (work.size() > 0) {
        Instruction_t *instruction = *work.begin();
        work.erase(work.begin());

        InstructionInfo<Analysis> &info = instructionData[instruction];

        std::vector<Analysis> partsBefore;
        partsBefore.reserve(info.predecessors.size());
        for (const auto pred : info.predecessors) {
            partsBefore.push_back(instructionData[pred].after);
        }
        if (instruction == entry) {
            partsBefore.push_back(atFunctionEntry);
        }
        info.before = Analysis::merge(partsBefore);

        Analysis afterMod = info.before.afterInstruction(instruction);
        if (afterMod.differsFrom(info.after)) {
            info.after = afterMod;
            for (auto succ : info.successors) {
                work.insert(succ);
            }
        }
    }

    std::map<Instruction_t *, Analysis> result;
    for (const auto &[instruction, info] : instructionData) {
        result[instruction] = info.before;
    }
    return result;
}

// explicit instantiation since the template function is in a cpp file
#include "pointeranalysis.h"
template std::map<Instruction_t *, PointerAnalysis> FixedPointAnalysis::run<PointerAnalysis>(Function_t *function, PointerAnalysis atFunctionEntry);
