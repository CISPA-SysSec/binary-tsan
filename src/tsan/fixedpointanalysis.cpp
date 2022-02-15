#include "fixedpointanalysis.h"

#include <irdb-cfg>
#include <numeric>

using namespace IRDB_SDK;

bool FixedPointAnalysis::canHandle(IRDB_SDK::Function_t *function)
{
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isBranch() && !decoded->isCall() && decoded->hasOperand(0)) {
            if (decoded->getOperand(0)->isRegister()) { // || decoded->getOperand(0)->isMemory()
                return false;
            }
        }
    }
    return true;
}

template<typename BackwardsInstructionAnalysis, typename BackwardsAnalysisCommon>
struct BackwardsInstructionInfo {
    BackwardsInstructionInfo(Instruction_t *instruction, const BackwardsAnalysisCommon &common) :
        data(instruction, common)
    { }

    std::vector<int> predecessors;
    BackwardsInstructionAnalysis data;
};

template<typename BackwardsInstructionAnalysis, typename BackwardsAnalysisCommon>
std::map<IRDB_SDK::Instruction_t*, BackwardsInstructionAnalysis> FixedPointAnalysis::runBackwards(Function_t *function)
{
    using InstructionIndex = int;

    const auto &allInstructions = function->getInstructions();
    const BackwardsAnalysisCommon commonData;

    // initialize basic data
    std::vector<BackwardsInstructionInfo<BackwardsInstructionAnalysis, BackwardsAnalysisCommon>> backwardsData;
    backwardsData.reserve(allInstructions.size());
    std::map<Instruction_t*, InstructionIndex> instructionIndexMap;
    for (auto instruction : allInstructions) {
        instructionIndexMap[instruction] = backwardsData.size();
        BackwardsInstructionInfo<BackwardsInstructionAnalysis, BackwardsAnalysisCommon> info(instruction, commonData);
        backwardsData.push_back(info);
    }

    // fill in instruction predecessors
    const auto cfg = ControlFlowGraph_t::factory(function);
    for (const auto block : cfg->getBlocks()) {
        const auto &instructions = block->getInstructions();
        for (std::size_t i = 0;i<instructions.size();i++) {
            auto &info = backwardsData[instructionIndexMap[instructions[i]]];
            if (i == 0) {
                for (const auto pred : block->getPredecessors()) {
                    info.predecessors.push_back(instructionIndexMap[pred->getInstructions().back()]);
                }
            } else {
                info.predecessors.push_back(instructionIndexMap[instructions[i-1]]);
            }
        }
    }

    // update until fixed point is reached
    std::vector<bool> isInserted(allInstructions.size(), true);
    std::vector<InstructionIndex> work(allInstructions.size(), 0);
    std::iota(work.begin(), work.end(), 0);
    while (work.size() > 0) {
        const InstructionIndex current = work.back();
        work.pop_back();
        isInserted[current] = false;

        backwardsData[current].data.updateDataBefore();
        for (InstructionIndex before : backwardsData[current].predecessors) {
            if (backwardsData[before].data.mergeFrom(backwardsData[current].data)) {
                if (!isInserted[before]) {
                    work.push_back(before);
                    isInserted[before] = true;
                }
            }
        }
    }

    std::map<IRDB_SDK::Instruction_t*, BackwardsInstructionAnalysis> result;
    for (const auto &[instruction, index] : instructionIndexMap) {
        result[instruction] = backwardsData[index].data;
    }
    return result;
}


template<typename Analysis>
struct InstructionInfo {
    std::vector<IRDB_SDK::Instruction_t*> predecessors;
    std::vector<IRDB_SDK::Instruction_t*> successors;
    Analysis before;
    Analysis after;
};

template<typename Analysis>
std::map<Instruction_t *, Analysis> FixedPointAnalysis::runForward(Function_t *function, Analysis atFunctionEntry)
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
template std::map<Instruction_t *, PointerAnalysis> FixedPointAnalysis::runForward<PointerAnalysis>(Function_t *function, PointerAnalysis atFunctionEntry);
#include "deadregisteranalysis.h"
template std::map<Instruction_t*, DeadRegisterInstructionAnalysis> FixedPointAnalysis::runBackwards<DeadRegisterInstructionAnalysis, DeadRegisterAnalysisCommon>(Function_t *function);
