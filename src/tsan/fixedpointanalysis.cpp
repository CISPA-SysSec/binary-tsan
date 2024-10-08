#include "fixedpointanalysis.h"

#include <irdb-cfg>
#include <numeric>

#include "helper.h"

using namespace IRDB_SDK;

std::pair<bool, bool> FixedPointAnalysis::canHandle(const Function &function)
{
    bool hasRegisterJump = false;
    for (Instruction *instruction : function.getInstructions()) {
        const auto &decoded = instruction->getDecoded();
        if (decoded->isBranch() && !decoded->isCall() && decoded->hasOperand(0)) {
            if (decoded->getOperand(0)->isRegister()) {
                hasRegisterJump = true;
            }
            if (decoded->getOperand(0)->isMemory() && !decoded->getOperand(0)->isPcrel()) {
                return {false, false};
            }
            if (instruction->getIRDBInstruction()->getRelocations().size() > 0) {
                // this usually only happens for push jump thunks
                // the analysis does not work here, but there is also no need
                return {false, false};
            }
        }
    }
    return {true, !hasRegisterJump};
}

template<typename InstructionAnalysis, typename AnalysisCommon>
struct InstructionInfo {
    InstructionInfo(Instruction *instruction, const AnalysisCommon &common) :
        data(instruction, common)
    { }

    // predecessors when going backwards, successors when going forward
    std::vector<int> nextInstructions;
    InstructionAnalysis data;
};

// TODO: deal with exit node -> entry node loop and nop blocks
template<typename InstructionAnalysis, typename AnalysisCommon>
std::map<Instruction *, InstructionAnalysis> FixedPointAnalysis::runAnalysis(const ControlFlowGraph &cfg,
        const std::set<std::pair<const BasicBlock *, const BasicBlock *> > &removeEdges,
        const AnalysisCommon &commonData)
{
    using InstructionIndex = int;

    const auto &allInstructions = cfg.getFunction()->getInstructions();

    // initialize basic data
    std::vector<InstructionInfo<InstructionAnalysis, AnalysisCommon>> instructionData;
    instructionData.reserve(allInstructions.size());
    std::map<Instruction*, InstructionIndex> instructionIndexMap;
    for (auto instruction : allInstructions) {
        instructionIndexMap[instruction] = instructionData.size();
        InstructionInfo<InstructionAnalysis, AnalysisCommon> info(instruction, commonData);
        instructionData.push_back(info);
    }

    // fill in instruction predecessors
    for (const auto &block : cfg.getBlocks()) {
        const auto &instructions = block.getInstructions();
        for (std::size_t i = 0;i<instructions.size();i++) {
            auto &info = instructionData[instructionIndexMap[instructions[i]]];
            if (InstructionAnalysis::isForwardAnalysis()) {
                if (i == instructions.size()-1) {
                    for (const auto succ : block.getSuccessors()) {
                        if (removeEdges.find({&block, succ}) == removeEdges.end()) {
                            info.nextInstructions.push_back(instructionIndexMap[succ->getInstructions()[0]]);
                        }
                    }
                } else {
                    info.nextInstructions.push_back(instructionIndexMap[instructions[i+1]]);
                }
            } else {
                if (i == 0) {
                    for (const auto pred : block.getPredecessors()) {
                        if (removeEdges.find({pred, &block}) == removeEdges.end()) {
                            Instruction *prevInstruction = pred->getInstructions().back();
                            info.nextInstructions.push_back(instructionIndexMap[prevInstruction]);
                        }
                    }
                } else {
                    info.nextInstructions.push_back(instructionIndexMap[instructions[i-1]]);
                }
            }
        }
    }
    // TODO: als pointer origin können auch returnregister bei funktionsaufrufen in frage kommen

    // update until fixed point is reached
    std::vector<bool> isInserted(allInstructions.size(), true);
    std::vector<InstructionIndex> work(allInstructions.size(), 0);
    std::iota(work.begin(), work.end(), 0);
    while (work.size() > 0) {
        const InstructionIndex current = work.back();
        work.pop_back();
        isInserted[current] = false;

        instructionData[current].data.updateData();
        for (InstructionIndex beforeOrAfter : instructionData[current].nextInstructions) {
            if (instructionData[beforeOrAfter].data.mergeFrom(instructionData[current].data)) {
                if (!isInserted[beforeOrAfter]) {
                    work.push_back(beforeOrAfter);
                    isInserted[beforeOrAfter] = true;
                }
            }
        }
    }

    std::map<Instruction*, InstructionAnalysis> result;
    for (const auto &[instruction, index] : instructionIndexMap) {
        result[instruction] = instructionData[index].data;
    }
    return result;
}


template<typename Analysis>
struct SimpleInstructionInfo {
    std::vector<Instruction*> predecessors;
    std::vector<Instruction*> successors;
    Analysis before;
    Analysis after;
};

// TODO: get rid of this inefficient analysis and replace it with the one above
// TODO: this does not work with exceptions
template<typename Analysis>
std::map<Instruction*, Analysis> FixedPointAnalysis::runForward(const Function &function, Analysis atFunctionEntry)
{
    std::map<Instruction*, SimpleInstructionInfo<Analysis>> instructionData;
    for (const auto &block : function.getCFG().getBlocks()) {
        const auto &instructions = block.getInstructions();
        for (std::size_t i = 0;i<instructions.size();i++) {
            SimpleInstructionInfo<Analysis> info;
            if (i == 0) {
                for (const auto pred : block.getPredecessors()) {
                    info.predecessors.push_back(pred->getInstructions().back());
                }
            } else {
                info.predecessors.push_back(instructions[i-1]);
            }
            if (i == instructions.size()-1) {
                for (const auto succ : block.getSuccessors()) {
                    info.successors.push_back(succ->getInstructions()[0]);
                }
            } else {
                info.successors.push_back(instructions[i+1]);
            }
            instructionData[instructions[i]] = info;
        }
    }

    auto entry = function.getEntryPoint();

    std::set<Instruction*> work;
    work.insert(function.getInstructions().begin(), function.getInstructions().end());
    while (work.size() > 0) {
        Instruction *instruction = *work.begin();
        work.erase(work.begin());

        SimpleInstructionInfo<Analysis> &info = instructionData[instruction];

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

    std::map<Instruction*, Analysis> result;
    for (const auto &[instruction, info] : instructionData) {
        result[instruction] = info.before;
    }
    return result;
}

// explicit instantiation since the template function is in a cpp file
#include "pointeranalysis.h"
template std::map<Instruction*, PointerAnalysis> FixedPointAnalysis::runForward<PointerAnalysis>(const Function &function, PointerAnalysis atFunctionEntry);
#include "deadregisteranalysis.h"
template std::map<Instruction*, DeadRegisterInstructionAnalysis> FixedPointAnalysis::runAnalysis<DeadRegisterInstructionAnalysis, RegisterAnalysisCommon>(const ControlFlowGraph &function, const std::set<std::pair<const BasicBlock*, const BasicBlock*>> &noReturnFunctions, const RegisterAnalysisCommon&);
template std::map<Instruction*, UndefinedRegisterInstructionAnalysis> FixedPointAnalysis::runAnalysis<UndefinedRegisterInstructionAnalysis, RegisterAnalysisCommon>(const ControlFlowGraph &function, const std::set<std::pair<const BasicBlock*, const BasicBlock*>> &noReturnFunctions, const RegisterAnalysisCommon&);
template std::map<Instruction*, StackOffsetAnalysis> FixedPointAnalysis::runAnalysis<StackOffsetAnalysis, StackOffsetAnalysisCommon>(const ControlFlowGraph &function, const std::set<std::pair<const BasicBlock*, const BasicBlock*>> &noReturnFunctions, const StackOffsetAnalysisCommon&);
