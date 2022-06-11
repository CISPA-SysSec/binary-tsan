#include "controlflowgraph.h"

#include <irdb-cfg>

using namespace IRDB_SDK;

ControlFlowGraph::ControlFlowGraph(Function_t *function, const std::unordered_map<IRDB_SDK::Instruction_t*, Instruction*> &instructionMap)
{
    // for now this directly translates the IRDB CFG to a custom CFG without changes
    const auto cfg = ControlFlowGraph_t::factory(function);

    std::map<IRDB_SDK::BasicBlock_t*, int> blockIndices;

    blocks.reserve(cfg->getBlocks().size());
    for (const auto block : cfg->getBlocks()) {
        std::vector<Instruction*> instructions;
        instructions.reserve(block->getInstructions().size());
        for (auto instruction : block->getInstructions()) {
            instructions.push_back(instructionMap.find(instruction)->second);
        }
        blockIndices[block] = blocks.size();
        blocks.emplace_back(instructions);
    }

    for (const auto block : cfg->getBlocks()) {
        std::vector<BasicBlock*> predecessors;
        predecessors.reserve(block->getPredecessors().size());
        for (const auto pred : block->getPredecessors()) {
            predecessors.push_back(&blocks[blockIndices[pred]]);
        }
        std::vector<BasicBlock*> successors;
        successors.reserve(block->getSuccessors().size());
        for (const auto succ : block->getSuccessors()) {
            predecessors.push_back(&blocks[blockIndices[succ]]);
        }
    }
}
