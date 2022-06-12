#include "controlflowgraph.h"

#include <irdb-cfg>

using namespace IRDB_SDK;

ControlFlowGraph::ControlFlowGraph(Function_t *irdbFunction, Function *function,
                                   const std::unordered_map<IRDB_SDK::Instruction_t*, Instruction*> &instructionMap) :
    function(function)
{
    // for now this directly translates the IRDB CFG to a custom CFG without changes
    const auto cfg = ControlFlowGraph_t::factory(irdbFunction);

    std::map<IRDB_SDK::BasicBlock_t*, int> blockIndices;

    blocks.reserve(cfg->getBlocks().size());
    for (const auto block : cfg->getBlocks()) {
        std::vector<Instruction*> instructions;
        instructions.reserve(block->getInstructions().size());
        for (auto instruction : block->getInstructions()) {
            instructions.push_back(instructionMap.find(instruction)->second);
        }
        blockIndices[block] = blocks.size();
        blocks.emplace_back(instructions, block->getIsExitBlock());
    }

    for (const auto block : cfg->getBlocks()) {
        const auto blockIndex = blockIndices[block];
        std::vector<BasicBlock*> predecessors;
        predecessors.reserve(block->getPredecessors().size());
        for (const auto pred : block->getPredecessors()) {
            predecessors.push_back(&blocks[blockIndices[pred]]);
        }
        blocks[blockIndex].setPredecessors(predecessors);

        std::vector<BasicBlock*> successors;
        successors.reserve(block->getSuccessors().size());
        for (const auto succ : block->getSuccessors()) {
            const auto successorIndex = blockIndices[succ];
            successors.push_back(&blocks[successorIndex]);

            const auto &edgeType = cfg->getEdgeType(block, succ);
            edges.insert({{&blocks[blockIndex], &blocks[successorIndex]}, edgeType});
        }
        blocks[blockIndex].setSuccessors(successors);
    }
}

const CFGEdgeType_t &ControlFlowGraph::getEdgeType(const BasicBlock *source, const BasicBlock *target) const
{
    const auto it = edges.find({source, target});
    if (it == edges.end()) {
        throw std::invalid_argument("No edge is present between the given basic blocks!");
    }
    return it->second;
}
