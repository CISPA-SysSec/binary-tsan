#ifndef CONTROLFLOWGRAPH_H
#define CONTROLFLOWGRAPH_H

#include <irdb-core>
#include <unordered_map>

#include "instruction.h"

class BasicBlock
{
public:
    BasicBlock(const std::vector<Instruction*> &instructions) :
        instructions(instructions)
    { }

    void setPredecessors(const std::vector<BasicBlock*> &pred) { predecessors = pred; }
    const std::vector<BasicBlock*> getPredecessors() const { return predecessors; }

    void setSuccessors(const std::vector<BasicBlock*> &succ) { successors = succ; }
    const std::vector<BasicBlock*> getSuccessors() const { return successors; }

    const std::vector<Instruction*>& getInstructions() const { return instructions; }

private:
    std::vector<Instruction*> instructions;
    std::vector<BasicBlock*> predecessors;
    std::vector<BasicBlock*> successors;
};

class ControlFlowGraph
{
public:
    ControlFlowGraph(IRDB_SDK::Function_t *function, const std::unordered_map<IRDB_SDK::Instruction_t*, Instruction*> &instructionMap);

    const std::vector<BasicBlock> &getBlocks() const { return blocks; }

private:
    std::vector<BasicBlock> blocks;
};

#endif // CONTROLFLOWGRAPH_H
