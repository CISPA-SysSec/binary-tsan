#ifndef CONTROLFLOWGRAPH_H
#define CONTROLFLOWGRAPH_H

#include <irdb-core>
#include <irdb-cfg>
#include <unordered_map>

#include "instruction.h"

class Function;

class BasicBlock
{
public:
    BasicBlock(const std::vector<Instruction*> &instructions, bool isExit) :
        instructions(instructions),
        isExit(isExit)
    { }

    void setPredecessors(const std::vector<BasicBlock*> &pred) { predecessors = pred; }
    const std::vector<BasicBlock*> getPredecessors() const { return predecessors; }

    void setSuccessors(const std::vector<BasicBlock*> &succ) { successors = succ; }
    const std::vector<BasicBlock*> getSuccessors() const { return successors; }

    const std::vector<Instruction*>& getInstructions() const { return instructions; }
    bool isExitBlock() const { return isExit; }

private:
    std::vector<Instruction*> instructions;
    std::vector<BasicBlock*> predecessors;
    std::vector<BasicBlock*> successors;

    bool isExit;
};

class ControlFlowGraph
{
public:
    ControlFlowGraph(IRDB_SDK::Function_t *irdbFunction, Function *function,
                     const std::unordered_map<IRDB_SDK::Instruction_t*, Instruction*> &instructionMap);

    const std::vector<BasicBlock> &getBlocks() const { return blocks; }

    Function* getFunction() const { return function; }

    const IRDB_SDK::CFGEdgeType_t &getEdgeType(const BasicBlock *source, const BasicBlock *target) const;

private:
    std::vector<BasicBlock> blocks;
    std::map<std::pair<const BasicBlock*, const BasicBlock*>, IRDB_SDK::CFGEdgeType_t> edges;
    Function *function;
};

#endif // CONTROLFLOWGRAPH_H
