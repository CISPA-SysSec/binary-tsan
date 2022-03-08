#include "cfgtodot.h"

#include <string>

#include "helper.h"

using namespace IRDB_SDK;

static std::string blockName(BasicBlock_t *block)
{
    return "node_" + std::to_string(block->getInstructions()[0]->getAddress()->getVirtualOffset());
}

std::string CFGToDot::createDotFromCFG(const std::unique_ptr<ControlFlowGraph_t> &cfg)
{
    std::set<Instruction_t*> landingPads;
    for (auto block : cfg->getBlocks()) {
        for (auto instruction : block->getInstructions()) {
            if (instruction->getEhCallSite() && instruction->getEhCallSite()->getLandingPad()) {
                landingPads.insert(instruction->getEhCallSite()->getLandingPad());
            }
        }
    }

    std::stringstream result;

    result <<"digraph \"CFG\" {"<<std::endl;
    result <<"size = \"5, 10\";"<<std::endl;
//    result <<"splines = ortho;"<<std::endl;
    result <<"margin=0;"<<std::endl;
    for (const auto block : cfg->getBlocks()) {
        result <<"node [shape = rectangle];"<<std::endl;
        result <<"{"<<std::endl;
        result <<blockName(block)<<" [label = \"";
        for (auto instruction : block->getInstructions()) {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            const std::string assembly = disassembly(instruction);
            // align operands after mnemonic
            const std::string prefix = isAtomic(instruction) ? "lock " : decoded->hasRelevantRepPrefix() ? "rep " : decoded->hasRelevantRepnePrefix() ? "repne " : "";
            std::string mnemonic = prefix + decoded->getMnemonic();
            const std::string operandPart = std::string(assembly.begin() + mnemonic.size(), assembly.end());
            while (mnemonic.size() < 7) {
                mnemonic.push_back(' ');
            }
            const std::string instructionString = mnemonic + operandPart;
            result <<std::hex<<instruction->getAddress()->getVirtualOffset()<<": "<<instructionString<<"\\l";
        }
        // select a monospace font to make alignment work
        result <<"\", fontname = \"DejaVu Sans Mono\"];"<<std::endl;
        result <<"}"<<std::endl;

        if (block->getPredecessors().size() == 0) {
            Instruction_t *instruction = block->getInstructions()[0];
            const bool isLandingPad = landingPads.find(instruction) != landingPads.end();
            const bool isFunctionEntry = cfg->getFunction()->getEntryPoint() == instruction;
            if (isLandingPad || isFunctionEntry) {
                const std::string nodeName = isLandingPad ? "\"landing pad\"" : "\"function entry\"";
                result <<"node [shape = ellipse];"<<std::endl;
                result <<"{ "<<nodeName<<" }"<<std::endl;
                result <<"edge [style = solid];"<<std::endl;
                result <<nodeName<<" -> "<<blockName(block)<<std::endl;
            }
        }
    }
    result <<"edge [style = solid];"<<std::endl;
    for (const auto block : cfg->getBlocks()) {
        for (const auto succ : block->getSuccessors()) {
            const auto decoded = DecodedInstruction_t::factory(block->getInstructions().back());
            std::string color = "darkblue";
            if (decoded->isBranch() && !decoded->isCall()) {
                const auto edgeTypes = cfg->getEdgeType(block, succ);
                const auto it = edgeTypes.find(CFGEdgeTypeEnum::cetFallthroughEdge);
                if (it != edgeTypes.end()) {
                    color = "darkred";
                } else {
                    color = "darkgreen";
                }
            }
            result <<blockName(block)<<" -> "<<blockName(succ)<<" [color = \""<<color<<"\"];"<<std::endl;
        }
    }
    result <<"}"<<std::endl;

    return result.str();
}
