#include "cfgtodot.h"

#include <string>

#include "helper.h"

using namespace IRDB_SDK;

static std::size_t blockName(BasicBlock_t *block)
{
    return block->getInstructions()[0]->getAddress()->getVirtualOffset();
}

std::string CFGToDot::createDotFromCFG(const std::unique_ptr<ControlFlowGraph_t> &cfg)
{
    std::stringstream result;

    result <<"digraph \"CFG\" {"<<std::endl;
    result <<"size = \"5, 10\";"<<std::endl;
//    result <<"splines = ortho;"<<std::endl;
    result <<"margin=0;"<<std::endl;
    result <<"node [shape = rectangle];"<<std::endl;
    for (const auto block : cfg->getBlocks()) {
        result <<"{"<<std::endl;
        result <<"\""<<blockName(block)<<"\" [label = \"";
        for (auto instruction : block->getInstructions()) {
            const auto decoded = DecodedInstruction_t::factory(instruction);
            const std::string assembly = disassembly(instruction);
            // align operands after mnemonic
            std::string mnemonic = decoded->getMnemonic();
            while (mnemonic.size() < 8) {
                mnemonic.push_back(' ');
            }
            const std::string instructionString = mnemonic + std::string(assembly.begin() + (decoded->getMnemonic().size() + 1), assembly.end());
            result <<instructionString<<"\\l";
        }
        // select a monospace font to make alignment work
        result <<"\", fontname = \"DejaVu Sans Mono\"];"<<std::endl;
        result <<"}"<<std::endl;
    }
    result <<"edge [style = solid];"<<std::endl;
    for (const auto block : cfg->getBlocks()) {
        for (const auto succ : block->getSuccessors()) {
            const auto decoded = DecodedInstruction_t::factory(block->getInstructions().back());
            std::string color = "darkblue";
            if (decoded->isBranch()) {
                const auto edgeTypes = cfg->getEdgeType(block, succ);
                const auto it = edgeTypes.find(CFGEdgeTypeEnum::cetFallthroughEdge);
                if (it != edgeTypes.end()) {
                    color = "darkred";
                } else {
                    color = "darkgreen";
                }
            }
            result <<"\""<<blockName(block)<<"\" -> \""<<blockName(succ)<<"\" [color = \""<<color<<"\"];"<<std::endl;
        }
    }
    result <<"}"<<std::endl;

    return result.str();
}
