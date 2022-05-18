#include "annotations.h"

#include <fstream>
#include <iostream>
#include <algorithm>

#include "stringhelper.h"
#include "register.h"
#include "stringhelper.h"

using namespace IRDB_SDK;

bool Annotations::parseFromFile(FileIR_t *ir, const std::string &filename)
{
    std::ifstream file(filename);
    if (!file) {
        std::cout <<"Could not open annotation file"<<std::endl;
        return false;
    }

    const auto &instructions = ir->getInstructions();

    std::string line;
    const auto &functions = ir->getFunctions();
    while(getline(file, line)) {
        if (line.size() == 0) {
            continue;
        }
        // so that the used annotations are documented in the tsan log
        std::cout <<"Found annotation: "<<line<<std::endl;
        const auto parts = split(line, ' ');

        if (parts.size() == 3) {
            // find function with name
            const std::string functionName = parts[0];
            const std::string afterString = "after:";
            const bool hasAfterPrefix = startsWith(functionName, afterString);
            const std::string strippedName = hasAfterPrefix ? std::string(functionName.begin() + afterString.size(), functionName.end()) : functionName;
            auto functionIt = std::find_if(functions.begin(), functions.end(), [&strippedName] (auto f) {
                // no exact checking because of the possible part1@plt stuff
                return startsWith(f->getName(), strippedName);
            });
            if (functionIt == functions.end()) {
                std::cout <<"Could not find function with name: "<<strippedName<<std::endl;
                return false;
            }

            // parse operation
            const std::string operationString = parts[1];
            HappensBeforeOperation operation;
            if (operationString == "acquire") {
                operation = HappensBeforeOperation::Acquire;
            } else if (operationString == "release") {
                operation = HappensBeforeOperation::Release;
            } else {
                std::cout <<"Could not find operation with name: "<<operationString<<std::endl;
                return false;
            }

            // TODO: check register for correctness
            const std::string reg = parts[2];
            happensBefore[*functionIt].push_back(HappensBeforeAnnotation(*functionIt, operation, reg, !hasAfterPrefix));

        } else if (parts.size() == 2) {

            const std::string instructionAddress = parts[0];
            const unsigned long address = std::stoul(instructionAddress, 0, 16);
            if (!startsWith(instructionAddress, "0x") || address == 0) {
                std::cout <<"Could not parse instruction address: "<<instructionAddress<<std::endl;
                return false;
            }

            const auto instruction = std::find_if(instructions.begin(), instructions.end(), [address](Instruction_t *instruction) {
                return instruction->getAddress()->getVirtualOffset() == address;
            });

            if (instruction == instructions.end()) {
                std::cout <<"Could not find instruction with virtual offset: "<<instructionAddress<<std::endl;
                return false;
            }

            const std::string operationString = parts[1];
            if (operationString == "ignore") {
                ignoreInstructions.insert(*instruction);
            } else if (operationString == "acquire") {
                atomicInstructions[*instruction] = __tsan_memory_order::__tsan_memory_order_acquire;
            } else if (operationString == "release") {
                atomicInstructions[*instruction] = __tsan_memory_order::__tsan_memory_order_release;
            } else if (operationString == "acquire_release") {
                atomicInstructions[*instruction] = __tsan_memory_order::__tsan_memory_order_acq_rel;
            } else {
                std::cout <<"Could not find operation with name: "<<operationString<<std::endl;
                return false;
            }

        } else {
            std::cout <<"Could not parse annotation: "<<line<<std::endl;
            return false;
        }


    }
    return true;
}
