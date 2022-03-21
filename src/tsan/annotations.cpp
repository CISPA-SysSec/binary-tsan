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

    std::string line;
    const auto &functions = ir->getFunctions();
    while(getline(file, line)) {
        if (line.size() == 0) {
            continue;
        }
        // so that the used annotations are documented in the tsan log
        std::cout <<"Found annotation: "<<line<<std::endl;
        const auto parts = split(line, ' ');
        if (parts.size() != 3) {
            std::cout <<"Could not parse annotation: "<<line<<std::endl;
            return false;
        }

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
    }
    return true;
}
