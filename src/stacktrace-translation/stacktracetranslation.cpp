#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>

#include "protobuf/instrumentationmap.pb.h"
#include "simplefile.h"

static bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

static std::vector<std::string> split(const std::string &txt, char ch)
{
    size_t pos = txt.find( ch );
    size_t initialPos = 0;

    std::vector<std::string> result;
    while( pos != std::string::npos ) {
        result.push_back( txt.substr( initialPos, pos - initialPos ) );
        initialPos = pos + 1;
        pos = txt.find( ch, initialPos );
    }
    result.push_back( txt.substr( initialPos, std::min( pos, txt.size() ) - initialPos + 1 ) );
    return result;
}

int main()
{

    std::map<std::string, InstrumentationMap> instrumentation;

    for (std::string line; std::getline(std::cin, line);) {
        const auto parts = split(line, ' ');
        if (parts.size() == 0) {
            continue;
        }
        if (contains(parts[parts.size()-1], "(") && contains(parts[parts.size()-1], "+0x")) {
            std::string origin = parts[parts.size()-1];
            origin.erase(std::remove(origin.begin(), origin.end(), '('), origin.end());
            origin.erase(std::remove(origin.begin(), origin.end(), ')'), origin.end());
            const auto originParts = split(origin, '+');
            if (originParts.size() != 2) {
                continue;
            }
            const std::string sourceObject = originParts[0];
            const uintptr_t addr = std::stoul(originParts[1], nullptr, 16);

            if (instrumentation.find(sourceObject) == instrumentation.end()) {
                const std::string filename = sourceObject + ".instrinfo";
                InstrumentationMap instrumentationMap;
                const bool success = readProtobufFromFile(instrumentationMap, filename);
                if (success) {
                    instrumentation[sourceObject] = instrumentationMap;
                }
            }

            const auto it = instrumentation.find(sourceObject);
            if (it != instrumentation.end()) {
                const auto &instr = it->second.instrumentation();
                const auto addrIt = instr.find(addr);
                if (addrIt != instr.end()) {
                    for (int i = 0;i<int(parts.size())-1;i++) {
                        std::cout <<parts[i]<<" ";
                    }
                    const std::string disassembly = addrIt->second.disassembly();
                    const std::string assemblyStr = disassembly.size() > 0 ? ": " + disassembly : "";
                    std::cout <<"(" << sourceObject << "+0x" << std::hex << addr << " -> originally 0x" << addrIt->second.original_address() << assemblyStr <<")"<<std::endl;

                    if (addrIt->second.has_function_has_entry_exit() && !addrIt->second.function_has_entry_exit()) {
                        std::cout <<"    *** Missing stack trace entry(/ies) ***"<<std::endl;
                    }

                    continue;
                }
            }

        }
        std::cout <<line<<std::endl;
    }
    return 0;
}
