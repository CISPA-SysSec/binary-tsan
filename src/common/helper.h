#ifndef HELPER_H
#define HELPER_H

#include <irdb-core>
#include <irdb-util>
#include <string>
#include <algorithm>

inline bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

inline bool isAtomic(const IRDB_SDK::Instruction_t *instruction)
{
    const auto decoded = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    const std::string dataBits = instruction->getDataBits();
    return std::any_of(dataBits.begin(), dataBits.begin() + decoded->getPrefixCount(), [](char c) {
        return static_cast<unsigned char>(c) == 0xF0;
    });
}

inline std::string standard64Bit(const std::string &reg)
{
    std::string full = IRDB_SDK::registerToString(IRDB_SDK::convertRegisterTo64bit(IRDB_SDK::strToRegister(reg)));
    std::transform(full.begin(), full.end(), full.begin(), ::tolower);
    return full;
}

inline std::string toBytes(IRDB_SDK::RegisterID reg, int bytes)
{
    IRDB_SDK::RegisterID correctBytes;
    if (bytes == 1) {
        correctBytes = convertRegisterTo8bit(reg);
    } else if (bytes == 2) {
        correctBytes = convertRegisterTo16bit(reg);
    } else if (bytes == 4) {
        correctBytes = convertRegisterTo32bit(reg);
    } else if (bytes == 8) {
        correctBytes = convertRegisterTo64bit(reg);
    } else {
        throw std::invalid_argument("Invalid register byte size");
    }
    std::string full = registerToString(correctBytes);
    std::transform(full.begin(), full.end(), full.begin(), ::tolower);
    return full;
}

// returns the name of the function that the instruction calls, or an empty string in all other cases
inline std::string targetFunctionName(const IRDB_SDK::Instruction_t *instruction)
{
    const auto lastDecoded = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    if (!lastDecoded->isCall()) {
        return "";
    }
    if (instruction->getTarget() == nullptr) {
        return "";
    }
    const IRDB_SDK::Function_t *callTarget = instruction->getTarget()->getFunction();
    if (callTarget == nullptr) {
        return "";
    }
    return callTarget->getName();
}

#endif // HELPER_H
