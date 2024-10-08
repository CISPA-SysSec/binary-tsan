#ifndef HELPER_H
#define HELPER_H

#include <irdb-core>
#include <irdb-util>
#include <string>
#include <algorithm>

#include "stringhelper.h"

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

struct JumpInfo
{
    JumpInfo(bool canLeave, bool canStay, bool tailCall) :
        canLeaveFunction(canLeave),
        canStayInFunction(canStay),
        isTailCall(tailCall)
    { }

    bool canLeaveFunction;
    bool canStayInFunction;
    bool isTailCall;
};

// may only be called for jump instructions (not calls)
inline JumpInfo getJumpInfo(const IRDB_SDK::Instruction_t *instruction)
{
    const IRDB_SDK::Function_t *function = instruction->getFunction();
    if (instruction->getTarget() && instruction->getTarget()->getFunction() != function) {
        // TODO: sanity check: instruction does not have a fallthrough
        return JumpInfo(true, false, true);
    }
    const auto icfs = instruction->getIBTargets();
    // TODO: check conditional or unconditional branch
    if (icfs) {
        const auto leaving = find_if(icfs->begin(), icfs->end(), [function](IRDB_SDK::Instruction_t *target) {
            return target->getFunction() != function;
        });
        const auto staying = find_if(icfs->begin(), icfs->end(), [function](IRDB_SDK::Instruction_t *target) {
            return target->getFunction() == function;
        });

        const bool mightLeave = leaving != icfs->end();
        const bool mightStay = staying != icfs->end();

        return JumpInfo(mightLeave, mightStay, !mightStay);
    }
    // TODO: what to do here?
    return JumpInfo(true, true, false);
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

inline std::string disassembly(const IRDB_SDK::Instruction_t *instruction)
{
    const auto decoded = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    if (decoded->isCall()) {
        const std::string target = targetFunctionName(instruction);
        // indirect calls do not have a target name
        if (target.size() > 0) {
            return "call " + target;
        }
    }
    const std::string prefix = isAtomic(instruction) ? "lock " : decoded->hasRelevantRepPrefix() ? "rep " : decoded->hasRelevantRepnePrefix() ? "repne " : "";
    return prefix + instruction->getDisassembly();
}

#endif // HELPER_H
