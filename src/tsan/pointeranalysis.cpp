#include "pointeranalysis.h"

using namespace IRDB_SDK;

PointerAnalysis PointerAnalysis::merge(const std::vector<PointerAnalysis> &parts)
{
    PointerAnalysis result;
    for (auto reg : possibleRegisters()) {
        bool hasRegister = false;
        MemoryLocation location = -1;
        for (const PointerAnalysis &p : parts) {
            auto it = p.registerPointers.find(reg);
            if (it != p.registerPointers.end()) {
                if (!hasRegister) {
                    hasRegister = true;
                    location = it->second;
                } else {
                    if (location != it->second) {
                        location = -1;
                    }
                }
            }
        }
        if (hasRegister) {
            result.registerPointers[reg] = location;
        }
    }
    return result;
}

PointerAnalysis PointerAnalysis::afterInstruction(const Instruction_t *instruction) const
{
    PointerAnalysis result = *this;
    const auto decoded = DecodedInstruction_t::factory(instruction);
    if (decoded->getMnemonic() == "mov" && decoded->hasOperand(1) && decoded->getOperand(0)->isRegister() && decoded->getOperand(1)->isRegister()) {
        const RegisterID source = strToRegister(decoded->getOperand(1)->getString());
        const RegisterID destination = strToRegister(decoded->getOperand(0)->getString());
        if (is64bitRegister(destination)) {
            const auto sourceIt = result.registerPointers.find(source);
            if (sourceIt != result.registerPointers.end()) {
                result.registerPointers[destination] = sourceIt->second;
            }
        } else {
            // pointer must always be 64 bit
            const RegisterID dest64Bit = convertRegisterTo64bit(destination);
            result.registerPointers[dest64Bit] = -1;
        }
    } else if (decoded->isCall()) {
        for (const RegisterID callerSave : callerSaveRegisters()) {
            result.registerPointers[callerSave] = -1;
        }
    } else {
        // TODO: implicitly written registers
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isRegister()) {
                const RegisterID destination = strToRegister(operand->getString());
                const RegisterID dest64Bit = convertRegisterTo64bit(destination);
                result.registerPointers[dest64Bit] = -1;
            }
        }
    }
    return result;
}

bool PointerAnalysis::differsFrom(const PointerAnalysis &other) const
{
    return this->registerPointers != other.registerPointers;
}

PointerAnalysis PointerAnalysis::functionEntry()
{
    PointerAnalysis result;
    int counter = 0;
    for (const RegisterID reg : callerSaveRegisters()) {
        result.registerPointers[reg] = counter;
        counter++;
    }
    return result;
}

std::map<IRDB_SDK::RegisterID, MemoryLocation> PointerAnalysis::getMemoryLocations() const
{
    std::map<IRDB_SDK::RegisterID, MemoryLocation> result;
    for (const auto &[registerID, location] : registerPointers) {
        if (location != -1) {
            result[registerID] = location;
        }
    }
    return result;
}

std::vector<IRDB_SDK::RegisterID> PointerAnalysis::callerSaveRegisters()
{
    return {rn_RAX, rn_RCX, rn_RDX, rn_RSI, rn_RDI, rn_R8, rn_R9, rn_R10, rn_R11};
}

std::vector<RegisterID> PointerAnalysis::possibleRegisters()
{
    return {rn_RAX, rn_RBX, rn_RCX, rn_RDX, rn_RSI, rn_RDI, rn_RBP, rn_R8, rn_R9, rn_R10, rn_R11, rn_R12, rn_R13, rn_R14, rn_R15};
}
