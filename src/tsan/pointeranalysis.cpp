#include "pointeranalysis.h"

using namespace IRDB_SDK;

PointerAnalysis PointerAnalysis::merge(const std::vector<PointerAnalysis> &parts)
{
    PointerAnalysis result;
    for (auto reg : possibleRegisters()) {
        bool hasRegister = false;
        MemoryLocation location = MemoryLocation::invalid();
        for (const PointerAnalysis &p : parts) {
            auto it = p.registerPointers.find(reg);
            if (it != p.registerPointers.end()) {
                if (!hasRegister) {
                    hasRegister = true;
                    location = it->second;
                } else {
                    if (location != it->second) {
                        location = MemoryLocation::invalid();
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
    // TODO: syscall instruction
    PointerAnalysis result = *this;
    const auto decoded = DecodedInstruction_t::factory(instruction);
    const std::string mnemonic = decoded->getMnemonic();
    if (mnemonic == "mov" && decoded->hasOperand(1) && decoded->getOperand(0)->isRegister() && decoded->getOperand(1)->isRegister()) {
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
            result.registerPointers[dest64Bit] = MemoryLocation::invalid();
        }
    } else if (mnemonic == "lea" && decoded->getOperand(0)->getArgumentSizeInBytes() == 8) {
        const auto op1 = decoded->getOperand(1);
        const RegisterID destination = strToRegister(decoded->getOperand(0)->getString());
        if (op1->hasBaseRegister() && !op1->hasIndexRegister()) {
            const std::string op1Str = op1->getString();
            const RegisterID source = strToRegister(std::string(op1Str.begin(), op1Str.begin() + 3));
            const auto sourceIt = result.registerPointers.find(source);
            if (sourceIt != result.registerPointers.end() && sourceIt->second.isValid) {
                MemoryLocation target = sourceIt->second;
                if (op1->hasMemoryDisplacement()) {
                    target.offset += op1->getMemoryDisplacement();
                }
                result.registerPointers[destination] = target;
            } else {
                result.registerPointers[destination] = MemoryLocation::invalid();
            }
        } else {
            result.registerPointers[destination] = MemoryLocation::invalid();
        }
    } else if (mnemonic == "add" && decoded->getOperand(0)->getArgumentSizeInBytes() == 8 &&
               decoded->getOperand(0)->isRegister() && decoded->getOperand(1)->isConstant()) {
        const RegisterID destination = strToRegister(decoded->getOperand(0)->getString());
        const auto sourceIt = result.registerPointers.find(destination);
        if (sourceIt != result.registerPointers.end() && sourceIt->second.isValid) {
            // TODO: negative number encoding?
            sourceIt->second.offset += decoded->getOperand(1)->getConstant();
        } else {
            result.registerPointers[destination] = MemoryLocation::invalid();
        }
    } else if (decoded->isCall()) {
        for (const RegisterID callerSave : callerSaveRegisters()) {
            result.registerPointers[callerSave] = MemoryLocation::invalid();
        }
    } else {
        // TODO: implicitly written registers
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isRegister()) {
                const RegisterID destination = strToRegister(operand->getString());
                const RegisterID dest64Bit = convertRegisterTo64bit(destination);
                if (operand->getArgumentSizeInBytes() == 8) {
                    result.registerPointers[dest64Bit] = MemoryLocation(static_cast<int64_t>(instruction->getAddress()->getVirtualOffset()), 0);
                } else {
                    result.registerPointers[dest64Bit] = MemoryLocation::invalid();
                }
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
        result.registerPointers[reg] = MemoryLocation(counter, 0);
        counter++;
    }
    return result;
}

std::map<IRDB_SDK::RegisterID, MemoryLocation> PointerAnalysis::getMemoryLocations() const
{
    std::map<IRDB_SDK::RegisterID, MemoryLocation> result;
    for (const auto &[registerID, location] : registerPointers) {
        if (location.isValid) {
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
