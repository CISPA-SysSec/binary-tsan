#include "pointeranalysis.h"

#include "stringhelper.h"
#include "helper.h"

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

PointerAnalysis PointerAnalysis::afterInstruction(const Instruction *instruction) const
{
    // TODO: syscall instruction
    PointerAnalysis result = *this;
    const auto &decoded = instruction->getDecoded();
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
                    result.registerPointers[dest64Bit] = MemoryLocation(static_cast<int64_t>(instruction->getVirtualOffset()), 0);
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
    return {rn_RAX, rn_RBX, rn_RCX, rn_RDX, rn_RSI, rn_RDI, rn_RBP, rn_RSP, rn_R8, rn_R9, rn_R10, rn_R11, rn_R12, rn_R13, rn_R14, rn_R15};
}


StackOffsetAnalysis::StackOffsetAnalysis(IRDB_SDK::Instruction_t *instruction, const StackOffsetAnalysisCommon &common)
{
    if (common.functionEntry == instruction) {
        before.rspOffset.offset = 0;
        before.rspOffset.state = OffsetState::VALUE;
        before.containingStackpointer[X86_REG_RSP] = true;
        updateData();
    }

    const auto decoded = DecodedInstruction_t::factory(instruction);
    const auto mnemonic = decoded->getMnemonic();
    const auto disassembly = instruction->getDisassembly();
    if (disassembly == "mov rbp, rsp") {
        operation = StackOperation(StackOperationType::MOVE_RSP_TO_RBP);
    } else if (disassembly == "mov rsp, rbp") {
        operation = StackOperation(StackOperationType::MOVE_RBP_TO_RSP);
    } else if (startsWith(disassembly, "sub rsp, ") && decoded->getOperand(1)->isConstant()) {
        // TODO: what about negative numbers?
        operation = StackOperation(StackOperationType::OFFSET_RSP, -decoded->getOperand(1)->getConstant());
    } else if (startsWith(disassembly, "add rsp, ") && decoded->getOperand(1)->isConstant()) {
        operation = StackOperation(StackOperationType::OFFSET_RSP, decoded->getOperand(1)->getConstant());
    } else if (mnemonic == "push") {
        operation = StackOperation(StackOperationType::OFFSET_RSP, -8);
    } else if (mnemonic == "pop") {
        operation = StackOperation(StackOperationType::OFFSET_RSP, 8);
    } else if (decoded->isCall()) {
        operation = StackOperation(StackOperationType::FUNCTION_CALL);
    } else {
        for (auto operand : decoded->getOperands()) {
            if (operand->isWritten() && operand->isRegister()) {
                if (operand->getString() == "rsp") {
                    operation = StackOperation(StackOperationType::INVALIDATE_RSP);
                } else if (operand->getString() == "rbp") {
                    operation = StackOperation(StackOperationType::INVALIDATE_RBP);
                }
            }
            // TODO: check for rsp leaks into other registers
            if (operand->isMemory()) {
                // ignore stack access with index for now
                // TODO: stack access with index
                if (operand->hasBaseRegister() && !operand->hasIndexRegister()) {
                    const std::string opStr = operand->getString();
                    const int64_t offset = operand->getMemoryDisplacement();
                    if (startsWith(opStr, "rsp")) {
                        operation = StackOperation(StackOperationType::STACK_ACCESS_RSP, offset);
                    } else if (startsWith(opStr, "rbp")) {
                        operation = StackOperation(StackOperationType::STACK_ACCESS_RBP, offset);
                    }
                }
            }
        }
        // TODO: check if rsp or rbp are read or written in any other way
        // read for the stackoffset, written
    }
    // TODO: lea rsp offsets, do they exist??
    // TODO: pushf, pushfd, pushfq?
    // TODO: even when failing the analysis, the alignment after function calls is known
    // TODO: the offset at return statements is known, backwards analysis is also possible

    // treat the generalized register moves
    // TODO: arguments on the stack??
    if (mnemonic == "mov") {
        const auto op0 = decoded->getOperand(0);
        const auto op1 = decoded->getOperand(1);
        if (op0->isRegister()) {
            const x86_reg to = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(op0->getString()));
            const x86_reg to64 = Register::generalPurposeRegisterTo64Bit(to);
            if (op1->isRegister()) {
                // TODO: better way to convert registers
                const x86_reg from = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(op1->getString()));
                const x86_reg from64 = Register::generalPurposeRegisterTo64Bit(from);
                registerMove = RegisterMove(from64, to64);
            } else {
                registerKill = to64;
            }
        } else if (op0->isMemory() && op1->isRegister()) {
            const x86_reg reg = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(op1->getString()));
            const x86_reg reg64 = Register::generalPurposeRegisterTo64Bit(reg);
            writeToMemory = reg64;
        }
    } else if (mnemonic == "lea") {
        const auto op0 = decoded->getOperand(0);
        const auto op1 = decoded->getOperand(1);
        const x86_reg to = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(op0->getString()));
        const x86_reg to64 = Register::generalPurposeRegisterTo64Bit(to);
        if (op1->hasBaseRegister()) {
            std::string regStr = split(op1->getString(), '+')[0];
            if (regStr.back() == ' ') {
                regStr.pop_back();
            }
            const x86_reg from = Register::registerIDToCapstoneRegister(IRDB_SDK::strToRegister(regStr));
            const x86_reg from64 = Register::generalPurposeRegisterTo64Bit(from);
            registerMove = RegisterMove(from64, to64);
        }
    }
}

void StackOffsetAnalysis::updateData()
{
    after = before;
    switch(operation.operationType) {
    case StackOperationType::OFFSET_RSP:
        after.rspOffset.offset = before.rspOffset.offset + operation.operationOffset;
        break;
    case StackOperationType::MOVE_RSP_TO_RBP:
        after.rbpOffset = before.rspOffset;
        break;
    case StackOperationType::MOVE_RBP_TO_RSP:
        after.rspOffset = before.rbpOffset;
        break;
    case StackOperationType::INVALIDATE_RSP:
        after.rspOffset.state = OffsetState::INVALID;
        break;
    case StackOperationType::INVALIDATE_RBP:
        after.rbpOffset.state = OffsetState::INVALID;
        break;
    case StackOperationType::STACK_ACCESS_RSP:
        if (before.rspOffset.state == OffsetState::VALUE) {
            after.minAccessOffset = std::min(after.minAccessOffset, before.rspOffset.offset + operation.operationOffset);
        }
        break;
    case StackOperationType::STACK_ACCESS_RBP:
        if (before.rbpOffset.state == OffsetState::VALUE) {
            after.minAccessOffset = std::min(after.minAccessOffset, before.rbpOffset.offset + operation.operationOffset);
        }
        break;
    case StackOperationType::FUNCTION_CALL:
    {
        FullRegisterSet nonCallerSave;
        nonCallerSave[X86_REG_RSP] = true;
        nonCallerSave[X86_REG_RBP] = true;
        nonCallerSave[X86_REG_RBX] = true;
        nonCallerSave[X86_REG_R11] = true;
        nonCallerSave[X86_REG_R12] = true;
        nonCallerSave[X86_REG_R13] = true;
        nonCallerSave[X86_REG_R14] = true;
        nonCallerSave[X86_REG_R15] = true;
        if ((before.containingStackpointer & ~nonCallerSave).any()) {
            after.stackLeaked = true;
        }
        break;
    }
    case StackOperationType::NONE:
        break;
    }
    // not perfect, but doing this right would require an additional backwards analysis
    if (after.rspOffset.state == OffsetState::VALUE && before.rspOffset.state == OffsetState::VALUE &&
            before.rspOffset.offset <= after.minAccessOffset && after.rspOffset.offset > after.minAccessOffset) {
        after.minAccessOffset = after.rspOffset.offset;
    }

    if (registerMove) {
        after.containingStackpointer[registerMove->to] = before.containingStackpointer[registerMove->from];
    }
    if (registerKill) {
        after.containingStackpointer[*registerKill] = false;
    }
    if (writeToMemory) {
        if (before.containingStackpointer[*writeToMemory]) {
            after.stackLeaked = true;
        }
    }
}

bool StackOffsetAnalysis::mergeFrom(const StackOffsetAnalysis &predecessor)
{
    bool changed = before.rspOffset.mergeFrom(predecessor.after.rspOffset);
    changed |= before.rbpOffset.mergeFrom(predecessor.after.rbpOffset);
    if (predecessor.after.minAccessOffset < before.minAccessOffset) {
        before.minAccessOffset = predecessor.after.minAccessOffset;
        changed = true;
    }
    if (predecessor.after.stackLeaked && !before.stackLeaked) {
        before.stackLeaked = true;
        changed = true;
    }

    const FullRegisterSet containingBefore = before.containingStackpointer;
    before.containingStackpointer |= predecessor.after.containingStackpointer;
    if (before.containingStackpointer != containingBefore) {
        changed = true;
    }
    return changed;
}

static std::string offsetString(const StackOffset &offset)
{
    switch(offset.state) {
    case OffsetState::INVALID:
        return "invalid";
    case OffsetState::UNKNOWN:
        return "/";
    case OffsetState::VALUE:
        return std::to_string(offset.offset);
    }
}

void StackOffsetAnalysis::print() const
{
    std::cout <<"rsp: "<<offsetString(before.rspOffset)<<"   rbp: "<<offsetString(before.rbpOffset)<<" access: "<<std::dec<<before.minAccessOffset<<std::endl;
}
