#include "deadregisteranalysis.h"
#include "helper.h"
#include "function.h"

#include <algorithm>

using namespace IRDB_SDK;

static const std::vector<x86_reg> callerSaveRegisters = {
    X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI,
    X86_REG_RDI, X86_REG_R8, X86_REG_R9, X86_REG_R10,
    X86_REG_R11, X86_REG_EFLAGS, X86_REG_XMM0, X86_REG_XMM1,
    X86_REG_XMM2, X86_REG_XMM3, X86_REG_XMM4, X86_REG_XMM5,
    X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, X86_REG_XMM9,
    X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13,
    X86_REG_XMM14, X86_REG_XMM15
};

static bool isPartOfGroup(const cs_insn *instruction, const x86_insn_group group)
{
    const auto it = std::find(std::begin(instruction->detail->groups), std::end(instruction->detail->groups), group);
    return it != std::end(instruction->detail->groups);
}

DeadRegisterInstructionAnalysis::DeadRegisterInstructionAnalysis(Instruction *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getIRDBInstruction()->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle.handle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (x86_reg reg : instruction->getWrittenRegisters()) {
        setBits(writtenRegs, reg);
    }
    for (x86_reg reg : instruction->getReadRegisters()) {
        setBits(readRegs, reg);
    }

    // special cases for the assumed calling convention
    if (isPartOfGroup(decoded, X86_GRP_RET)) {
        setBits(readRegs, X86_REG_RAX);
        setBits(readRegs, X86_REG_RDX);
        setBits(readRegs, X86_REG_XMM0);
        setBits(readRegs, X86_REG_XMM1);
    }
    // tail call optimization leads to jumps to other functions, these have be treated like calls since the arguments are in the registers
    const bool isJump = isPartOfGroup(decoded, X86_GRP_JUMP);

    // indirect jump
    if (isJump && instruction->getTarget() == nullptr) {
        readRegs.set();
    }

    const bool jumpToOtherFunction = decoded->mnemonic == std::string("jmp") && getJumpInfo(instruction->getIRDBInstruction()).isTailCall;
    if (isPartOfGroup(decoded, X86_GRP_CALL) || jumpToOtherFunction) {
        setBits(readRegs, X86_REG_RDI);
        setBits(readRegs, X86_REG_RSI);
        setBits(readRegs, X86_REG_RDX);
        setBits(readRegs, X86_REG_RCX);
        setBits(readRegs, X86_REG_R8);
        setBits(readRegs, X86_REG_R9);
        setBits(readRegs, X86_REG_R10);
        for (int i = 0;i<8;i++) {
            setBits(readRegs, static_cast<x86_reg>(X86_REG_XMM0 + i));
        }

        if (instruction->getTarget() != nullptr) {
            const auto targetFunction = instruction->getTargetFunction();
            // if the jump is not to the entrypoint, the calling convention does not apply
            if (targetFunction == nullptr || instruction->getTarget() != targetFunction->getEntryPoint()) {
                readRegs.set();
            }
            auto targetIt = common.functionWrittenRegisters.find(targetFunction);
            if (targetIt != common.functionWrittenRegisters.end()) {
                for (auto reg : callerSaveRegisters) {
                    // TODO: what if only a subregister is written?
                    if (Register::hasCallerSaveRegister(targetIt->second, reg)) {
                        setBits(writtenRegs, reg);
                    }
                }
            }
        } else {
            writtenRegs.set();
        }

        // TODO: handle known common functions like stack_chk_fail
    }
    // for the syscall instruction (while it does not read and write all registers, this is safe enough)
    if (isPartOfGroup(decoded, X86_GRP_INT)) {
        readRegs.set();
        // TODO: determine which registers are definitely written
    }
    // TODO: jumps that leave the function

    cs_free(decoded, 1);

    // initially consider all registers alive
    before.reset();
    after.reset();

    auto ownFunctionIt = common.functionWrittenRegisters.find(instruction->getFunction());
    if (ownFunctionIt != common.functionWrittenRegisters.end()) {
        writtenInFunction = ownFunctionIt->second;
    }
}

void DeadRegisterInstructionAnalysis::setBits(std::bitset<47> &bitset, x86_reg reg)
{
    const auto bits = registerBitIndices(reg);
    for (int bit : bits) {
        bitset[bit] = true;
    }
}

static const std::map<x86_reg, std::vector<int>> indexMap = {
    {X86_REG_RAX, {0, 1, 2, 3}}, {X86_REG_EAX, {0, 1, 2, 3}}, {X86_REG_AX, {1, 2, 3}}, {X86_REG_AH, {2}}, {X86_REG_AL, {3}},
    {X86_REG_RCX, {4, 5, 6, 7}}, {X86_REG_ECX, {4, 5, 6, 7}}, {X86_REG_CX, {5, 6, 7}}, {X86_REG_CH, {6}}, {X86_REG_CL, {7}},
    {X86_REG_RDX, {8, 9, 10, 11}}, {X86_REG_EDX, {8, 9, 10, 11}}, {X86_REG_DX, {9, 10, 11}}, {X86_REG_DH, {10}}, {X86_REG_DL, {11}},
    {X86_REG_RSI, {12, 13, 14}}, {X86_REG_ESI, {12, 13, 14}}, {X86_REG_SI, {13, 14}}, {X86_REG_SIL, {14}},
    {X86_REG_RDI, {15, 16, 17}}, {X86_REG_EDI, {15, 16, 17}}, {X86_REG_DI, {16, 17}}, {X86_REG_DIL, {17}},
    {X86_REG_R8, {18, 19, 20}}, {X86_REG_R8D, {18, 19, 20}}, {X86_REG_R8W, {19, 20}}, {X86_REG_R8B, {20}},
    {X86_REG_R9, {21, 22, 23}}, {X86_REG_R9D, {21, 22, 23}}, {X86_REG_R9W, {22, 23}}, {X86_REG_R9B, {23}},
    {X86_REG_R10, {24, 25, 26}}, {X86_REG_R10D, {24, 25, 26}}, {X86_REG_R10W, {25, 26}}, {X86_REG_R10B, {26}},
    {X86_REG_R11, {27, 28, 29}}, {X86_REG_R11D, {27, 28, 29}}, {X86_REG_R11W, {28, 29}}, {X86_REG_R11B, {29}},
    {X86_REG_EFLAGS, {30}},
    {X86_REG_XMM0, {31}}, {X86_REG_XMM1, {32}}, {X86_REG_XMM2, {33}}, {X86_REG_XMM3, {34}}, {X86_REG_XMM4, {35}},
    {X86_REG_XMM5, {36}}, {X86_REG_XMM6, {37}}, {X86_REG_XMM7, {38}}, {X86_REG_XMM8, {39}}, {X86_REG_XMM9, {40}},
    {X86_REG_XMM10, {41}}, {X86_REG_XMM11, {42}}, {X86_REG_XMM12, {43}}, {X86_REG_XMM13, {44}}, {X86_REG_XMM14, {45}},
    {X86_REG_XMM15, {46}},
};

std::vector<int> DeadRegisterInstructionAnalysis::registerBitIndices(x86_reg reg)
{
    auto it = indexMap.find(reg);
    if (it != indexMap.end()) {
        return it->second;
    }
    return {};
}

CallerSaveRegisterSet DeadRegisterInstructionAnalysis::getDeadRegisters() const
{
    CallerSaveRegisterSet result;
    for (const auto capstoneReg : callerSaveRegisters) {
        // all subregisters must be dead for the whole register to count as dead
        bool isDead = true;
        for (int bit : registerBitIndices(capstoneReg)) {
            isDead &= before[bit];
        }
        if (isDead) {
            Register::setCallerSaveRegister(result, capstoneReg);
        }
    }
    // only registers written in the function can be dead
    return result & writtenInFunction;
}

// TODO: at the beginning of the function, registers are undefined, if they are not used for arguments. (watch out with eh handlers)
UndefinedRegisterInstructionAnalysis::UndefinedRegisterInstructionAnalysis(Instruction *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getIRDBInstruction()->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle.handle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (x86_reg reg : instruction->getWrittenRegisters()) {
        Register::setCallerSaveRegister(makeDefined, reg);
    }
    for (x86_reg reg : instruction->getReadRegisters()) {
        Register::setCallerSaveRegister(readRegs, reg);
    }

    if (isPartOfGroup(decoded, X86_GRP_CALL)) {
        // all caller save registers and flags are undefined after a function call
        if (instruction->getTarget() != nullptr) {
            auto targetIt = common.functionWrittenRegisters.find(instruction->getTargetFunction());
            if (targetIt != common.functionWrittenRegisters.end()) {
                makeUndefined = targetIt->second;
            }
        } else {
            makeUndefined.set();
        }

        Register::setCallerSaveRegister(makeDefined, X86_REG_RAX);
        Register::setCallerSaveRegister(makeDefined, X86_REG_RDX);
        Register::setCallerSaveRegister(makeDefined, X86_REG_XMM0);
        Register::setCallerSaveRegister(makeDefined, X86_REG_XMM1);
    }
    // for the syscall instruction (while it does not define all registers, this is safer)
    if (isPartOfGroup(decoded, X86_GRP_INT)) {
        makeDefined.set();
    }

    cs_free(decoded, 1);
}

CallerSaveRegisterSet UndefinedRegisterInstructionAnalysis::getDeadRegisters() const
{
    return undefinedBefore;
}
