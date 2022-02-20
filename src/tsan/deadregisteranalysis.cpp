#include "deadregisteranalysis.h"
#include "helper.h"

#include <algorithm>

using namespace IRDB_SDK;

static const std::map<x86_reg, RegisterID> capstoneRegToRegisterID = {
    {X86_REG_RAX, RegisterID::rn_RAX},
    {X86_REG_RCX, RegisterID::rn_RCX},
    {X86_REG_RDX, RegisterID::rn_RDX},
    {X86_REG_RSI, RegisterID::rn_RSI},
    {X86_REG_RDI, RegisterID::rn_RDI},
    {X86_REG_R8, RegisterID::rn_R8},
    {X86_REG_R9, RegisterID::rn_R9},
    {X86_REG_R10, RegisterID::rn_R10},
    {X86_REG_R11, RegisterID::rn_R11},
    {X86_REG_EFLAGS, RegisterID::rn_EFLAGS}
};

static bool isPartOfGroup(const cs_insn *instruction, const x86_insn_group group)
{
    const auto it = std::find(std::begin(instruction->detail->groups), std::end(instruction->detail->groups), group);
    return it != std::end(instruction->detail->groups);
}

static std::vector<x86_reg> getReadRegisters(cs_insn *decoded)
{
    std::vector<x86_reg> readRegisters;
    for (int i = 0;i<decoded->detail->regs_read_count;i++) {
        const x86_reg reg = (x86_reg)decoded->detail->regs_read[i];
        readRegisters.push_back(reg);
    }
    auto x86 = decoded->detail->x86;
    for (int i = 0;i<x86.op_count;i++) {
        const auto &op = x86.operands[i];
        if (op.type == X86_OP_REG) {
            // TODO: special cases in zipr
            if (op.access & CS_AC_READ) {
                readRegisters.push_back(op.reg);
            }
        } else if (op.type == X86_OP_MEM) {
            readRegisters.push_back(op.mem.base);
            readRegisters.push_back(op.mem.index);
        }
    }
    return readRegisters;
}

static std::vector<x86_reg> getWrittenRegisters(cs_insn *decoded)
{
    std::vector<x86_reg> writtenRegisters;
    for (int i = 0;i<decoded->detail->regs_write_count;i++) {
        const x86_reg reg = (x86_reg)decoded->detail->regs_write[i];
        writtenRegisters.push_back(reg);
    }
    auto x86 = decoded->detail->x86;
    for (int i = 0;i<x86.op_count;i++) {
        const auto &op = x86.operands[i];
        if (op.type == X86_OP_REG) {
            if (op.access & CS_AC_WRITE) {
                writtenRegisters.push_back(op.reg);
            }
        }
    }
    return writtenRegisters;
}

// TODO: false read: or r8d, 0xffffffff
static bool isFalseRead(cs_insn *decoded)
{
    // instructions like xor eax, eax do not read eax for practical purposes
    const bool isXor = std::string(decoded->mnemonic) == "xor";
    auto x86 = decoded->detail->x86;
    const bool sameRegisters = x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG && x86.operands[0].reg == x86.operands[1].reg;
    if (isXor && sameRegisters) {
        return true;
    }
    return false;
}

DeadRegisterInstructionAnalysis::DeadRegisterInstructionAnalysis(Instruction_t *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (x86_reg reg : getWrittenRegisters(decoded)) {
        setBits(writtenRegs, reg);
    }
    for (x86_reg reg : getReadRegisters(decoded)) {
        setBits(readRegs, reg);
    }
    // handle special cases that do not read the register for practical purposes (for example xor eax, eax)
    if (isFalseRead(decoded)) {
        readRegs.reset();
    }

    // special cases for the assumed calling convention
    if (isPartOfGroup(decoded, X86_GRP_RET)) {
        setBits(readRegs, X86_REG_RAX);
    }
    // tail call optimization leads to jumps to other functions, these have be treated like calls since the arguments are in the registers
    const bool isJump = isPartOfGroup(decoded, X86_GRP_JUMP);
    const bool jumpToOtherFunction = isJump && getJumpInfo(instruction).isTailCall;

    if (isPartOfGroup(decoded, X86_GRP_CALL) || jumpToOtherFunction) {
        setBits(readRegs, X86_REG_RDI);
        setBits(readRegs, X86_REG_RSI);
        setBits(readRegs, X86_REG_RDX);
        setBits(readRegs, X86_REG_RCX);
        setBits(readRegs, X86_REG_R8);
        setBits(readRegs, X86_REG_R9);

        // all caller save registers and flags are dirtied
        writtenRegs.set();

        // TODO: handle known common functions like stack_chk_fail
    }
    // TODO: jumps that leave the function
    // TODO: syscalls

    cs_free(decoded, 1);

    // initially consider all registers dead
    before.set();
    after.set();
}

void DeadRegisterInstructionAnalysis::setBits(std::bitset<40> &bitset, x86_reg reg)
{
    const auto bits = registerBitIndices(reg);
    for (int bit : bits) {
        bitset[bit] = true;
    }
}

std::vector<int> DeadRegisterInstructionAnalysis::registerBitIndices(x86_reg reg)
{
    const std::map<x86_reg, std::vector<int>> indexMap = {
        {X86_REG_RAX, {0, 1, 2, 3, 4}}, {X86_REG_EAX, {1, 2, 3, 4}}, {X86_REG_AX, {2, 3, 4}}, {X86_REG_AH, {3}}, {X86_REG_AL, {4}},
        {X86_REG_RCX, {5, 6, 7, 8, 9}}, {X86_REG_ECX, {6, 7, 8, 9}}, {X86_REG_CX, {7, 8, 9}}, {X86_REG_CH, {8}}, {X86_REG_CL, {9}},
        {X86_REG_RDX, {10, 11, 12, 13, 14}}, {X86_REG_EDX, {11, 12, 13, 14}}, {X86_REG_DX, {12, 13, 14}}, {X86_REG_DH, {13}}, {X86_REG_DL, {14}},
        {X86_REG_RSI, {15, 16, 17, 18}}, {X86_REG_ESI, {16, 17, 18}}, {X86_REG_SI, {17, 18}}, {X86_REG_SIL, {18}},
        {X86_REG_RDI, {19, 20, 21, 22}}, {X86_REG_EDI, {20, 21, 22}}, {X86_REG_DI, {21, 22}}, {X86_REG_DIL, {22}},
        {X86_REG_R8, {23, 24, 25, 26}}, {X86_REG_R8D, {24, 25, 26}}, {X86_REG_R8W, {25, 26}}, {X86_REG_R8B, {26}},
        {X86_REG_R9, {27, 28, 29, 30}}, {X86_REG_R9D, {28, 29, 30}}, {X86_REG_R9W, {29, 30}}, {X86_REG_R9B, {30}},
        {X86_REG_R10, {31, 32, 33, 34}}, {X86_REG_R10D, {32, 33, 34}}, {X86_REG_R10W, {33, 34}}, {X86_REG_R10B, {34}},
        {X86_REG_R11, {35, 36, 37, 38}}, {X86_REG_R11D, {36, 37, 38}}, {X86_REG_R11W, {37, 38}}, {X86_REG_R11B, {38}},
        {X86_REG_EFLAGS, {39}}
    };

    auto it = indexMap.find(reg);
    if (it != indexMap.end()) {
        return it->second;
    }
    return {};
}

std::set<IRDB_SDK::RegisterID> DeadRegisterInstructionAnalysis::getDeadRegisters() const
{
    std::set<IRDB_SDK::RegisterID> result;
    for (const auto &[capstoneReg, regId] : capstoneRegToRegisterID) {
        // all subregisters must be dead for the whole register to count as dead
        bool isDead = true;
        for (int bit : registerBitIndices(capstoneReg)) {
            isDead &= before[bit];
        }
        if (isDead) {
            result.insert(regId);
        }
    }
    return result;
}


UndefinedRegisterInstructionAnalysis::UndefinedRegisterInstructionAnalysis(Instruction_t *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (x86_reg reg : getWrittenRegisters(decoded)) {
        makeDefined[registerBitIndex(reg)] = true;
    }
    for (x86_reg reg : getReadRegisters(decoded)) {
        readRegs[registerBitIndex(reg)] = true;
    }
    if (isFalseRead(decoded)) {
        readRegs.reset();
    }

    if (isPartOfGroup(decoded, X86_GRP_CALL)) {
        // all caller save registers and flags are undefined after a function call
        makeUndefined.set();
        makeDefined[registerBitIndex(X86_REG_RAX)] = true;
    }

    cs_free(decoded, 1);

    // initially consider all registers defined (important for function arguments)
    undefinedBefore.reset();
    undefinedAfter.reset();
}

int UndefinedRegisterInstructionAnalysis::registerBitIndex(x86_reg reg)
{
    const std::map<x86_reg, int> indexMap = {
        {X86_REG_RAX, 0}, {X86_REG_EAX, 0}, {X86_REG_AX, 0}, {X86_REG_AH, 0}, {X86_REG_AL, 0},
        {X86_REG_RCX, 1}, {X86_REG_ECX, 1}, {X86_REG_CX, 1}, {X86_REG_CH, 1}, {X86_REG_CL, 1},
        {X86_REG_RDX, 2}, {X86_REG_EDX, 2}, {X86_REG_DX, 2}, {X86_REG_DH, 2}, {X86_REG_DL, 2},
        {X86_REG_RSI, 3}, {X86_REG_ESI, 3}, {X86_REG_SI, 3}, {X86_REG_SIL, 3},
        {X86_REG_RDI, 4}, {X86_REG_EDI, 4}, {X86_REG_DI, 4}, {X86_REG_DIL, 4},
        {X86_REG_R8, 5}, {X86_REG_R8D, 5}, {X86_REG_R8W, 5}, {X86_REG_R8B, 5},
        {X86_REG_R9, 6}, {X86_REG_R9D, 6}, {X86_REG_R9W, 6}, {X86_REG_R9B, 6},
        {X86_REG_R10, 7}, {X86_REG_R10D, 7}, {X86_REG_R10W, 7}, {X86_REG_R10B, 7},
        {X86_REG_R11, 8}, {X86_REG_R11D, 8}, {X86_REG_R11W, 8}, {X86_REG_R11B, 8},
        {X86_REG_EFLAGS, 9}
    };

    auto it = indexMap.find(reg);
    if (it != indexMap.end()) {
        return it->second;
    }
    return {};
}

std::set<IRDB_SDK::RegisterID> UndefinedRegisterInstructionAnalysis::getDeadRegisters() const
{
    std::set<IRDB_SDK::RegisterID> result;
    for (const auto &[capstoneReg, regId] : capstoneRegToRegisterID) {
        if (undefinedBefore[registerBitIndex(capstoneReg)]) {
            result.insert(regId);
        }
    }
    return result;
}
