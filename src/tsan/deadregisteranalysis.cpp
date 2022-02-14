#include "deadregisteranalysis.h"

#include <algorithm>

using namespace IRDB_SDK;

static bool isPartOfGroup(const cs_insn *instruction, const x86_insn_group group)
{
    const auto it = std::find(std::begin(instruction->detail->groups), std::end(instruction->detail->groups), group);
    return it != std::end(instruction->detail->groups);
}

DeadRegisterInstructionAnalysis::DeadRegisterInstructionAnalysis(Instruction_t *instruction, const DeadRegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (int i = 0;i<decoded->detail->regs_write_count;i++) {
        const x86_reg reg = (x86_reg)decoded->detail->regs_write[i];
        const int regIndex = registerBitIndex(reg);
        writtenRegs[regIndex] = true;
    }
    for (int i = 0;i<decoded->detail->regs_read_count;i++) {
        const x86_reg reg = (x86_reg)decoded->detail->regs_read[i];
        const int regIndex = registerBitIndex(reg);
        readRegs[regIndex] = true;
    }
    auto x86 = decoded->detail->x86;
    for (int i = 0;i<x86.op_count;i++) {
        const auto &op = x86.operands[i];
        if (op.type == X86_OP_REG) {
            // TODO: special cases in zipr
            if (op.access & CS_AC_READ) {
                readRegs[registerBitIndex(op.reg)] = true;
            }
            if (op.access & CS_AC_WRITE) {
                writtenRegs[registerBitIndex(op.reg)] = true;
            }
        } else if (op.type == X86_OP_MEM) {
            readRegs[registerBitIndex(op.mem.base)] = true;
            readRegs[registerBitIndex(op.mem.index)] = true;
        }
    }

    // TODO: the instruction xor rax, rax does not actually read rax (quite common)

    // special cases for the assumed calling convention
    if (isPartOfGroup(decoded, X86_GRP_RET)) {
        readRegs[registerBitIndex(X86_REG_RAX)] = true;
    }
    if (isPartOfGroup(decoded, X86_GRP_CALL)) {
        readRegs[registerBitIndex(X86_REG_RDI)] = true;
        readRegs[registerBitIndex(X86_REG_RSI)] = true;
        readRegs[registerBitIndex(X86_REG_RDX)] = true;
        readRegs[registerBitIndex(X86_REG_RCX)] = true;
        readRegs[registerBitIndex(X86_REG_R8)] = true;
        readRegs[registerBitIndex(X86_REG_R9)] = true;

        // all caller save registers and flags are dirtied
        writtenRegs.set();
    }
    // TODO: jumps that leave the function
    // TODO: syscalls

    cs_free(decoded, 1);

    // reduce necessary iterations
    writtenRegs[UNUSED_REG] = false;
    readRegs[UNUSED_REG] = false;

    // initially consider all registers dead
    before.set();
    after.set();
}

int DeadRegisterInstructionAnalysis::registerBitIndex(x86_reg reg)
{

    std::map<x86_reg, int> indexMap = {
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
    return UNUSED_REG;
}

std::set<IRDB_SDK::RegisterID> DeadRegisterInstructionAnalysis::getDeadRegisters() const
{
    std::set<IRDB_SDK::RegisterID> result;
    if (before[0]) result.insert(RegisterID::rn_RAX);
    if (before[1]) result.insert(RegisterID::rn_RCX);
    if (before[2]) result.insert(RegisterID::rn_RDX);
    if (before[3]) result.insert(RegisterID::rn_RSI);
    if (before[4]) result.insert(RegisterID::rn_RDI);
    if (before[5]) result.insert(RegisterID::rn_R8);
    if (before[6]) result.insert(RegisterID::rn_R9);
    if (before[7]) result.insert(RegisterID::rn_R10);
    if (before[8]) result.insert(RegisterID::rn_R11);
    if (before[9]) result.insert(RegisterID::rn_EFLAGS);
    return result;
}

void DeadRegisterInstructionAnalysis::printResult() const
{
    for (int i = 0;i<10;i++) {
        if (before[i]) {
            switch (i) {
            case 0: std::cout <<"rax"; break;
            case 1: std::cout <<"rcx"; break;
            case 2: std::cout <<"rdx"; break;
            case 3: std::cout <<"rsi"; break;
            case 4: std::cout <<"rdi"; break;
            case 5: std::cout <<"r8"; break;
            case 6: std::cout <<"r9"; break;
            case 7: std::cout <<"r10"; break;
            case 8: std::cout <<"r11"; break;
            case 9: std::cout <<"eflags"; break;
            }
            std::cout <<", ";
        }
    }
    std::cout <<std::endl;
}
