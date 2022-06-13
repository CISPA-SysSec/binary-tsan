#include "deadregisteranalysis.h"
#include "helper.h"

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

static bool isFalseRead(cs_insn *decoded)
{
    // instructions like xor eax, eax do not read eax for practical purposes
    const std::string mnemonic = std::string(decoded->mnemonic);
    const bool isXorOrSbb = mnemonic == "xor" || mnemonic == "sbb" ||
            mnemonic == "pxor" || mnemonic == "xorps" || mnemonic == "xorpd" ||
            mnemonic == "pcmpeqd";
    auto x86 = decoded->detail->x86;
    const bool sameRegisters = x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG && x86.operands[0].reg == x86.operands[1].reg;
    if (isXorOrSbb && sameRegisters) {
        return true;
    }

    const bool isOr = mnemonic == "or";
    const bool isRegImm = x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM;
    const bool isOnes = x86.operands[1].imm == -1 || (x86.operands[1].size == 4 && x86.operands[1].imm == 0xffffffff);
    if (isOr && isRegImm && isOnes) {
        return true;
    }
    return false;
}

// TODO: if sse masks are used, the written operand is also read
static std::vector<x86_reg> getReadRegisters(cs_insn *decoded, bool checkFalseReads)
{
    std::vector<x86_reg> readRegisters;
    readRegisters.reserve(decoded->detail->regs_read_count + 1);
    const bool isRepInstruction = startsWith(decoded->mnemonic, "rep ") || startsWith(decoded->mnemonic, "repe ") || startsWith(decoded->mnemonic, "repne ");
    for (int i = 0;i<decoded->detail->regs_read_count;i++) {
        const x86_reg reg = (x86_reg)decoded->detail->regs_read[i];
        // the rep instructions are classified as reading the eflags register,
        // but they do not depend on the values of the eflags before the instruction
        if (reg != X86_REG_EFLAGS || !isRepInstruction) {
            readRegisters.push_back(reg);
        }
    }
    // instructions like xor rax, rax do not read their explicit operands for practical purposes
    if (checkFalseReads && isFalseRead(decoded)) {
        return readRegisters;
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
    writtenRegisters.reserve(decoded->detail->regs_write_count + 1);
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
    // add registers that are missing in the capstone list
    if (decoded->mnemonic == std::string("lock cmpxchg") || decoded->mnemonic == std::string("cmpxchg")) {
        writtenRegisters.push_back(X86_REG_EFLAGS);
    }
    return writtenRegisters;
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
    for (x86_reg reg : getWrittenRegisters(decoded)) {
        setBits(writtenRegs, reg);
    }
    for (x86_reg reg : getReadRegisters(decoded, true)) {
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
            auto targetIt = common.functionWrittenRegisters.find(instruction->getTargetFunction());
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

    // initially consider all registers dead
    before.set();
    after.set();

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

// TODO: am anfang der funktion sind register die nicht für argumente da sind undefiniert (aufpassen mit EH handlern)
UndefinedRegisterInstructionAnalysis::UndefinedRegisterInstructionAnalysis(Instruction *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getIRDBInstruction()->getDataBits();
    cs_insn *decoded = nullptr;
    const int count = cs_disasm(common.capstoneHandle.handle, (uint8_t*)instructionData.data(), instructionData.size(), 0, 1, &decoded);
    if (count == 0) {
        std::cout <<"ERROR: no disassembly!"<<std::endl;
        return;
    }
    for (x86_reg reg : getWrittenRegisters(decoded)) {
        Register::setCallerSaveRegister(makeDefined, reg);
    }
    for (x86_reg reg : getReadRegisters(decoded, true)) {
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
