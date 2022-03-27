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
    const bool isXorOrSbb = std::string(decoded->mnemonic) == "xor" || std::string(decoded->mnemonic) == "sbb" ||
            std::string(decoded->mnemonic) == "pxor" || std::string(decoded->mnemonic) == "xorps" ||
            std::string(decoded->mnemonic) == "xorpd";
    auto x86 = decoded->detail->x86;
    const bool sameRegisters = x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG && x86.operands[0].reg == x86.operands[1].reg;
    if (isXorOrSbb && sameRegisters) {
        return true;
    }

    // TODO: less than 64 bit operand size
    const bool isOr = std::string(decoded->mnemonic) == "or";
    const bool allOnes = x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM && x86.operands[1].imm == -1;
    if (isOr && allOnes) {
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

DeadRegisterInstructionAnalysis::DeadRegisterInstructionAnalysis(Instruction_t *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getDataBits();
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
    const bool jumpToOtherFunction = isJump && getJumpInfo(instruction).isTailCall;

    // indirect jump
    if (isJump && instruction->getTarget() == nullptr) {
        readRegs.set();
    }

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
            auto targetIt = common.functionWrittenRegisters.find(instruction->getTarget()->getFunction());
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

void DeadRegisterInstructionAnalysis::setBits(std::bitset<56> &bitset, x86_reg reg)
{
    const auto bits = registerBitIndices(reg);
    for (int bit : bits) {
        bitset[bit] = true;
    }
}

static const std::map<x86_reg, std::vector<int>> indexMap = {
    {X86_REG_RAX, {0, 1, 2, 3, 4}}, {X86_REG_EAX, {1, 2, 3, 4}}, {X86_REG_AX, {2, 3, 4}}, {X86_REG_AH, {3}}, {X86_REG_AL, {4}},
    {X86_REG_RCX, {5, 6, 7, 8, 9}}, {X86_REG_ECX, {6, 7, 8, 9}}, {X86_REG_CX, {7, 8, 9}}, {X86_REG_CH, {8}}, {X86_REG_CL, {9}},
    {X86_REG_RDX, {10, 11, 12, 13, 14}}, {X86_REG_EDX, {11, 12, 13, 14}}, {X86_REG_DX, {12, 13, 14}}, {X86_REG_DH, {13}}, {X86_REG_DL, {14}},
    {X86_REG_RSI, {15, 16, 17, 18}}, {X86_REG_ESI, {16, 17, 18}}, {X86_REG_SI, {17, 18}}, {X86_REG_SIL, {18}},
    {X86_REG_RDI, {19, 20, 21, 22}}, {X86_REG_EDI, {20, 21, 22}}, {X86_REG_DI, {21, 22}}, {X86_REG_DIL, {22}},
    {X86_REG_R8, {23, 24, 25, 26}}, {X86_REG_R8D, {24, 25, 26}}, {X86_REG_R8W, {25, 26}}, {X86_REG_R8B, {26}},
    {X86_REG_R9, {27, 28, 29, 30}}, {X86_REG_R9D, {28, 29, 30}}, {X86_REG_R9W, {29, 30}}, {X86_REG_R9B, {30}},
    {X86_REG_R10, {31, 32, 33, 34}}, {X86_REG_R10D, {32, 33, 34}}, {X86_REG_R10W, {33, 34}}, {X86_REG_R10B, {34}},
    {X86_REG_R11, {35, 36, 37, 38}}, {X86_REG_R11D, {36, 37, 38}}, {X86_REG_R11W, {37, 38}}, {X86_REG_R11B, {38}},
    {X86_REG_EFLAGS, {39}},
    {X86_REG_XMM0, {40}}, {X86_REG_XMM1, {41}}, {X86_REG_XMM2, {42}}, {X86_REG_XMM3, {43}}, {X86_REG_XMM4, {44}},
    {X86_REG_XMM5, {45}}, {X86_REG_XMM6, {46}}, {X86_REG_XMM7, {47}}, {X86_REG_XMM8, {48}}, {X86_REG_XMM9, {49}},
    {X86_REG_XMM10, {50}}, {X86_REG_XMM11, {51}}, {X86_REG_XMM12, {52}}, {X86_REG_XMM13, {53}}, {X86_REG_XMM14, {54}},
    {X86_REG_XMM15, {55}},
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
UndefinedRegisterInstructionAnalysis::UndefinedRegisterInstructionAnalysis(Instruction_t *instruction, const RegisterAnalysisCommon &common)
{
    const std::string instructionData = instruction->getDataBits();
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
            auto targetIt = common.functionWrittenRegisters.find(instruction->getTarget()->getFunction());
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
