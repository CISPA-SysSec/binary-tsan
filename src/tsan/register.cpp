#include "register.h"

#include <stdexcept>

#include "stringhelper.h"

using namespace IRDB_SDK;

// TODO: use cs_reg_name instead
std::string Register::registerToString(x86_reg reg)
{
    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM31) {
        return "xmm" + std::to_string(reg - X86_REG_XMM0);
    }
    if (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM31) {
        return "ymm" + std::to_string(reg - X86_REG_YMM0);
    }
    if (reg >= X86_REG_ZMM0 && reg <= X86_REG_ZMM31) {
        return "zmm" + std::to_string(reg - X86_REG_ZMM0);
    }
    switch (reg) {
        case X86_REG_AH: return "ah";
        case X86_REG_AL: return "al";
        case X86_REG_AX: return "ax";
        case X86_REG_BH: return "bh";
        case X86_REG_BL: return "bl";
        case X86_REG_BP: return "bp";
        case X86_REG_BPL: return "bpl";
        case X86_REG_BX: return "bx";
        case X86_REG_CH: return "ch";
        case X86_REG_CL: return "cl";
        case X86_REG_CS: return "cs";
        case X86_REG_CX: return "cx";
        case X86_REG_DH: return "dh";
        case X86_REG_DI: return "di";
        case X86_REG_DIL: return "dil";
        case X86_REG_DL: return "dl";
        case X86_REG_DS: return "ds";
        case X86_REG_DX: return "dx";
        case X86_REG_EAX: return "eax";
        case X86_REG_EBP: return "ebp";
        case X86_REG_EBX: return "ebx";
        case X86_REG_ECX: return "ecx";
        case X86_REG_EDI: return "edi";
        case X86_REG_EDX: return "edx";
        case X86_REG_EFLAGS: return "eflags";
        case X86_REG_EIP: return "eip";
        case X86_REG_EIZ: return "eiz";
        case X86_REG_ES: return "es";
        case X86_REG_ESI: return "esi";
        case X86_REG_ESP: return "esp";
        case X86_REG_FS: return "fs";
        case X86_REG_GS: return "gs";
        case X86_REG_IP: return "ip";
        case X86_REG_RAX: return "rax";
        case X86_REG_RBP: return "rbp";
        case X86_REG_RBX: return "rbx";
        case X86_REG_RCX: return "rcx";
        case X86_REG_RDI: return "rdi";
        case X86_REG_RDX: return "rdx";
        case X86_REG_RIP: return "rip";
        case X86_REG_RIZ: return "riz";
        case X86_REG_RSI: return "rsi";
        case X86_REG_RSP: return "rsp";
        case X86_REG_SI: return "si";
        case X86_REG_SIL: return "sil";
        case X86_REG_R8: return "r8";
        case X86_REG_R9: return "r9";
        case X86_REG_R10: return "r10";
        case X86_REG_R11: return "r11";
        case X86_REG_R12: return "r12";
        case X86_REG_R13: return "r13";
        case X86_REG_R14: return "r14";
        case X86_REG_R15: return "r15";
        case X86_REG_R8B: return "r8b";
        case X86_REG_R9B: return "r9b";
        case X86_REG_R10B: return "r10b";
        case X86_REG_R11B: return "r11b";
        case X86_REG_R12B: return "r12b";
        case X86_REG_R13B: return "r13b";
        case X86_REG_R14B: return "r14b";
        case X86_REG_R15B: return "r15b";
        case X86_REG_R8D: return "r8d";
        case X86_REG_R9D: return "r9d";
        case X86_REG_R10D: return "r10d";
        case X86_REG_R11D: return "r11d";
        case X86_REG_R12D: return "r12d";
        case X86_REG_R13D: return "r13d";
        case X86_REG_R14D: return "r14d";
        case X86_REG_R15D: return "r15d";
        case X86_REG_R8W: return "r8w";
        case X86_REG_R9W: return "r9w";
        case X86_REG_R10W: return "r10w";
        case X86_REG_R11W: return "r11w";
        case X86_REG_R12W: return "r12w";
        case X86_REG_R13W: return "r13w";
        case X86_REG_R14W: return "r14w";
        case X86_REG_R15W: return "r15w";
        default: throw std::invalid_argument("Can not convert register to string");
    }
}

x86_reg Register::registerIDToCapstoneRegister(IRDB_SDK::RegisterID reg)
{
    using IRDB_SDK::RegisterID;
    switch (reg) {
        case RegisterID::rn_UNKNOWN: return X86_REG_INVALID;
        case RegisterID::rn_EFLAGS: return X86_REG_EFLAGS;
        case RegisterID::rn_IP: return X86_REG_IP;
        case RegisterID::rn_EAX: return X86_REG_EAX;
        case RegisterID::rn_ECX: return X86_REG_ECX;
        case RegisterID::rn_EDX: return X86_REG_EDX;
        case RegisterID::rn_EBX: return X86_REG_EBX;
        case RegisterID::rn_ESP: return X86_REG_ESP;
        case RegisterID::rn_EBP: return X86_REG_EBP;
        case RegisterID::rn_ESI: return X86_REG_ESI;
        case RegisterID::rn_EDI: return X86_REG_EDI;
        case RegisterID::rn_R8D: return X86_REG_R8D;
        case RegisterID::rn_R9D: return X86_REG_R9D;
        case RegisterID::rn_R10D: return X86_REG_R10D;
        case RegisterID::rn_R11D: return X86_REG_R11D;
        case RegisterID::rn_R12D: return X86_REG_R12D;
        case RegisterID::rn_R13D: return X86_REG_R13D;
        case RegisterID::rn_R14D: return X86_REG_R14D;
        case RegisterID::rn_R15D: return X86_REG_R15D;
        case RegisterID::rn_RAX: return X86_REG_RAX;
        case RegisterID::rn_RCX: return X86_REG_RCX;
        case RegisterID::rn_RDX: return X86_REG_RDX;
        case RegisterID::rn_RBX: return X86_REG_RBX;
        case RegisterID::rn_RSP: return X86_REG_RSP;
        case RegisterID::rn_RBP: return X86_REG_RBP;
        case RegisterID::rn_RSI: return X86_REG_RSI;
        case RegisterID::rn_RDI: return X86_REG_RDI;
        case RegisterID::rn_R8: return X86_REG_R8;
        case RegisterID::rn_R9: return X86_REG_R9;
        case RegisterID::rn_R10: return X86_REG_R10;
        case RegisterID::rn_R11: return X86_REG_R11;
        case RegisterID::rn_R12: return X86_REG_R12;
        case RegisterID::rn_R13: return X86_REG_R13;
        case RegisterID::rn_R14: return X86_REG_R14;
        case RegisterID::rn_R15: return X86_REG_R15;
        case RegisterID::rn_AX: return X86_REG_AX;
        case RegisterID::rn_CX: return X86_REG_CX;
        case RegisterID::rn_DX: return X86_REG_DX;
        case RegisterID::rn_BX: return X86_REG_BX;
        case RegisterID::rn_BP: return X86_REG_BP;
        case RegisterID::rn_SP: return X86_REG_SP;
        case RegisterID::rn_SI: return X86_REG_SI;
        case RegisterID::rn_DI: return X86_REG_DI;
        case RegisterID::rn_R8W: return X86_REG_R8W;
        case RegisterID::rn_R9W: return X86_REG_R9W;
        case RegisterID::rn_R10W: return X86_REG_R10W;
        case RegisterID::rn_R11W: return X86_REG_R11W;
        case RegisterID::rn_R12W: return X86_REG_R12W;
        case RegisterID::rn_R13W: return X86_REG_R13W;
        case RegisterID::rn_R14W: return X86_REG_R14W;
        case RegisterID::rn_R15W: return X86_REG_R15W;
        case RegisterID::rn_AH: return X86_REG_AH;
        case RegisterID::rn_CH: return X86_REG_CH;
        case RegisterID::rn_DH: return X86_REG_DH;
        case RegisterID::rn_BH: return X86_REG_BH;
        case RegisterID::rn_AL: return X86_REG_AL;
        case RegisterID::rn_CL: return X86_REG_CL;
        case RegisterID::rn_DL: return X86_REG_DL;
        case RegisterID::rn_BL: return X86_REG_BL;
        case RegisterID::rn_SIL: return X86_REG_SIL;
        case RegisterID::rn_DIL: return X86_REG_DIL;
        case RegisterID::rn_BPL: return X86_REG_BPL;
        case RegisterID::rn_SPL: return X86_REG_SPL;
        case RegisterID::rn_R8B: return X86_REG_R8B;
        case RegisterID::rn_R9B: return X86_REG_R9B;
        case RegisterID::rn_R10B: return X86_REG_R10B;
        case RegisterID::rn_R11B: return X86_REG_R11B;
        case RegisterID::rn_R12B: return X86_REG_R12B;
        case RegisterID::rn_R13B: return X86_REG_R13B;
        case RegisterID::rn_R14B: return X86_REG_R14B;
        case RegisterID::rn_R15B: return X86_REG_R15B;
        default: throw std::invalid_argument("Could not convert registers");
    }
}

static int getCallerSaveRegisterIndex(x86_reg reg)
{
    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15) {
        return 10 + int(reg - X86_REG_XMM0);
    }
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AH:
    case X86_REG_AL:
        return 0;
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CH:
    case X86_REG_CL:
        return 1;
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DH:
    case X86_REG_DL:
        return 2;
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI:
    case X86_REG_SIL:
        return 3;
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI:
    case X86_REG_DIL:
        return 4;
    case X86_REG_R8:
    case X86_REG_R8D:
    case X86_REG_R8W:
    case X86_REG_R8B:
        return 5;
    case X86_REG_R9:
    case X86_REG_R9D:
    case X86_REG_R9W:
    case X86_REG_R9B:
        return 6;
    case X86_REG_R10:
    case X86_REG_R10D:
    case X86_REG_R10W:
    case X86_REG_R10B:
        return 7;
    case X86_REG_R11:
    case X86_REG_R11D:
    case X86_REG_R11W:
    case X86_REG_R11B:
        return 8;
    case X86_REG_EFLAGS:
        return 9;
    default:
        return -1;
    }
}

x86_reg Register::generalPurposeRegisterTo64Bit(const x86_reg reg)
{
    switch (reg) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AH:
    case X86_REG_AL:
        return X86_REG_RAX;
    case X86_REG_RBX:
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BH:
    case X86_REG_BL:
        return X86_REG_RBX;
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CH:
    case X86_REG_CL:
        return X86_REG_RCX;
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DH:
    case X86_REG_DL:
        return X86_REG_RDX;
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI:
    case X86_REG_SIL:
        return X86_REG_RSI;
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI:
    case X86_REG_DIL:
        return X86_REG_RDI;
    case X86_REG_RBP:
    case X86_REG_EBP:
    case X86_REG_BP:
    case X86_REG_BPL:
        return X86_REG_RBP;
    case X86_REG_RSP:
    case X86_REG_ESP:
    case X86_REG_SP:
    case X86_REG_SPL:
        return X86_REG_RSP;
    case X86_REG_R8:
    case X86_REG_R8D:
    case X86_REG_R8W:
    case X86_REG_R8B:
        return X86_REG_R8;
    case X86_REG_R9:
    case X86_REG_R9D:
    case X86_REG_R9W:
    case X86_REG_R9B:
        return X86_REG_R9;
    case X86_REG_R10:
    case X86_REG_R10D:
    case X86_REG_R10W:
    case X86_REG_R10B:
        return X86_REG_R10;
    case X86_REG_R11:
    case X86_REG_R11D:
    case X86_REG_R11W:
    case X86_REG_R11B:
        return X86_REG_R11;
    case X86_REG_R12:
    case X86_REG_R12D:
    case X86_REG_R12W:
    case X86_REG_R12B:
        return X86_REG_R12;
    case X86_REG_R13:
    case X86_REG_R13D:
    case X86_REG_R13W:
    case X86_REG_R13B:
        return X86_REG_R13;
    case X86_REG_R14:
    case X86_REG_R14D:
    case X86_REG_R14W:
    case X86_REG_R14B:
        return X86_REG_R14;
    case X86_REG_R15:
    case X86_REG_R15D:
    case X86_REG_R15W:
    case X86_REG_R15B:
        return X86_REG_R15;
    default:
        return X86_REG_INVALID;
    }
}

x86_reg Register::getCallerSaveRegisterForIndex(size_t index)
{
    if (index >= 10 && index < 26) {
        return static_cast<x86_reg>(X86_REG_XMM0 + index - 10);
    }
    switch (index) {
    case 0:
        return X86_REG_RAX;
    case 1:
        return X86_REG_RCX;
    case 2:
        return X86_REG_RDX;
    case 3:
        return X86_REG_RSI;
    case 4:
        return X86_REG_RDI;
    case 5:
        return X86_REG_R8;
    case 6:
        return X86_REG_R9;
    case 7:
        return X86_REG_R10;
    case 8:
        return X86_REG_R11;
    case 9:
        return X86_REG_EFLAGS;
    default:
        return X86_REG_INVALID;
    }
}

void Register::setCallerSaveRegister(CallerSaveRegisterSet &registers, x86_reg reg)
{
    int index = getCallerSaveRegisterIndex(reg);
    if (index >= 0) {
        registers[index] = true;
    }
}

bool Register::hasCallerSaveRegister(const CallerSaveRegisterSet &registers, x86_reg reg)
{
    int index = getCallerSaveRegisterIndex(reg);
    if (index >= 0) {
        return registers[index];
    }
    return false;
}

CallerSaveRegisterSet Register::registerSet(const std::vector<x86_reg> &regs)
{
    CallerSaveRegisterSet result;
    for (auto reg : regs) {
        Register::setCallerSaveRegister(result, reg);
    }
    return result;
}

CallerSaveRegisterSet Register::xmmRegisterSet()
{
    CallerSaveRegisterSet result;
    auto baseIndex = getCallerSaveRegisterIndex(X86_REG_XMM0);
    for (int i = 0;i<16;i++) {
        result[baseIndex + i] = true;
    }
    return result;
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
std::vector<x86_reg> Register::getReadRegisters(cs_insn *decoded, bool checkFalseReads)
{
    // TODO: use cs_regs_access instead
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

std::vector<x86_reg> Register::getWrittenRegisters(cs_insn *decoded)
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
