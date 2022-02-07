#include "analysis.h"

#include <algorithm>
#include <irdb-cfg>

#include "pointeranalysis.h"
#include "fixedpointanalysis.h"
#include "helper.h"

using namespace IRDB_SDK;

FunctionInfo Analysis::analyseFunction(Function_t *function)
{
    FunctionInfo result;
    result.inferredStackFrameSize = inferredStackFrameSize(function);

    result.noInstrumentInstructions = detectStackCanaryInstructions(function);

    result.inferredAtomicInstructions = inferAtomicInstructions(function);
    for (auto guardInstruction : detectStaticVariableGuards(function)) {
        result.inferredAtomicInstructions[guardInstruction] = __tsan_memory_order_acquire;
    }

    result.properEntryPoint = function->getEntryPoint();
    if (contains(result.properEntryPoint->getDisassembly(), "endbr")) {
        result.properEntryPoint = result.properEntryPoint->getFallthrough();
    }

    const auto cfg = ControlFlowGraph_t::factory(function);
    for (const auto block : cfg->getBlocks()) {
        if (!block->getIsExitBlock()) {
            continue;
        }
        Instruction_t *instruction = block->getInstructions().back();
        if (!instruction->isFunctionExit()) {
            continue;
        }
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isCall()) {
            continue;
        }
        // is the exit instruction after functions calls that do not return (for example exit)
        if (contains(instruction->getDisassembly(), "nop")) {
            continue;
        }
        // TODO: causes problems in libQt5Core
        const bool isSimpleConstJump = false;//decoded->isUnconditionalBranch() && (decoded->getOperand(0)->isConstant() || decoded->getOperand(0)->isPcrel());
        if (!decoded->isReturn() && !isSimpleConstJump) {
            result.exitPoints.clear();
            break;
        }
        result.exitPoints.push_back(instruction);
    }

    result.addEntryExitInstrumentation = false;
    if (result.exitPoints.size() > 0) {
        // TODO: there might be functions with an important variable location memory read in the jump instruction
        const bool isStub = std::find(result.exitPoints.begin(), result.exitPoints.end(), result.properEntryPoint) != result.exitPoints.end();
        if (!isStub) {
            result.addEntryExitInstrumentation = true;
        }
    }

    result.stackLeavesFunction = doesStackLeaveFunction(function);

    return result;
}

std::map<Instruction_t *, __tsan_memory_order> Analysis::inferAtomicInstructions(IRDB_SDK::Function_t *function) const
{
    const auto instructions = function->getInstructions();
    const bool hasAtomic = std::any_of(instructions.begin(), instructions.end(), isAtomic);
    if (!hasAtomic) {
        return {};
    }

    PointerAnalysis functionEntry = PointerAnalysis::functionEntry();
    auto analysis = FixedPointAnalysis::run<PointerAnalysis>(function, functionEntry);

    std::map<int, std::vector<Instruction_t*>> sameLocation;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getMnemonic() == "nop" || decoded->getMnemonic() == "lea") {
            continue;
        }
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isMemory() && operand->hasBaseRegister() && !operand->hasIndexRegister() && !operand->hasMemoryDisplacement()) {
                const RegisterID reg = strToRegister(operand->getString());
                if (!is64bitRegister(reg)) {
                    continue;
                }
                auto analysisResult = analysis[instruction].getMemoryLocations();
                if (analysisResult.find(reg) != analysisResult.end()) {
                    const int location = analysisResult[reg];
                    sameLocation[location].push_back(instruction);
                }
            }
        }
    }

    std::map<Instruction_t *, __tsan_memory_order> result;

    bool hasPrinted = false;
    for (const auto &[pos, sameLocInstructions] : sameLocation) {
        const std::size_t atomicCount = std::count_if(sameLocInstructions.begin(), sameLocInstructions.end(), isAtomic);
        if (atomicCount == 0 || atomicCount == sameLocInstructions.size()) {
            continue;
        }
        if (!hasPrinted) {
             std::cout <<"Inferred atomics in function "<<function->getName()<<std::endl;
             hasPrinted = true;
        }
        std::cout <<"Same memory location set:"<<std::endl;
        for (auto instruction : sameLocInstructions) {

            if (!isAtomic(instruction)) {
                const auto decoded = DecodedInstruction_t::factory(instruction);
                // TODO: auch xchg??
                if (decoded->getMnemonic() == "mov") {
                    result[instruction] = __tsan_memory_order_relaxed;
//                    std::cout <<"Inferred atomic instruction: "<<instruction->getDisassembly()<<std::endl;
                } else {
                    std::cout <<"WARNING: found non-atomic instruction to atomic like memory: "<<instruction->getDisassembly()<<std::endl;
                }
            }

            const std::string atomicStr = isAtomic(instruction) ? "lock " : "";
            std::cout <<atomicStr<<instruction->getDisassembly()<<std::endl;
        }
        std::cout <<std::endl;
    }
    return result;
}

std::set<Instruction_t*> Analysis::detectStackCanaryInstructions(Function_t *function) const
{
    const std::string CANARY_CHECK = "fs:[0x28]";

    std::set<Instruction_t*> result;

    Instruction_t *canaryStackWrite = nullptr;

    // find the initial read of the canary value and its corresponding write to stack
    Instruction_t *instruction = function->getEntryPoint();
    for (int i = 0;i<20;i++) {
        const std::string assembly = instruction->getDisassembly();
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (contains(assembly, CANARY_CHECK)) {
            if (decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() && decoded->getOperand(0)->isRegister()) {
                Instruction_t *next = instruction->getFallthrough();
                if (next == nullptr) {
                    std::cout <<"ERROR: unexpected instruction termination"<<std::endl;
                    break;
                }
                const auto nextDecoded = DecodedInstruction_t::factory(next);
                if (!nextDecoded->hasOperand(1) || !nextDecoded->getOperand(1)->isRegister() ||
                        decoded->getOperand(0)->getString() != nextDecoded->getOperand(1)->getString()) {
                    std::cout <<"ERROR: could not find canary stack write!"<<std::endl;
                    break;
                }
                canaryStackWrite = next;
            }
            break;
        }
        if (decoded->isReturn()) {
            break;
        }
        instruction = instruction->getFallthrough();
        if (instruction == nullptr) {
            break;
        }
    }

    // find canary read/writes
    if (canaryStackWrite != nullptr) {
//        std::cout <<"Ignore canary instruction: "<<canaryStackWrite->getDisassembly()<<std::endl;
        result.insert(canaryStackWrite);
        const auto decodedWrite = DecodedInstruction_t::factory(canaryStackWrite);

        for (Instruction_t *instruction : function->getInstructions()) {
            const std::string assembly = instruction->getDisassembly();
            const auto decoded = DecodedInstruction_t::factory(instruction);
            const bool isCanaryStackRead = decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() &&
                    decoded->getOperand(1)->getString() == decodedWrite->getOperand(0)->getString();
            if (contains(assembly, CANARY_CHECK) || isCanaryStackRead) {
//                std::cout <<"Ignore canary instruction: "<<assembly<<std::endl;
                result.insert(instruction);
                continue;
            }
        }
    }
    return result;
}

static bool isLeafFunction(const Function_t *function)
{
    const auto instructions = function->getInstructions();
    return std::none_of(instructions.begin(), instructions.end(), [](const Instruction_t *i) {
        const auto decoded = DecodedInstruction_t::factory(i);
        return decoded->isCall();
    });
}

int Analysis::inferredStackFrameSize(const IRDB_SDK::Function_t *function) const
{
    // TODO: if the function does not use the stack at all, return 0 (to avoid moving the stack for the tsan function call)
    if (!isLeafFunction(function)) {
        return 0;
    }
    int rwSize = 0;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getMnemonic() != "mov") {
            continue;
        }
        if (!decoded->hasOperand(0) || !decoded->hasOperand(1)) {
            continue;
        }
        const auto op0 = decoded->getOperand(0);
        const auto op1 = decoded->getOperand(1);
        const auto acc = op0->isMemory() ? op0 : op1;
        if (!acc->isMemory()) {
            continue;
        }
        // TODO: rsp based writes
        const std::string opstr = acc->getString();
        const bool isStackPointer = contains(opstr, "rbp") || contains(opstr, "ebp");
        if (!isStackPointer) {
            continue;
        }
        intptr_t offset = static_cast<intptr_t>(acc->getMemoryDisplacement());
        rwSize = std::max(rwSize, static_cast<int>(-offset) + static_cast<int>(acc->getArgumentSizeInBytes()));
    }
    // sanity check
    if (rwSize > 2000) {
        rwSize = 0;
    }
    // add a large offset to be sure
    return rwSize + 256;
}

bool Analysis::doesStackLeaveFunction(IRDB_SDK::Function_t *function) const
{
    bool rbpHasRsp = false;
    bool rbpUsed = false;
    for (const Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        // TODO: check for read and written operand more clearly
        if (!decoded->hasOperand(1)) {
            continue;
        }
        const std::string disassembly = instruction->getDisassembly();
        if (disassembly == "mov rbp, rsp" || disassembly == "mov ebp, esp") {
            rbpHasRsp = true;
            continue;
        }
        const auto op1 = decoded->getOperand(1);
        const std::string op1String = op1->getString();

        if (decoded->getMnemonic() == "lea") {
            if (contains(op1String, "rsp") || contains(op1String, "esp")) {
                return true;
            }
            if (contains(op1String, "rbp") || contains(op1String, "ebp")) {
                rbpUsed = true;
            }
        }
        if (op1->isRegister()) {
            const std::string reg1 = standard64Bit(op1String);
            if (reg1 == "rsp") {
                return true;
            }
            if (reg1 == "rbp") {
                rbpUsed = true;
            }
        }
    }
    if (rbpUsed && rbpHasRsp) {
        return true;
    }
    return false;
}

std::set<Instruction_t*> Analysis::detectStaticVariableGuards(Function_t *function) const
{
    const auto cfg = ControlFlowGraph_t::factory(function);

    // find locations of all static variable guards
    std::set<std::string> guardLocations;
    for (const auto &block : cfg->getBlocks()) {
        const auto instructions = block->getInstructions();
        if (instructions.size() < 2) {
            continue;
        }
        // check if there is a static guard aquire
        const Instruction_t *last = instructions.back();
        const std::string targetName = targetFunctionName(last);
        // TODO: is the name the same for all compilers/compiler versions?
        if (!contains(targetName, "cxa_guard_acquire")) {
            continue;
        }
        // find location of the guard lock variable
        for (int i = int(instructions.size())-2;i>=0;i--) {
            const Instruction_t *instruction = instructions[i];
            const auto decoded = DecodedInstruction_t::factory(instruction);
            if (!decoded->hasOperand(0) || !decoded->getOperand(0)->isRegister()) {
                continue;
            }
            const std::string writtenRegister = standard64Bit(decoded->getOperand(0)->getString());
            if (writtenRegister != "rdi") {
                continue;
            }
            if (!decoded->hasOperand(1) || !decoded->getOperand(1)->isConstant()) {
                break;
            }
            // TODO: this only works if the getString function is consistent
            // if it is created by disecting the disassembly, this is not the case
            // Therefore, make sure that it is a canonical form
            const std::string guardLocation = decoded->getOperand(1)->getString();
//            std::cout <<"Found static variable guard location: "<<guardLocation<<std::endl;
            guardLocations.insert(guardLocation);
        }
        if (guardLocations.size() == 0) {
            std::cout <<"WARNING: could not find static variable guard location!"<<std::endl;
        }
    }

    // find all read accesses to the guard variables
    std::set<Instruction_t*> result;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getOperands().size() < 2 || !decoded->getOperand(1)->isMemory()) {
            continue;
        }
        const std::string op1Str = decoded->getOperand(1)->getString();
        const bool isGuardLocation = guardLocations.find(op1Str) != guardLocations.end();
        if (isGuardLocation) {
//            std::cout <<"Found static variable guard read: "<<instruction->getDisassembly()<<std::endl;
            result.insert(instruction);
        }
    }
    return result;
}
