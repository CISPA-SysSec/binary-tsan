#include "analysis.h"

#include <algorithm>
#include <irdb-cfg>
#include <cxxabi.h>

#include "pointeranalysis.h"
#include "deadregisteranalysis.h"
#include "fixedpointanalysis.h"
#include "helper.h"

using namespace IRDB_SDK;

Analysis::Analysis(FileIR_t *ir) :
    ir(ir)
{ }

void Analysis::init(const Program &program, const Options &options)
{
    noReturnFunctions = findNoReturnFunctions(program);
    computeFunctionRegisterWrites(program);
    computeMaxFunctionArguments(program);

    this->options = options;

    if (options.deadRegisterAnalysisType == DeadRegisterAnalysisType::STARS) {
        const auto registerAnalysis = DeepAnalysis_t::factory(ir);
        auto starsDead = registerAnalysis->getDeadRegisters();
        for (const auto &[instruction, registers] : *starsDead) {
            CallerSaveRegisterSet capstoneRegs;
            for (const auto reg : registers) {
                // also insert the original register (for eflags etc.)
                // TODO: upgrading the register bit width might be a problem if the larger part is not dead
                Register::setCallerSaveRegister(capstoneRegs, Register::registerIDToCapstoneRegister(reg));
                const auto largeReg = convertRegisterTo64bit(reg);
                // TODO: is this even still necessary
                Register::setCallerSaveRegister(capstoneRegs, Register::registerIDToCapstoneRegister(largeReg));
            }
            deadRegisters[instruction] = capstoneRegs;
        }
    }
}

static bool isLeafFunction(const Function &function)
{
    const auto &instructions = function.getInstructions();
    return std::none_of(instructions.begin(), instructions.end(), [](const Instruction *i) {
        // TODO: do tail calls count here?
        return i->isCall();
    });
}

FunctionInfo Analysis::analyseFunction(const Function &function)
{
    updateDeadRegisters(function);

    totalAnalysedFunctions++;
    totalAnalysedInstructions += function.getInstructions().size();

    FunctionInfo result;
    result.isLeafFunction = isLeafFunction(function);

    std::set<Instruction_t*> notInstrumented = detectStackCanaryInstructions(function);
    stackCanaryInstructions += notInstrumented.size();

    const std::set<Instruction_t*> spinLockInstructions = {};//findSpinLocks(cfg.get());

    result.inferredAtomicInstructions = inferAtomicInstructions(function, spinLockInstructions);
    pointerInferredAtomics += result.inferredAtomicInstructions.size();
    for (const auto guardInstruction : detectStaticVariableGuards(function)) {
        result.inferredAtomicInstructions[guardInstruction] = __tsan_memory_order_acquire;
        staticVariableGuards++;
    }
    for (const auto spinLock : spinLockInstructions) {
        result.inferredAtomicInstructions[spinLock] = __tsan_memory_order_acquire;
        spinLocks++;
    }
    for (const auto &[instruction, memOrder] : options.annotations.atomicInstructions) {
        result.inferredAtomicInstructions[instruction] = memOrder;
    }

    // this analysis is fine with missing forward edges, it can always be run
    const StackOffsetAnalysisCommon common(function.getEntryPoint());
    const auto stackOffsetResult = FixedPointAnalysis::runAnalysis<StackOffsetAnalysis, StackOffsetAnalysisCommon>(function.getCFG(), {}, common);
    for (const auto &[instruction, analysis] : stackOffsetResult) {
        if (!analysis.isStackSafe()) {
            result.stackUnsafe.insert(instruction);
        }
    }

    result.properEntryPoint = function.getEntryPoint();
    if (contains(result.properEntryPoint->getDisassembly(), "endbr")) {
        result.properEntryPoint = result.properEntryPoint->getFallthrough();
    }

    bool hasProblem = false;
    for (const auto &block : function.getCFG().getBlocks()) {
        if (!block.isExitBlock()) {
            continue;
        }
        Instruction *instruction = block.getInstructions().back();
        if (!instruction->getIRDBInstruction()->isFunctionExit()) {
            continue;
        }
        if (instruction->isCall()) {
            continue;
        }
        // is the exit instruction after functions calls that do not return (for example exit)
        const std::string assembly = instruction->getDisassembly();
        if (contains(assembly, "nop") || contains(assembly, "ud2")) {
            continue;
        }
        if (!instruction->isReturn()) {
            // TODO: make sure that the jump is to an actual function
            // TODO: make sure that the stack is at the same level as the start of the function
            // TODO: also check dead registers at the start of the called function
            // TODO: check all of the registers and not only the last one?
            const auto dead = getDeadRegisters(instruction->getIRDBInstruction());
            bool mightHaveStackArguments = !Register::hasCallerSaveRegister(dead, X86_REG_R9) || !Register::hasCallerSaveRegister(dead, X86_REG_XMM7);
            if (instruction->getTarget() != nullptr && instruction->getTarget()->getFunction() != nullptr) {
                const auto targetIt = maxFunctionArguments.find(instruction->getIRDBInstruction()->getTarget()->getFunction());
                if (targetIt != maxFunctionArguments.end()) {
                    if (targetIt->second <= 6) {
                        mightHaveStackArguments = false;
                    } else {
                        if (!mightHaveStackArguments) {
                            // it might also be fine since the maxFunctionArguments is an upper limit
                            std::cout <<"Possible Error: disagreeing argument checks: "<<std::hex<<instruction->getVirtualOffset()<<" "<<disassembly(instruction->getIRDBInstruction())<<std::endl;
                        }
                    }
                }
            }
            bool stackCleared = true;
            const auto stackIt = stackOffsetResult.find(instruction->getIRDBInstruction());
            if (stackIt != stackOffsetResult.end()) {
                if (stackIt->second.getRspOffset().state == OffsetState::VALUE && stackIt->second.getRspOffset().offset != 0) {
                    stackCleared = false;
                }
            }
            if (instruction->getMnemonic() == "jmp" && instruction->getDecoded()->getOperand(0)->isConstant() && !mightHaveStackArguments &&
                    instruction->getTarget() != nullptr && stackCleared && instruction->getTarget()->getFunction() != nullptr &&
                    instruction->getTarget()->getFunction()->getEntryPoint() == instruction->getTarget()) {
                // this is fine and can be transformed into a call
//                std::cout <<"Try entry exit: "<<std::hex<<instruction->getAddress()->getVirtualOffset()<<" "<<disassembly(instruction)<<std::endl;
            } else {
//                auto targetName = instruction->getTarget() != nullptr && instruction->getTarget()->getFunction() != nullptr ? instruction->getTarget()->getFunction()->getName() : "";
//                std::cout <<"No exit: "<<std::hex<<instruction->getAddress()->getVirtualOffset()<<" "<<disassembly(instruction)<<" "<<function->getInstructions().size()<<" "<<targetName<<std::endl;
                result.exitPoints.clear();
                hasProblem = true;
                break;
            }
        }
        result.exitPoints.push_back(instruction);
    }

    result.addEntryExitInstrumentation = false;
    if (result.exitPoints.size() > 0) {
        // TODO: there might be functions with an important variable location memory read in the jump instruction
        const bool isStub = std::find(result.exitPoints.begin(), result.exitPoints.end(), result.properEntryPoint) != result.exitPoints.end();
        if (!isStub) {
            result.addEntryExitInstrumentation = true;
            entryExitInstrumentedFunctions++;
        }
    } else if (!hasProblem) {
        result.addEntryExitInstrumentation = true;
        entryExitInstrumentedFunctions++;
    }

    for (Instruction *instruction : function.getInstructions()) {
        if (instruction->isBranch() || instruction->isCall()) {
            continue;
        }
        const std::string mnemonic = instruction->getMnemonic();
        if (mnemonic == "lea" || mnemonic == "nop" || startsWith(mnemonic, "prefetch")) {
            continue;
        }
        if (notInstrumented.find(instruction->getIRDBInstruction()) != notInstrumented.end()) {
            totalNotInstrumented++;
            continue;
        }
        const std::string disassembly = instruction->getDisassembly();
        const bool isStackAccess = contains(disassembly, "rsp") || (contains(disassembly, "rbp") && function.getIRDBFunction()->getUseFramePointer());
        if (!options.instrumentStackAccess && isStackAccess) {
            stackMemory++;
            continue;
        }

        if (options.annotations.ignoreInstructions.find(instruction->getIRDBInstruction()) != options.annotations.ignoreInstructions.end()) {
            totalNotInstrumented++;
            continue;
        }

        const auto stackIt = stackOffsetResult.find(instruction->getIRDBInstruction());
        const bool isStackLeaked = stackIt != stackOffsetResult.end() && stackIt->second.isStackLeaked();

        const DecodedOperandVector_t operands = instruction->getDecoded()->getOperands();
        for (const auto &operand : operands) {
            if (!operand->isMemory()) {
                continue;
            }
            const auto opStr = operand->getString();
            const bool isStackOperand = contains(opStr, "rsp") || (contains(opStr, "rbp") && function.getIRDBFunction()->getUseFramePointer());
            if (!isStackLeaked && isStackOperand) {
                stackLocalVariables++;
                totalNotInstrumented++;
                break;
            }
            if (isDataConstant(ir, instruction, operand)) {
                constantMemoryRead++;
                totalNotInstrumented++;
                break;
            }
            result.instructionsToInstrument.insert(instruction);
            totalInstrumentedInstructions++;
            break;
        }
    }
    return result;
}

void Analysis::computeMaxFunctionArguments(const Program &program)
{
    // some commonly used C functions
    const std::map<std::string, int> knownFunctionArguments = {
        {"__cxa_atexitpart1@plt", 3}, {"strcmppart1@plt", 2}, {"freepart1@plt", 1},
        {"memcpypart1@plt", 3}, {"memsetpart1@plt", 3}, {"mallocpart1@plt", 1},
        {"reallocpart1@plt", 2}, {"callocpart1@plt", 2}, {"putspart1@plt", 1},
        {"fwritepart1@plt", 4}, {"memcmppart1@plt", 3}, {"memmovepart1@plt", 3},
        {"ferrorpart1@plt", 1}, {"fclosepart1@plt", 1}
    };

    // TODO: this only works with the itanium cxx abi
    for (const Function &function : program.getFunctions()) {
        std::string functionName = function.getName();

        auto knownIt = knownFunctionArguments.find(functionName);
        if (knownIt != knownFunctionArguments.end()) {
            maxFunctionArguments[function.getIRDBFunction()] = knownIt->second;
            continue;
        }

        const std::string pltString = "part1@plt";
        if (contains(functionName, pltString)) {
            functionName.erase(functionName.begin() + (functionName.size() - pltString.size()), functionName.end());
        }
        int status = 0;
        // TODO: if compiled with clang on ubuntu, this needs the library libc++abi-dev
        char *demangledStr = abi::__cxa_demangle(functionName.c_str(), NULL, NULL, &status);
        if (status == 0) {
            std::string demangled(demangledStr);
            int maxArgumentCount = 0;
            // the this pointer is not explicit in the output
            if (contains(demangled, "::")) {
                maxArgumentCount++;
            }
            // varargs
            if (contains(demangled, "...")) {
                // no upper limit, but this should be fine
                maxArgumentCount = 100;
            }
            // commas can also be in templates or function types, but this is the upper limit
            // 2 registers for each argument since structures can be directly passed in up to 2 registers
            // TODO: for pointers, primitive types, and references only 1 register is necessary
            maxArgumentCount += 2 * std::count(demangled.begin(), demangled.end(), ',');
            // the first argument does not have a comma
            if (std::count(demangled.begin(), demangled.end(), '(') > 1 || !contains(demangled, "()")) {
                maxArgumentCount += 2;
            }
//            std::cout <<maxArgumentCount<<" "<<demangled<<std::endl;
            maxFunctionArguments[function.getIRDBFunction()] = maxArgumentCount;
        }
        if (demangledStr != NULL) {
            free(demangledStr);
        }
    }
}

void Analysis::updateDeadRegisters(const Function &function)
{
    if (options.deadRegisterAnalysisType != DeadRegisterAnalysisType::CUSTOM) {
        return;
    }
    deadRegisters.clear();

    const auto [canHandleBackward, canHandleForward] = FixedPointAnalysis::canHandle(function);
    if (!canHandleBackward) {
        return;
    }
    canDoRegisterAnalysisFunctions++;

    RegisterAnalysisCommon deadRegisterCommon(functionWrittenRegisters);
    const auto analysisResult = FixedPointAnalysis::runAnalysis<DeadRegisterInstructionAnalysis, RegisterAnalysisCommon>(function.getCFG(), {}, deadRegisterCommon);
    for (const auto &[instruction, analysis] : analysisResult) {
        deadRegisters.insert({instruction, analysis.getDeadRegisters()});
    }
    if (options.useUndefinedRegisterAnalysis && canHandleForward) {
        std::set<std::pair<const BasicBlock*, const BasicBlock*>> removeEdges;
        for (const auto &block : function.getCFG().getBlocks()) {
            const auto lastInstruction = block.getInstructions().back();
            if (lastInstruction->getMnemonic() == "ud2") {
                for (const auto succ : block.getSuccessors()) {
                    removeEdges.insert({&block, succ});
                }
                continue;
            }
            if (!lastInstruction->isCall()) {
                continue;
            }
            if (isNoReturnCall(lastInstruction)) {
                for (const auto succ : block.getSuccessors()) {
                    removeEdges.insert({&block, succ});
                }
                continue;
            }
            for (const auto succ : block.getSuccessors()) {
                const auto &edgeType = function.getCFG().getEdgeType(&block, succ);
                if (edgeType.find(cetFallthroughEdge) == edgeType.end()) {
                    continue;
                }
                const auto instruction = succ->getInstructions()[0];
                if (succ->getInstructions().size() == 1 && instruction->getMnemonic() == "nop") {
                    if (succ->getSuccessors().size() > 0 && (*succ->getSuccessors().begin())->getPredecessors().size() == 1) {
                        continue;
                    }
                } else if (succ->getPredecessors().size() == 1) {
                    continue;
                }
                removeEdges.insert({&block, succ});
//                  std::cout <<"Remove edge: "<<function->getName()<<" "<<std::hex<<lastInstruction->getAddress()->getVirtualOffset()<<" "<<disassembly(lastInstruction)<<std::endl;
            }
        }
        const auto undefinedResult = FixedPointAnalysis::runAnalysis<UndefinedRegisterInstructionAnalysis, RegisterAnalysisCommon>(function.getCFG(), removeEdges, deadRegisterCommon);
        const bool hasProblem = std::any_of(undefinedResult.begin(), undefinedResult.end(), [](const auto &r) {
            if (r.second.hasProblem()) {
                std::cout <<std::hex<<r.first->getAddress()->getVirtualOffset()<<" "<<r.first->getDisassembly()<<std::endl;
            }
            return r.second.hasProblem();
        });
        if (!hasProblem) {
            for (const auto &[instruction, analysis] : undefinedResult) {
                auto it = deadRegisters.find(instruction);
                it->second |= analysis.getDeadRegisters();
            }
        } else {
            std::cout <<"WARNING: undefined register analysis problem in: "<<function.getName()<<std::endl;
        }
    }
}

CallerSaveRegisterSet Analysis::getDeadRegisters(IRDB_SDK::Instruction_t *instruction) const
{
    const auto dead = deadRegisters.find(instruction);
    if (dead != deadRegisters.end()) {
        return dead->second;
    }
    return CallerSaveRegisterSet();
}

std::function<void()> Analysis::getInstructionCounter(InstrumentationType type)
{
    return [this, type]() {
        switch (type) {
        case InstrumentationType::MEMORY_ACCESS:
            memoryInstrumentationInstructions++;
            break;
        case InstrumentationType::ENTRY_EXIT:
            entryExitInstrumentationInstructions++;
            break;
        case InstrumentationType::EXCEPTION_HANDLING:
            exceptionInstrumentationInstructions++;
            break;
        case InstrumentationType::WRAPPER:
            wrapperInstrumentationInstructions++;
            break;
        }
    };
}

struct Loop
{
    Loop(BasicBlock_t *header, const std::set<BasicBlock_t*> &nodes) : header(header), nodes(nodes) {}
    BasicBlock_t *header;
    std::set<BasicBlock_t*> nodes;
};

static std::vector<Loop> findLoops(ControlFlowGraph_t *cfg)
{
    // TODO: are exceptions handled in the domgraph?
    const auto domGraph = DominatorGraph_t::factory(cfg);

    std::vector<Loop> loops;

    for (const auto block : cfg->getBlocks()) {
        // the CFG is constructed such that return blocks always have the entry block as a successor
        if (block->getIsExitBlock()) {
            continue;
        }
        const auto decoded = DecodedInstruction_t::factory(block->getInstructions().back());
        // TODO: make own CFG where these blocks do not exist
        if (decoded->getMnemonic() == "nop" && block->getPredecessors().size() == 0) {
            continue;
        }
        for (const auto child : block->getSuccessors()) {
            if (child->getIsExitBlock()) {
                continue;
            }
            const auto &childDominated = domGraph->getDominated(child);
            const bool childDominatesBlock = childDominated.find(block) != childDominated.end();
            if (childDominatesBlock) { // backwards edge
                std::vector<BasicBlock_t*> workList;
                std::set<BasicBlock_t*> loopBlocks;
                loopBlocks.insert(child);
                if (block != child) {
                    loopBlocks.insert(block);
                    workList.push_back(block);
                }
                while (workList.size() > 0) {
                    const BasicBlock_t *currentBlock = workList.back();
                    workList.pop_back();
                    for (BasicBlock_t *predecessor : currentBlock->getPredecessors()) {
                        const bool hasPredecessor = loopBlocks.find(predecessor) != loopBlocks.end();
                        if (!hasPredecessor) {
                            loopBlocks.insert(predecessor);
                            workList.push_back(predecessor);
                        }
                    }
                }

                Loop loop(child, loopBlocks);
                loops.push_back(loop);
            }
        }
    }
    return loops;
}

std::set<Instruction_t*> Analysis::findSpinLocks(ControlFlowGraph_t *cfg) const
{
    std::set<Instruction_t*> spinLockMemoryReads;
    const auto loops = findLoops(cfg);
    for (const auto &loop : loops) {
        // any instruction that can not be present in a spin lock loop
        bool foundBad = false;
        Instruction_t *memoryRead = nullptr;
        std::shared_ptr<DecodedOperand_t> readOperand;
        for (const auto block : loop.nodes) {
            for (auto instruction : block->getInstructions()) {
                const auto decoded = DecodedInstruction_t::factory(instruction);
                if (decoded->isCall()) {
                    // some functions calls are allowed in a spin lock
                    const std::string targetName = targetFunctionName(instruction);
                    if (!contains(targetName, "usleep") && !contains(targetName, "sched_yield")) {
                        foundBad = true;
                        break;
                    }
                }
                if (decoded->getMnemonic() == "syscall") {
                    foundBad = true;
                    break;
                }
                // implicit memory modification
                if (decoded->getMnemonic() == "push" || decoded->getMnemonic() == "pop") {
                    foundBad = true;
                    break;
                }
                // TODO: if the memory operand is to fs: or the stack, print an error
                for (auto operand : decoded->getOperands()) {
                    if (operand->isWritten() && operand->isMemory()) {
                        foundBad = true;
                        break;
                    }
                    if (operand->isRead() && operand->isMemory()) {
                        if (memoryRead != nullptr) {
                            foundBad = true;
                            break;
                        }
                        if (!startsWith(decoded->getMnemonic(), "mov")) {
                            foundBad = true;
                            break;
                        }
                        memoryRead = instruction;
                        readOperand = operand;
                    }
                }
            }
            if (foundBad) {
                break;
            }
        }
        if (!foundBad && memoryRead != nullptr) {
            for (const auto block : loop.nodes) {
                for (auto instruction : block->getInstructions()) {
                    const auto decoded = DecodedInstruction_t::factory(instruction);
                    for (auto operand : decoded->getOperands()) {
                        if (operand->isWritten()) {
                            // TODO: implicit register writes
                            if ((readOperand->hasBaseRegister() && operand->getRegNumber() == readOperand->getBaseRegister()) ||
                                    (readOperand->hasIndexRegister() && operand->getRegNumber() == readOperand->getIndexRegister())) {
                                foundBad = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (!foundBad) {
                const auto domGraph = DominatorGraph_t::factory(cfg);
                const auto headerInstruction = loop.header->getInstructions()[0];
                std::cout <<"Found spin lock loop in "<<cfg->getFunction()->getName()<<"  "<<std::hex<<headerInstruction->getAddress()->getVirtualOffset()
                         <<": "<<headerInstruction->getDisassembly()<<std::endl;
                spinLockMemoryReads.insert(memoryRead);
            }
        }
    }
    return spinLockMemoryReads;
}

static void checkNoReturnRecursive(const Function *function, std::set<Function_t*> &noReturnFunctions, std::set<const Function*> &visited)
{
    if (visited.find(function) != visited.end()) {
        return;
    }
    visited.insert(function);

    // check known noreturn functions
    const std::string functionName = function->getName();

    // TODO: functionName == "_Unwind_Resumepart1@plt"
    if (functionName == "exitpart1@plt" || functionName == "abortpart1@plt" ||
            functionName == "pthread_exitpart1@plt" || functionName == "__assert_failpart1@plt" ||
            functionName == "__cxa_throwpart1@plt" || functionName == "__cxa_rethrowpart1@plt" ||
            functionName == "__stack_chk_failpart1@plt" || contains(functionName, "__throw_")) {
        noReturnFunctions.insert(function->getIRDBFunction());
        return;
    }

    bool hasNoReturnCall = false;
    for (Instruction *instruction : function->getInstructions()) {
        // if we have a return statement, the function will return
        if (instruction->isReturn()) {
            return;
        }

        const bool tailJump = instruction->isBranch() && !instruction->isCall() && getJumpInfo(instruction->getIRDBInstruction()).isTailCall;
        const bool isCall = instruction->isCall();
        if (tailJump || isCall) {
            if (instruction->getTarget() == nullptr || instruction->getTarget()->getFunction() == nullptr) {
                return;
            }
            checkNoReturnRecursive(instruction->getTargetFunction(), noReturnFunctions, visited);
            const bool isNoReturn = noReturnFunctions.find(instruction->getTargetFunction()->getIRDBFunction()) != noReturnFunctions.end();
            if (!isNoReturn && tailJump) {
                return;
            }
            if (isNoReturn) {
                hasNoReturnCall = true;
            }
        }
    }
    if (hasNoReturnCall) {
        noReturnFunctions.insert(function->getIRDBFunction());
    }
}

std::set<Function_t*> Analysis::findNoReturnFunctions(const Program &program) const
{
    // TODO: additional criteria: at the caller, there is a nop after the call?
    std::set<Function_t*> noReturnFunctions;
    std::set<const Function*> visited;

    for (const Function &function : program.getFunctions()) {
        checkNoReturnRecursive(&function, noReturnFunctions, visited);
    }

    return noReturnFunctions;
}

void Analysis::findWrittenRegistersRecursive(const Function *function, std::set<const Function*> &visited, CapstoneHandle &capstone)
{
    if (function == nullptr) {
        return;
    }
    if (visited.find(function) != visited.end()) {
        return;
    }
    visited.insert(function);

    CallerSaveRegisterSet writtenRegisters;
    for (Instruction_t *instruction : function->getIRDBFunction()->getInstructions()) {
        writtenRegisters |= Register::getWrittenCallerSaveRegisters(capstone, instruction);
    }
    // set it here first in case of some indirect recursive functions
    functionWrittenRegisters[function->getIRDBFunction()] = writtenRegisters;

    for (Instruction *instruction : function->getInstructions()) {
        // do not consider tail call jumps to a register since they could also stay in the function (switch tables or similar)
        if (instruction->isUnconditionalBranch() && instruction->getTarget() != nullptr && instruction->getTarget()->getFunction() != function) {
            Function *targetFunction = instruction->getTarget()->getFunction();
            findWrittenRegistersRecursive(targetFunction, visited, capstone);
            writtenRegisters |= functionWrittenRegisters[targetFunction->getIRDBFunction()];
        } else if (instruction->isUnconditionalBranch() && instruction->getTarget() == nullptr && instruction->getIRDBInstruction()->getRelocations().size() > 0) {
            // for a thunk, consider it to write all caller save registers
            writtenRegisters.set();
            break;
        }
        if (instruction->isCall()) {
            // indirect calls are considered to write all registers
            if (instruction->getTargetFunction() == nullptr) {
                writtenRegisters.set();
                break;
            } else if (instruction->getTargetFunction() != function) {
                Function *targetFunction = instruction->getTargetFunction();
                findWrittenRegistersRecursive(targetFunction, visited, capstone);
                writtenRegisters |= functionWrittenRegisters[targetFunction->getIRDBFunction()];
            }
        }
    }
    functionWrittenRegisters[function->getIRDBFunction()] = writtenRegisters;
}

void Analysis::computeFunctionRegisterWrites(const Program &program)
{
    std::set<const Function*> visited;
    CapstoneHandle capstone;
    for (const Function &function : program.getFunctions()) {
        findWrittenRegistersRecursive(&function, visited, capstone);
    }
}

bool Analysis::isDataConstant(FileIR_t *ir, Instruction *instruction, const std::shared_ptr<DecodedOperand_t> operand)
{
    // TODO: exeiop->sections.findByAddress(referenced_address);
    if (operand->hasBaseRegister()) {
        return false;
    }
    const auto additionalOffset = operand->isPcrel() ? instruction->getDecoded()->length() : 0;
    const auto realOffset = operand->getMemoryDisplacement() + additionalOffset;
    for (DataScoop_t *s : ir->getDataScoops()) {
        if (s->getStart()->getVirtualOffset() == 0) {
            continue;
        }
        if (s->isWriteable() || s->isExecuteable()) {
            continue;
        }
        if (realOffset > s->getStart()->getVirtualOffset() && realOffset < s->getEnd()->getVirtualOffset()) {
            if (operand->isWritten()) {
                return false;
                throw std::logic_error("read only memory seems to be written");
            }
            return true;
        }
    }
    return false;
}

inline bool isAtomic(const Instruction *instruction)
{
    const std::string dataBits = instruction->getIRDBInstruction()->getDataBits();
    return std::any_of(dataBits.begin(), dataBits.begin() + instruction->getDecoded()->getPrefixCount(), [](char c) {
        return static_cast<unsigned char>(c) == 0xF0;
    });
}

static bool isAtomicOrXchg(Instruction *instruction)
{
    return isAtomic(instruction) || instruction->getMnemonic() == "xchg";
}

std::map<Instruction_t *, __tsan_memory_order> Analysis::inferAtomicInstructions(const Function &function, const std::set<Instruction_t*> &spinLockInstructions) const
{
    const auto &instructions = function.getInstructions();
    const bool hasAtomic = std::any_of(instructions.begin(), instructions.end(), isAtomicOrXchg);
    if (!hasAtomic && spinLockInstructions.size() == 0) {
        return {};
    }

    PointerAnalysis functionEntry = PointerAnalysis::functionEntry();
    auto analysis = FixedPointAnalysis::runForward<PointerAnalysis>(function, functionEntry);

    std::map<MemoryLocation, std::vector<Instruction*>> sameLocation;
    for (Instruction *instruction : function.getInstructions()) {
        if (instruction->getMnemonic() == "nop" || instruction->getMnemonic() == "lea") {
            continue;
        }
        for (const auto &operand : instruction->getDecoded()->getOperands()) {
            if (operand->isMemory() && operand->hasBaseRegister() && !operand->hasIndexRegister()) {
                const std::string opString = operand->getString();
                const std::string regName(opString.begin(), opString.begin() + 3);
                const RegisterID reg = strToRegister(regName);
                if (!is64bitRegister(reg)) {
                    continue;
                }
                auto analysisResult = analysis[instruction->getIRDBInstruction()].getMemoryLocations();
                if (analysisResult.find(reg) != analysisResult.end()) {
                    MemoryLocation location = analysisResult[reg];
                    if (operand->hasMemoryDisplacement()) {
                        location.offset += operand->getMemoryDisplacement();
                    }
                    sameLocation[location].push_back(instruction);
                }
            }
        }
    }

    std::map<Instruction_t *, __tsan_memory_order> result;

    bool hasPrinted = false;
    for (const auto &[pos, sameLocInstructions] : sameLocation) {
        const std::size_t atomicCount = std::count_if(sameLocInstructions.begin(), sameLocInstructions.end(), isAtomicOrXchg);
        const std::size_t spinLockCount = std::count_if(sameLocInstructions.begin(), sameLocInstructions.end(), [&spinLockInstructions](auto instruction) {
            return spinLockInstructions.find(instruction->getIRDBInstruction()) != spinLockInstructions.end();
        });
        const std::size_t totalCount = atomicCount + spinLockCount;
        if (totalCount == 0 || atomicCount == sameLocInstructions.size()) {
            continue;
        }
        if (!hasPrinted) {
//             std::cout <<"Inferred atomics in function "<<function->getName()<<": "<<pos.locationId<<", "<<pos.offset<<std::endl;
             hasPrinted = true;
        }
//        std::cout <<"Same memory location set:"<<std::endl;
        for (auto instruction : sameLocInstructions) {
            if (spinLockInstructions.find(instruction->getIRDBInstruction()) != spinLockInstructions.end()) {
//                std::cout <<instruction->getDisassembly()<<" (spin lock read)"<<std::endl;
                continue;
            }
            if (!isAtomicOrXchg(instruction)) {
                if (instruction->getMnemonic() == "mov") {
                    if (spinLockCount == 0) {
                        result[instruction->getIRDBInstruction()] = __tsan_memory_order_relaxed;
                    } else {
                        for (auto operand : instruction->getDecoded()->getOperands()) {
                            if (operand->isMemory()) {
                                if (operand->isRead()) {
                                    result[instruction->getIRDBInstruction()] = __tsan_memory_order_acquire;
                                } else {
                                    result[instruction->getIRDBInstruction()] = __tsan_memory_order_release;
                                }
                                break;
                            }
                        }
                    }
                } else {
                    std::cout <<"WARNING: found non-atomic instruction to atomic like memory: "<<instruction->getDisassembly()<<std::endl;
                }
            } else if (spinLockCount > 0) {
                result[instruction->getIRDBInstruction()] = __tsan_memory_order_acquire;
            }
//            std::cout <<disassembly(instruction)<<std::endl;
        }
//        std::cout <<std::endl;
    }
    return result;
}

std::set<Instruction_t*> Analysis::detectStackCanaryInstructions(const Function &function) const
{
    const std::string CANARY_CHECK = "fs:[0x28]";

    std::set<Instruction_t*> result;

    Instruction *canaryStackWrite = nullptr;

    // find the initial read of the canary value and its corresponding write to stack
    Instruction *instruction = function.getEntryPoint();
    for (int i = 0;i<20;i++) {
        const std::string assembly = instruction->getDisassembly();
        const auto &decoded = instruction->getDecoded();
        if (contains(assembly, CANARY_CHECK)) {
            if (decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() && decoded->getOperand(0)->isRegister()) {
                Instruction *next = instruction->getFallthrough();
                if (next == nullptr) {
                    std::cout <<"ERROR: unexpected instruction termination"<<std::endl;
                    break;
                }
                const auto &nextDecoded = next->getDecoded();
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
        result.insert(canaryStackWrite->getIRDBInstruction());
        const auto &decodedWrite = canaryStackWrite->getDecoded();

        for (Instruction *instruction : function.getInstructions()) {
            const std::string &assembly = instruction->getDisassembly();
            const auto &decoded = instruction->getDecoded();
            const bool isCanaryStackRead = decoded->hasOperand(1) && decoded->getOperand(1)->isMemory() &&
                    decoded->getOperand(1)->getString() == decodedWrite->getOperand(0)->getString();
            if (contains(assembly, CANARY_CHECK) || isCanaryStackRead) {
//                std::cout <<"Ignore canary instruction: "<<assembly<<std::endl;
                result.insert(instruction->getIRDBInstruction());
                continue;
            }
        }
    }
    return result;
}

std::set<Instruction_t*> Analysis::detectStaticVariableGuards(const Function &function) const
{
    // find locations of all static variable guards
    std::set<std::string> guardLocations;
    for (const auto &block : function.getCFG().getBlocks()) {
        const auto &instructions = block.getInstructions();
        if (instructions.size() < 2) {
            continue;
        }
        // check if there is a static guard aquire
        const Instruction *last = instructions.back();
        const std::string targetName = targetFunctionName(last->getIRDBInstruction());
        // TODO: is the name the same for all compilers/compiler versions?
        if (!contains(targetName, "cxa_guard_acquire")) {
            continue;
        }
        // find location of the guard lock variable
        for (int i = int(instructions.size())-2;i>=0;i--) {
            const Instruction *instruction = instructions[i];
            const auto &decoded = instruction->getDecoded();
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
            std::cout <<"WARNING: could not find static variable guard location! "<<std::hex<<last->getVirtualOffset()<<" "<<function.getName()<<std::endl;
        }
    }

    // find all read accesses to the guard variables
    std::set<Instruction_t*> result;
    for (Instruction *instruction : function.getInstructions()) {
        const auto &decoded = instruction->getDecoded();
        if (decoded->getOperands().size() < 2 || !decoded->getOperand(1)->isMemory()) {
            continue;
        }
        const std::string op1Str = decoded->getOperand(1)->getString();
        const bool isGuardLocation = guardLocations.find(op1Str) != guardLocations.end();
        if (isGuardLocation) {
//            std::cout <<"Found static variable guard read: "<<instruction->getDisassembly()<<std::endl;
            result.insert(instruction->getIRDBInstruction());
        }
    }
    return result;
}

bool Analysis::isNoReturnCall(Instruction *instruction) const
{
    if (!instruction->isCall() || instruction->getTarget() == nullptr) {
        return false;
    }
    // currently not included in the no return analysis
    const bool isUnwindResume = targetFunctionName(instruction->getIRDBInstruction()) == "_Unwind_Resumepart1@plt";
    return noReturnFunctions.find(instruction->getIRDBInstruction()->getTarget()->getFunction()) != noReturnFunctions.end() || isUnwindResume;
}

void Analysis::printStatistics() const
{
    std::cout <<std::dec;
    std::cout <<std::endl<<"Statistics:"<<std::endl;
    std::cout <<"Analyzed Functions: "<<totalAnalysedFunctions<<std::endl;
    std::cout <<"\t* Entry/Exit instrumented: "<<entryExitInstrumentedFunctions<<std::endl;
    std::cout <<"\t* Register analyzed: "<<canDoRegisterAnalysisFunctions<<std::endl;
    std::cout <<std::endl;
    std::cout <<"Analyzed Instructions: "<<totalAnalysedInstructions<<std::endl;
    const std::size_t totalInstrumentationInstructions = memoryInstrumentationInstructions + entryExitInstrumentationInstructions +
            exceptionInstrumentationInstructions + wrapperInstrumentationInstructions;
    std::cout <<"\t* New Instrumentation Instructions: "<<totalInstrumentationInstructions<<std::endl;
    std::cout <<"\t\t- Memory Access: "<<memoryInstrumentationInstructions<<std::endl;
    std::cout <<"\t\t- Function Entry/Exit: "<<entryExitInstrumentationInstructions<<std::endl;
    std::cout <<"\t\t- Exception Handling: "<<exceptionInstrumentationInstructions<<std::endl;
    std::cout <<"\t\t- Wrapper Functions: "<<wrapperInstrumentationInstructions<<std::endl;
    std::cout <<"\t* Instrumented Instructions: "<<totalInstrumentedInstructions<<std::endl;
    std::cout <<"\t* Not instrumented: "<<totalNotInstrumented<<std::endl;
    // these might have some overlap, but it should not be too bad
    std::cout <<"\t\t- Stack Canaries: "<<stackCanaryInstructions<<std::endl;
    std::cout <<"\t\t- Stack Local Variables: "<<stackLocalVariables<<std::endl;
    std::cout <<"\t\t- Constant Memory Read: "<<constantMemoryRead<<std::endl;
    std::cout <<"\t\t- Stack Memory: "<<stackMemory<<std::endl;
    std::cout <<"\t* Inferred Atomics:"<<std::endl;
    std::cout <<"\t\t- Pointer Inference: "<<pointerInferredAtomics<<std::endl;
    std::cout <<"\t\t- Static Variable Guards: "<<staticVariableGuards<<std::endl;
    std::cout <<"\t\t- Spin Locks: "<<spinLocks<<std::endl;
}
