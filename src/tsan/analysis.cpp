#include "analysis.h"

#include <algorithm>
#include <irdb-cfg>

#include "pointeranalysis.h"
#include "fixedpointanalysis.h"
#include "helper.h"

using namespace IRDB_SDK;

Analysis::Analysis(FileIR_t *ir) :
    ir(ir)
{
    noReturnFunctions = findNoReturnFunctions();
}

FunctionInfo Analysis::analyseFunction(Function_t *function)
{
    totalAnalysedFunctions++;
    totalAnalysedInstructions += function->getInstructions().size();
    if (FixedPointAnalysis::canHandle(function)) {
        canDoRegisterAnalysisFunctions++;
    }

    FunctionInfo result;
    result.inferredStackFrameSize = inferredStackFrameSize(function);

    std::set<Instruction_t*> notInstrumented = detectStackCanaryInstructions(function);
    stackCanaryInstructions += notInstrumented.size();

    const auto cfg = ControlFlowGraph_t::factory(function);
    const auto spinLockInstructions = findSpinLocks(cfg.get());

    result.inferredAtomicInstructions = inferAtomicInstructions(function, spinLockInstructions);
    pointerInferredAtomics += result.inferredAtomicInstructions.size();
    for (auto guardInstruction : detectStaticVariableGuards(function)) {
        result.inferredAtomicInstructions[guardInstruction] = __tsan_memory_order_acquire;
        staticVariableGuards++;
    }
    for (auto spinLock : spinLockInstructions) {
        result.inferredAtomicInstructions[spinLock] = __tsan_memory_order_acquire;
        spinLocks++;
    }

    result.properEntryPoint = function->getEntryPoint();
    if (contains(result.properEntryPoint->getDisassembly(), "endbr")) {
        result.properEntryPoint = result.properEntryPoint->getFallthrough();
    }

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
            if (contains(targetFunctionName(instruction), "Unwind_Resume")) {
                unwindFunctions++;
            }
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
            entryExitInstrumentedFunctions++;
        }
    }

    const bool stackLeavesFunction = doesStackLeaveFunction(function);

    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->isBranch() || decoded->isCall()) {
            continue;
        }
        const std::string mnemonic = decoded->getMnemonic();
        if (mnemonic == "lea" || mnemonic == "nop" || startsWith(mnemonic, "prefetch")) {
            continue;
        }
        if (notInstrumented.find(instruction) != notInstrumented.end()) {
            totalNotInstrumented++;
            continue;
        }
        const std::string disassembly = instruction->getDisassembly();
        if (contains(disassembly, "fs:")) {
            totalNotInstrumented++;
            threadLocalMemory++;
            continue;
        }

        const DecodedOperandVector_t operands = decoded->getOperands();
        for (const auto &operand : operands) {
            if (!operand->isMemory()) {
                continue;
            }
            // TODO: under the right condition rbp based operands can also be ignored
            if (!stackLeavesFunction && (contains(operand->getString(), "rsp") || contains(operand->getString(), "esp"))) {
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
                    if (!contains(targetFunctionName(instruction), "usleep")) {
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

static void checkNoReturnRecursive(Function_t *function, std::set<Function_t*> &noReturnFunctions, std::set<Function_t*> &visited)
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
            functionName == "__cxa_throwpart1@plt") {
        noReturnFunctions.insert(function);
        return;
    }

    bool hasNoReturnCall = false;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        // if we have a return statement, the function will return
        if (decoded->isReturn()) {
            return;
        }

        const bool tailJump = decoded->isBranch() && !decoded->isCall() && getJumpInfo(instruction).isTailCall;
        const bool isCall = decoded->isCall();
        if (tailJump || isCall) {
            if (instruction->getTarget() == nullptr) {
                return;
            }
            checkNoReturnRecursive(instruction->getTarget()->getFunction(), noReturnFunctions, visited);
            const bool isNoReturn = noReturnFunctions.find(instruction->getTarget()->getFunction()) != noReturnFunctions.end();
            if (!isNoReturn && tailJump) {
                return;
            }
            if (isNoReturn) {
                hasNoReturnCall = true;
            }
        }
    }
    if (hasNoReturnCall) {
        noReturnFunctions.insert(function);
    }
}

std::set<Function_t*> Analysis::findNoReturnFunctions() const
{
    // TODO: additional criteria: at the caller, there is a nop after the call?
    std::set<Function_t*> noReturnFunctions;
    std::set<Function_t*> visited;

    for (Function_t *function : ir->getFunctions()) {
        checkNoReturnRecursive(function, noReturnFunctions, visited);
    }

//    for (auto f : noReturnFunctions) {
//        std::cout <<"no return: "<<std::hex<<f->getEntryPoint()->getAddress()->getVirtualOffset()<<" "<<f->getName()<<std::endl;
//    }

    return noReturnFunctions;
}

bool Analysis::isDataConstant(FileIR_t *ir, Instruction_t *instruction, const std::shared_ptr<DecodedOperand_t> operand)
{
    // TODO: exeiop->sections.findByAddress(referenced_address);
    if (operand->hasBaseRegister()) {
        return false;
    }
    const auto decoded = DecodedInstruction_t::factory(instruction);
    const auto additionalOffset = operand->isPcrel() ? decoded->length() : 0;
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

static bool isAtomicOrXchg(Instruction_t *instruction)
{
    const auto decoded = DecodedInstruction_t::factory(instruction);
    return isAtomic(instruction) || decoded->getMnemonic() == "xchg";
}

std::map<Instruction_t *, __tsan_memory_order> Analysis::inferAtomicInstructions(IRDB_SDK::Function_t *function, const std::set<Instruction_t*> &spinLockInstructions) const
{
    const auto instructions = function->getInstructions();
    const bool hasAtomic = std::any_of(instructions.begin(), instructions.end(), isAtomicOrXchg);
    if (!hasAtomic && spinLockInstructions.size() == 0) {
        return {};
    }

    PointerAnalysis functionEntry = PointerAnalysis::functionEntry();
    auto analysis = FixedPointAnalysis::runForward<PointerAnalysis>(function, functionEntry);

    std::map<MemoryLocation, std::vector<Instruction_t*>> sameLocation;
    for (Instruction_t *instruction : function->getInstructions()) {
        const auto decoded = DecodedInstruction_t::factory(instruction);
        if (decoded->getMnemonic() == "nop" || decoded->getMnemonic() == "lea") {
            continue;
        }
        for (const auto &operand : decoded->getOperands()) {
            if (operand->isMemory() && operand->hasBaseRegister() && !operand->hasIndexRegister()) {
                const std::string opString = operand->getString();
                const std::string regName(opString.begin(), opString.begin() + 3);
                const RegisterID reg = strToRegister(regName);
                if (!is64bitRegister(reg)) {
                    continue;
                }
                auto analysisResult = analysis[instruction].getMemoryLocations();
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
            return spinLockInstructions.find(instruction) != spinLockInstructions.end();
        });
        const std::size_t totalCount = atomicCount + spinLockCount;
        if (totalCount == 0 || atomicCount == sameLocInstructions.size()) {
            continue;
        }
        if (!hasPrinted) {
             std::cout <<"Inferred atomics in function "<<function->getName()<<": "<<pos.locationId<<", "<<pos.offset<<std::endl;
             hasPrinted = true;
        }
        std::cout <<"Same memory location set:"<<std::endl;
        for (auto instruction : sameLocInstructions) {
            if (spinLockInstructions.find(instruction) != spinLockInstructions.end()) {
                std::cout <<instruction->getDisassembly()<<" (spin lock read)"<<std::endl;
                continue;
            }
            if (!isAtomicOrXchg(instruction)) {
                const auto decoded = DecodedInstruction_t::factory(instruction);
                if (decoded->getMnemonic() == "mov") {
                    if (spinLockCount == 0) {
                        result[instruction] = __tsan_memory_order_relaxed;
                    } else {
                        for (auto operand : decoded->getOperands()) {
                            if (operand->isMemory()) {
                                if (operand->isRead()) {
                                    result[instruction] = __tsan_memory_order_acquire;
                                } else {
                                    result[instruction] = __tsan_memory_order_release;
                                }
                                break;
                            }
                        }
                    }
                } else {
                    std::cout <<"WARNING: found non-atomic instruction to atomic like memory: "<<instruction->getDisassembly()<<std::endl;
                }
            } else if (spinLockCount > 0) {
                result[instruction] = __tsan_memory_order_acquire;
            }
            std::cout <<disassembly(instruction)<<std::endl;
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

void Analysis::printStatistics() const
{
    std::cout <<std::dec;
    std::cout <<std::endl<<"Statistics:"<<std::endl;
    std::cout <<"Analyzed Functions: "<<totalAnalysedFunctions<<std::endl;
    std::cout <<"\t* Entry/Exit instrumented: "<<entryExitInstrumentedFunctions<<std::endl;
    std::cout <<"\t* Has UnwindResume: "<<unwindFunctions<<std::endl;
    std::cout <<"\t* Register analyzed: "<<canDoRegisterAnalysisFunctions<<std::endl;
    std::cout <<std::endl;
    std::cout <<"Analyzed Instructions: "<<totalAnalysedInstructions<<std::endl;
    std::cout <<"\t* New Instrumentation Instructions: "<<instrumentationInstructions<<std::endl;
    std::cout <<"\t* Instrumented Instructions: "<<totalInstrumentedInstructions<<std::endl;
    std::cout <<"\t* Not instrumented: "<<totalNotInstrumented<<std::endl;
    // these might have some overlap, but it should not be too bad
    std::cout <<"\t\t- Stack Canaries: "<<stackCanaryInstructions<<std::endl;
    std::cout <<"\t\t- Thread Local Memory: "<<threadLocalMemory<<std::endl;
    std::cout <<"\t\t- Stack Local Variables: "<<stackLocalVariables<<std::endl;
    std::cout <<"\t\t- Constant Memory Read: "<<constantMemoryRead<<std::endl;
    std::cout <<"\t* Inferred Atomics:"<<std::endl;
    std::cout <<"\t\t- Pointer Inference: "<<pointerInferredAtomics<<std::endl;
    std::cout <<"\t\t- Static Variable Guards: "<<staticVariableGuards<<std::endl;
    std::cout <<"\t\t- Spin Locks: "<<spinLocks<<std::endl;
}
