#ifndef ANNOTATIONS_H
#define ANNOTATIONS_H

#include <string>
#include <irdb-core>

// from tsan-interface-atomic.h, do not change
typedef enum {
    __tsan_memory_order_relaxed = 0,
    __tsan_memory_order_consume = 1,
    __tsan_memory_order_acquire = 2,
    __tsan_memory_order_release = 3,
    __tsan_memory_order_acq_rel = 4,
    __tsan_memory_order_seq_cst = 5
} __tsan_memory_order;

enum class HappensBeforeOperation
{
    Acquire,
    Release
};

struct HappensBeforeAnnotation
{
    HappensBeforeAnnotation(IRDB_SDK::Function_t *f, HappensBeforeOperation op, const std::string &reg, bool before) :
        function(f),
        operation(op),
        registerForPointer(reg),
        isBefore(before)
    { }
    IRDB_SDK::Function_t *function;
    HappensBeforeOperation operation;
    std::string registerForPointer;
    // WARNING: using the after prefix does not work for functions with stack arguments
    bool isBefore;
};

class Annotations
{
public:
    // if it is called multiple times then the annotation with accumulate
    bool parseFromFile(IRDB_SDK::FileIR_t *ir, const std::string &filename);

public:
    std::map<IRDB_SDK::Function_t*, std::vector<HappensBeforeAnnotation>> happensBefore;

    std::map<IRDB_SDK::Instruction_t*, __tsan_memory_order> atomicInstructions;
    std::set<IRDB_SDK::Instruction_t*> ignoreInstructions;
};

#endif // ANNOTATIONS_H
