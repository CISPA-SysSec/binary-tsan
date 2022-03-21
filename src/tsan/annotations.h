#ifndef ANNOTATIONS_H
#define ANNOTATIONS_H

#include <string>
#include <irdb-core>

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
};

#endif // ANNOTATIONS_H
