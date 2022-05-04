#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <mutex>
#include <algorithm>

#include "sanitizer_common/sanitizer_symbolizer.h"

#define CALLERPC ((void*)__builtin_return_address(0))
# define SANITIZER_INTERFACE_ATTRIBUTE __attribute__((visibility("default")))

using namespace __sanitizer;

static std::ofstream output;
static std::mutex mutex;

static void initialize()
{
    static bool isInitialized = false;
    if (isInitialized) {
        return;
    }
    isInitialized = true;

    SetCommonFlagsDefaults();
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.symbolize = true;
    cf.allow_addr2line = true;
    OverrideCommonFlags(cf);

    InitializeCommonFlags();
}

class ThreadInfo
{
public:
    ~ThreadInfo() {
        initialize();

        mutex.lock();
        std::cout <<accessCount.size()<<std::endl;
        if (!output.is_open()) {
            output.open("access_count.txt");
            if (!output.is_open()) {
                std::cout <<"Could not open log output file for writing"<<std::endl;
                mutex.unlock();
                return;
            }
        }

        std::map<std::string, unsigned long> functionAccessCount;

        Symbolizer *symbolizer = Symbolizer::GetOrInit();
        for (const auto &[location, count] : accessCount) {
            const auto res = symbolizer->SymbolizePC((uptr)location);
            if (res->info.function != nullptr) {
                functionAccessCount[res->info.function] += count;
            }
        }

        std::vector<std::pair<unsigned long, std::string>> sortedFunctions;
        sortedFunctions.reserve(functionAccessCount.size());
        for (const auto &[name, count] : functionAccessCount) {
            sortedFunctions.push_back({count, name});
        }
        std::sort(sortedFunctions.begin(), sortedFunctions.end());

        for (const auto &[count, name] : sortedFunctions) {
            std::cout <<name<<": "<<count<<std::endl;
            output <<name<<": "<<count<<std::endl;
        }

        mutex.unlock();
        destroyed = true;
    }
    std::vector<void*> callStack;
    std::map<void*, uint64_t> accessCount;
    bool destroyed = false;
};

static ThreadInfo threadInfo;

static void logAccess(void* ret)
{
    if (threadInfo.destroyed) {
        return;
    }
    // TODO: use thread local storage instead (but that seems to segfault)
    mutex.lock();
    threadInfo.accessCount[ret]++;
    mutex.unlock();
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_func_entry(void*) { }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_func_exit() { }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read1(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read2(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read4(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read8(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read16(void*) { logAccess(CALLERPC); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write1(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write2(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write4(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write8(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write16(void*) { logAccess(CALLERPC); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_read2(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_read4(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_read8(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_read16(void*) { logAccess(CALLERPC); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_write2(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_write4(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_write8(void*) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_unaligned_write16(void*) { logAccess(CALLERPC); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read1_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read2_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read4_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read8_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read16_pc(void*, void *pc) { logAccess(pc); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write1_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write2_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write4_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write8_pc(void*, void *pc) { logAccess(pc); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write16_pc(void*, void *pc) { logAccess(pc); }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_acquire(void*) { }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_release(void*) { }

SANITIZER_INTERFACE_ATTRIBUTE void __tsan_read_range(void*, unsigned long) { logAccess(CALLERPC); }
SANITIZER_INTERFACE_ATTRIBUTE void __tsan_write_range(void*, unsigned long) { logAccess(CALLERPC); }

// taken directly from the thread sanitizer code
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_testonly_barrier_init(u64 *barrier, u32 count) {
    if (count >= (1 << 8)) {
        exit(1);
    }
    // 8 lsb is thread count, the remaining are count of entered threads.
    *barrier = count;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_testonly_barrier_wait(u64 *barrier) {
    unsigned old = __atomic_fetch_add(barrier, 1 << 8, __ATOMIC_RELAXED);
    unsigned old_epoch = (old >> 8) / (old & 0xff);
    for (;;) {
        unsigned cur = __atomic_load_n(barrier, __ATOMIC_RELAXED);
        unsigned cur_epoch = (cur >> 8) / (cur & 0xff);
        if (cur_epoch != old_epoch)
            return;
        internal_sched_yield();
    }
}
SANITIZER_INTERFACE_ATTRIBUTE unsigned long __tsan_testonly_shadow_stack_current_size() { return 0; }

//typedef enum {
//  mo_relaxed,
//  mo_consume,
//  mo_acquire,
//  mo_release,
//  mo_acq_rel,
//  mo_seq_cst
//} morder;

//typedef unsigned char      a8;
//typedef unsigned short a16;
//typedef unsigned int       a32;
//typedef unsigned long long a64;
//__extension__ typedef __int128 a128;

//a8 __tsan_atomic8_load(const volatile a8 *a, morder mo) { logAccess(CALLERPC); return std::atomic }

//a16 __tsan_atomic16_load(const volatile a16 *a, morder mo);

//a32 __tsan_atomic32_load(const volatile a32 *a, morder mo);

//a64 __tsan_atomic64_load(const volatile a64 *a, morder mo);

//a128 __tsan_atomic128_load(const volatile a128 *a, morder mo);


//void __tsan_atomic8_store(volatile a8 *a, a8 v, morder mo);

//void __tsan_atomic16_store(volatile a16 *a, a16 v, morder mo);

//void __tsan_atomic32_store(volatile a32 *a, a32 v, morder mo);

//void __tsan_atomic64_store(volatile a64 *a, a64 v, morder mo);

//void __tsan_atomic128_store(volatile a128 *a, a128 v, morder mo);


//a8 __tsan_atomic8_exchange(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_exchange(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_exchange(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_exchange(volatile a64 *a, a64 v, morder mo);

//a128 __tsan_atomic128_exchange(volatile a128 *a, a128 v, morder mo);


//a8 __tsan_atomic8_fetch_add(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_add(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_add(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_add(volatile a64 *a, a64 v, morder mo);

//a128 __tsan_atomic128_fetch_add(volatile a128 *a, a128 v, morder mo);


//a8 __tsan_atomic8_fetch_sub(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_sub(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_sub(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_sub(volatile a64 *a, a64 v, morder mo);

//a128 __tsan_atomic128_fetch_sub(volatile a128 *a, a128 v, morder mo);


//a8 __tsan_atomic8_fetch_and(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_and(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_and(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_and(volatile a64 *a, a64 v, morder mo);

//a128 __tsan_atomic128_fetch_and(volatile a128 *a, a128 v, morder mo);


//a8 __tsan_atomic8_fetch_or(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_or(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_or(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_or(volatile a64 *a, a64 v, morder mo);

//a128 __tsan_atomic128_fetch_or(volatile a128 *a, a128 v, morder mo);



//a8 __tsan_atomic8_fetch_xor(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_xor(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_xor(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_xor(volatile a64 *a, a64 v, morder mo);


//a128 __tsan_atomic128_fetch_xor(volatile a128 *a, a128 v, morder mo);



//a8 __tsan_atomic8_fetch_nand(volatile a8 *a, a8 v, morder mo);

//a16 __tsan_atomic16_fetch_nand(volatile a16 *a, a16 v, morder mo);

//a32 __tsan_atomic32_fetch_nand(volatile a32 *a, a32 v, morder mo);

//a64 __tsan_atomic64_fetch_nand(volatile a64 *a, a64 v, morder mo);


//a128 __tsan_atomic128_fetch_nand(volatile a128 *a, a128 v, morder mo);



//int __tsan_atomic8_compare_exchange_strong(volatile a8 *a, a8 *c, a8 v,
//                                           morder mo, morder fmo);

//int __tsan_atomic16_compare_exchange_strong(volatile a16 *a, a16 *c, a16 v,
//                                            morder mo, morder fmo);

//int __tsan_atomic32_compare_exchange_strong(volatile a32 *a, a32 *c, a32 v,
//                                            morder mo, morder fmo);

//int __tsan_atomic64_compare_exchange_strong(volatile a64 *a, a64 *c, a64 v,
//                                            morder mo, morder fmo);


//int __tsan_atomic128_compare_exchange_strong(volatile a128 *a, a128 *c, a128 v,
//                                             morder mo, morder fmo);



//int __tsan_atomic8_compare_exchange_weak(volatile a8 *a, a8 *c, a8 v, morder mo,
//                                         morder fmo);

//int __tsan_atomic16_compare_exchange_weak(volatile a16 *a, a16 *c, a16 v,
//                                          morder mo, morder fmo);

//int __tsan_atomic32_compare_exchange_weak(volatile a32 *a, a32 *c, a32 v,
//                                          morder mo, morder fmo);

//int __tsan_atomic64_compare_exchange_weak(volatile a64 *a, a64 *c, a64 v,
//                                          morder mo, morder fmo);


//int __tsan_atomic128_compare_exchange_weak(volatile a128 *a, a128 *c, a128 v,
//                                           morder mo, morder fmo);


//a8 __tsan_atomic8_compare_exchange_val(volatile a8 *a, a8 c, a8 v, morder mo,
//                                       morder fmo);

//a16 __tsan_atomic16_compare_exchange_val(volatile a16 *a, a16 c, a16 v,
//                                         morder mo, morder fmo);

//a32 __tsan_atomic32_compare_exchange_val(volatile a32 *a, a32 c, a32 v,
//                                         morder mo, morder fmo);

//a64 __tsan_atomic64_compare_exchange_val(volatile a64 *a, a64 c, a64 v,
//                                         morder mo, morder fmo);


//a128 __tsan_atomic128_compare_exchange_val(volatile a128 *a, a128 c, a128 v,
//                                           morder mo, morder fmo);


}
