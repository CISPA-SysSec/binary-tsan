// RUN: %clangxx_tsan -O1 %s -o %t

#include <pthread.h>
#include <iostream>

using namespace std;

void *Thread(void *a) {
    volatile int *value = (int*)a;
    for (int i = 0;i<4000000;i++) {
        // probably generates a "xchg" instruction
        __atomic_exchange_n(value, i, __ATOMIC_RELAXED);
    }
    return 0;
}

int main() {
    int *a = new int(0);
    pthread_t t1, t2;
    pthread_create(&t1, 0, Thread, a);
    pthread_create(&t2, 0, Thread, a);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    
    std::cout <<*a<<std::endl;
    return *a;
}

// CHECK-NOT: WARNING: ThreadSanitizer: data race
