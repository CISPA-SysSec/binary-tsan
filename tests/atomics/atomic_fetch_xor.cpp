// RUN: %clangxx_tsan -O1 %s -o %t

#include <pthread.h>
#include <iostream>

using namespace std;

const int iterations = 4000000;

void *Thread(void *a) {
    volatile int *value = (int*)a;
    for (int i = 0;i<iterations;i++) {
        // probably generates a "lock and" instruction
        __atomic_fetch_xor(value, i, __ATOMIC_RELAXED);
    }
    return 0;
}

int main() {
    int *a = new int(0xA1B573F9);
    pthread_t t1, t2;
    pthread_create(&t1, 0, Thread, a);
    pthread_create(&t2, 0, Thread, a);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    
    std::cout <<*a<<std::endl;
    if (*a != -1581943815) {
        return 1;
    }
    return 0;
}

// CHECK-NOT: WARNING: ThreadSanitizer: data race
