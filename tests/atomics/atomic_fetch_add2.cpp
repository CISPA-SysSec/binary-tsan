// RUN: %clangxx_tsan -O1 %s -o %t

#include <pthread.h>
#include <iostream>

using namespace std;

const int it = 4000000;

void *Thread(void *a) {
    volatile int *value = (int*)a;
    for (int i = 0;i<it;i++) {
        // probably generates a "lock xadd" instruction
        int v = __atomic_fetch_add(value, 1, __ATOMIC_RELAXED);
        if (v > it * 2) {
            break;
        }
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
    if (*a != it * 2) {
        return 1;
    }
    return 0;
}

// CHECK-NOT: WARNING: ThreadSanitizer: data race
