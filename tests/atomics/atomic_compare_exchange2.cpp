// RUN: %clangxx_tsan -O1 %s -o %t

#include <pthread.h>
#include <iostream>

using namespace std;

int a = 0;
int counter[2];

const int iterations = 4000000;

void *Thread(void *counter) {
    int c = 0;
    for (int i = 0;i<iterations;i++) {
        // probably generates a "lock cmpxchg" instruction
        int b = i;
        if (__atomic_compare_exchange_n(&a, &b, i + 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            c++;
        }
    }
    *((int*)counter) = c;
    return 0;
}

int main() {
    counter[0] = 0;
    counter[1] = 0;
    pthread_t t1, t2;
    pthread_create(&t1, 0, Thread, counter);
    pthread_create(&t2, 0, Thread, counter + 1);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    
    int total = counter[0] + counter[1];
    std::cout <<total<<std::endl;
    if (total != iterations) {
        return 1;
    }
    return 0;
}

// CHECK-NOT: WARNING: ThreadSanitizer: data race
