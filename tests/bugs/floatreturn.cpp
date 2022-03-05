// RUN: %clangxx_tsan -O1 -lm %s -o %t && %deflake %run %t | FileCheck %s

#include <iostream>

volatile float glob = 0;
volatile float readRes = 42.053;

__attribute__((noinline)) float test()
{
//     std::cout <<glob<<std::endl;
    return readRes;
}

void *Thread(void *) {
    for (int i = 0;i<100;i++) {
        const float a = test();
        glob = a;
        if (a != 42.053f) {
            std::cout <<"ERROR WRONG VALUE: "<<a<<std::endl;
        }
    }
    return 0;
}

int main() {
    pthread_t t1, t2;
    pthread_create(&t1, 0, Thread, nullptr);
    pthread_create(&t2, 0, Thread, nullptr);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    
    std::cout <<glob<<std::endl;
    return 0;
}

// CHECK: WARNING: ThreadSanitizer: data race
// CHECK-NOT: ERROR WRONG VALUE

