// RUN: %clangxx_tsan -O2 %s -o %t && %run %t | FileCheck %s

#include <iostream>


__attribute__((noinline)) int test(int a, int b, int c, int d, int e, int f, int g, int j, int k)
{
    std::cout <<a<<" "<<b<<" "<<c<<" "<<d<<" "<<e<<" "<<f<<" "<<g<<" "<<j<<" "<<k<<std::endl;
    return k;
}

__attribute__((noinline)) int foo(int a, int b, int c, int d, int e, int f, int g, int j, int k) {
    std::cout <<a<<" "<<b<<std::endl;
    return test(a, b, c, d, e, f, g, j, k);
}

int main() {
    std::cout <<foo(0, 1, 2, 3, 4, 5, 6, 7, 42)<<std::endl;
    return 0;
}

// CHECK: 0 1
// CHECK-NEXT: 0 1 2 3 4 5 6 7 42
// CHECK-NEXT: 42
