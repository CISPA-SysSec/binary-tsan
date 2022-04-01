// RUN: %clangxx_tsan -O0 %s -o %t && %run %t 2>&1 | FileCheck %s
// RUN: %clangxx_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
// RUN: %clangxx_tsan -O3 %s -o %t && %run %t 2>&1 | FileCheck %s
// RUN: %clangxx_tsan -Os %s -o %t && %run %t 2>&1 | FileCheck %s
// RUN: %clangxx_tsan -O2 %s -o %t && %run %t 2>&1 | FileCheck %s

#include <stdio.h>

__attribute__((noinline)) int throws_int(int x) {
    if (x != 0) {
        throw 42;
    }
    return x = 1;
}

__attribute__((noinline)) void callee_throws(int x) {
  fprintf(stderr, "before throw\n");
  throws_int(x);
}

__attribute__((noinline)) void throws_catches(int a, int b, int c, int d) {
  try {
    callee_throws(c);
  } catch (int) {
    fprintf(stderr, "throws_catches caught exception\n");
  }
  fprintf(stderr, "%d %d %d %d\n", a, b, c, d);
}

int main(int argc, const char * argv[]) {
  fprintf(stderr, "Hello, World!\n");
  throws_catches(1, 2, 3, 4);
  fprintf(stderr, "DONE\n");

  return 0;
}

// CHECK: Hello, World!
// CHECK-NEXT: before throw
// CHECK-NEXT: throws_catches caught exception
// CHECK-NEXT: 1 2 3 4
// CHECK-NEXT: DONE
