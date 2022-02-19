// RUN: %gcc_tsan --std=c11 -O1 %s -o %t

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) const char *getStr(int i)
{
    if (i == 0) return "first test 0";
    return "second test 1";
}

int main()
{
  int res = strlen (getStr(1));
  printf("%d\n", res);
  return res;
}

