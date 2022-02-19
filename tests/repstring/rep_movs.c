// RUN: %gcc_tsan --std=c11 -Os %s -o %t

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char data[100];
    const char* str = "this is a test";
    memcpy(data, str, strlen(str));
    printf("%s\n", data);
    return 0;
}

// CHECK: this is a test
