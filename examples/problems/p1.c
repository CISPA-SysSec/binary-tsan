#include <iostream>
#include <stdlib.h>

int *t;

int
chk(int x, int y)
{
        int i;
        int r = 0;

        for (i=0; i<4; i++) {
                r = r + t[x + 8*i];
        }
        return r;
}

int
main()
{
        t = (int*)calloc(64, sizeof(int));
        chk(0, 0);
        return 0;
}

