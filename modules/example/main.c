#include "calc.h"
#include<stdio.h>

int main()
{
    int a = 1;
    int b = 2;
    printf("add(%d,%d)=%d\n", a, b, myadd(a,b));
    printf("sub(%d,%d)=%d\n", a, b, mysub(a,b));
    printf("mul(%d,%d)=%d\n", a, b, mymul(a,b));
    printf("div(%d,%d)=%f\n", a, b, mydiv(a,b));

    return 0;
}
