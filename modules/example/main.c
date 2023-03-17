#include "calc.h"
#include<stdio.h>

int main()
{
    int a = 1;
    int b = 2;
    printf("add(%d,%d)=%d\n", a,b,add(a,b));
    printf("sub(%d,%d)=%d\n", a,b,sub(a,b));
    printf("mul(%d,%d)=%d\n", a,b,mul(a,b));
    printf("div(%d,%d)=%f\n", a,b,div(a,b));
    
    return 0;
}
