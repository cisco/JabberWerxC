#include <stdio.h>

int main (int argc, char **argv)
{
    printf("%zd", sizeof(void *) * 8);
    return 0;
}
