#include <stdio.h>

/* Prototype function */
void myfunction (int i);

char *p;

int main() {
    printf("&main = %p\n", &main);
    printf("&myfunction = %p\n", &myfunction);
    printf("&&ret_addr = %p\n", &&ret_addr);
    myfunction(12);
ret_addr:
    printf("... end\n");
}

void myfunction (int i) {
    char buf[20] = "0123456789012345678";
    printf("&i = %p\n", &i);
    printf("sizeof(pointer) is %lu\n", sizeof(p));
    printf("&buf[0] = %p\n", buf);
    for (p = ((char *) &i) + 64; p > buf; p--) {
        printf("%p: 0x%02x\t", p, *(unsigned char*) p);
        if (!((unsigned long)p % 4))
            printf("\n");
    }
    printf("\n");
}
