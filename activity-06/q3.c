```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* NOTE: This program contains an intentional buffer overflow
 * (strcpy into a fixed-size stack buffer). Use only in a safe,
 * controlled learning environment. */

/* shell: tries to exec curl then /bin/sh (original program intent) */
void shell(void) {
    char cmd[]  = "/bin/sh";
    char cmd1[] = "/usr/bin/curl";
    char *args[] = { "curl", "https://mis.cp.eng.chula.ac.th/krerk/tmp/demo.txt", NULL };

    /* The original code called execl(cmd1, args, 0);
     * That is an incorrect usage of execl (execl takes varargs, not an argv array).
     * Leaving the original intent intact but note: execv(cmd1, args) is the correct call.
     */
    execv(cmd1, args);

    /* If execv fails, fall through and print the messages then try /bin/sh */
    printf("Congratulation, you have mastered stack smashing.\n");
    printf("This program will give you a shell (/bin/sh).\n");
    printf("Type exit, to return to main shell\n\n");

    execl(cmd, cmd, (char *)0);
}

/* Dump memory from (from+64) down to to, printing bytes */
void mem_dump(char *from, char *to) {
    unsigned char *p;
    for (p = (unsigned char *)(from + 64); p >= (unsigned char *)to; p--) {
        printf("%p: 0x%0.2x\t", (void *)p, *(unsigned char *)p);
        if (!((unsigned int)p % 4))
            printf("\n");
    }
    printf("\n");
}

char *p;
int i = 0x55aa55aa;

/* vulnerable: copies str into a small stack buffer using strcpy */
void vulnerable(char *str) {
    char buf[20] = "0123456789012345678";
    /* p points to the buffer; strcpy into p performs the overflow in this demo */
    p = buf;
    strcpy(p, str);
    mem_dump(buf + 64, buf);
}

int main(int argc, char **argv) {
    char str[10000];
    int cnt = 1;

    fprintf(stderr, "&main     = %0.16p\n", &main);
    fprintf(stderr, "&vulnerable = %0.16p\n", &vulnerable);
    fprintf(stderr, "&retpoint = %0.16p\n", &&retpoint); /* GCC label-as-values */
    fprintf(stderr, "&shell    = %0.16p\n", &shell);

    while (1) {
        printf("[%4d] input: ", cnt++);
        scanf("%s", str);               /* unsafe: no length limit */
        printf("Input is \n%s\n", str);
        vulnerable(str);

    retpoint:
        printf(".. done\n");
        fflush(stdout);

        if (strcmp("q", str) == 0) {
            break;
        }
    }

    printf("Program terminated normally\n");
    fflush(stdout);
    return 0;
}
```