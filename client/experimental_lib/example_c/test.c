#include <stdio.h>
#include <stdlib.h>
#include "pm3.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(-1);
    }
    pm3 *p;
    p = pm3_open(argv[1]);
    pm3_console(p, "hw status", true);
    pm3_close(p);
}
