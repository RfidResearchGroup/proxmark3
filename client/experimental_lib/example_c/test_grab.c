#include "pm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

    int pipefd[2];
    char buf[8196 + 1];
    size_t n;

    if (pipe(pipefd) == -1) {
        exit(-1);
    }

    int pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(-1);
    }

    // child
    if (pid == 0) {
        printf("[INFO] inside child\n");

        // Redirect stdout to the write end of the pipe
        dup2(pipefd[1], STDOUT_FILENO);

        close(pipefd[0]);  // Child: close read end of the pipe
        close(pipefd[1]);  // Close original write end

        pm3 *p;
        p = pm3_open("/dev/ttyS9");
        //printf("Device: %s\n", pm3_name_get(p));

        // Execute the command
        pm3_console(p, "hw status");
        pm3_close(p);
        _exit(-1);
    } else {

        printf("[INFO] inside parent\n");
        // Parent: close write end of the pipe
        close(pipefd[1]);

        // Read from the pipe
        while (1) {
            n = read(pipefd[0], buf, sizeof(buf));
            if (n == -1) {
                continue;
            }
            if (n == 0) {
                break;
            } else {
                // null termination
                buf[n] = 0;
                if (strstr(buf, "Unique ID") != NULL) {
                    printf("%s", buf);
                }
            }
        }

        // Close read end
        close(pipefd[0]);
    }
}
