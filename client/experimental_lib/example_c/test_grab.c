#include "pm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

//    char buf[8196 + 1];
    size_t n;

    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(-1);
    }

    pm3 *p;
    p = pm3_open(argv[1]);

    // Execute the command
    pm3_console(p, "hw status", false);

    const char *buf = pm3_grabbed_output_get(p);
    const char *line_start = buf;
    const char *newline_pos;
    while ((newline_pos = strchr(line_start, '\n')) != NULL) {
        // Determine the length of the line
        size_t line_length = newline_pos - line_start;

        // Create a temporary buffer to hold the line
        char line[line_length + 1];
        strncpy(line, line_start, line_length);
        line[line_length] = '\0'; // Null-terminate the string

        if (strstr(line, "ERROR") != NULL) {
            printf("%s", line);
        }
        if (strstr(line, "Unique ID") != NULL) {
            printf("%s", line);
        }

        // Move to the next line
        line_start = newline_pos + 1;
    }


    pm3_close(p);
}
