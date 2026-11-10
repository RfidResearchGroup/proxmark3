#!/usr/bin/env python3
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Exercise script directory listing with real directories and long paths."""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

PREAMBLE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "pm3_cmd.h"
#define _GREEN_(s) s
#define NOLF ""
#define PrintAndLogEx(level, ...) test_log(__VA_ARGS__)
static char output[65536], previous_path[8192];
static size_t output_len, outstanding, scan_calls, longest_path;
static bool fail_malloc;
static void test_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(output + output_len, sizeof(output) - output_len, format, args);
    va_end(args);
    assert(n >= 0 && (size_t)n < sizeof(output) - output_len);
    output_len += n;
}
static int test_scandir(const char *path, struct dirent ***list,
                        int (*filter)(const struct dirent *),
                        int (*compare)(const struct dirent **, const struct dirent **)) {
    assert(scan_calls == 0 || strcmp(previous_path, path) != 0);
    assert(strlen(path) < sizeof(previous_path));
    strcpy(previous_path, path);
    scan_calls++;
    int n = scandir(path, list, filter, compare);
    if (n >= 0) outstanding += n + 1;
    return n;
}
void *test_malloc(size_t size) {
    if (fail_malloc) return NULL;
    void *p = malloc(size);
    if (p != NULL) outstanding++;
    return p;
}
static void test_free(void *p) {
    assert(p != NULL && outstanding > 0);
    outstanding--;
    free(p);
}
static bool str_endswith(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}
'''

WRAPPERS = r'''
static bool test_is_directory(const char *path) {
    size_t len = strlen(path);
    if (len > longest_path) longest_path = len;
    return path_is_directory(path);
}
#define scandir test_scandir
#define malloc test_malloc
#define free test_free
#define path_is_directory test_is_directory
'''

TEST = r'''
#undef scandir
#undef malloc
#undef free
#undef path_is_directory
static void reset(void) {
    assert(outstanding == 0);
    output_len = scan_calls = longest_path = 0;
    output[0] = previous_path[0] = '\0';
    fail_malloc = false;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    (void)test_malloc;
    const char *long_root = argv[1], *basic_root = argv[2];
    assert(strlen(long_root) == 1023);
    assert(filelist(long_root, NULL, 0, false, 0, 0) == PM3_SUCCESS);
    assert(longest_path >= strlen(long_root) + strlen("child"));
    char child[8192];
    assert(snprintf(child, sizeof(child), "%schild", long_root) < (int)sizeof(child));
    bool child_readable = path_is_directory(child);
    assert(scan_calls == (child_readable ? 2 : 1));
    if (child_readable) assert(strstr(output, "long.lua") != NULL);
    reset();

    assert(filelist(basic_root, ".lua", 0, false, 0, 0) == PM3_SUCCESS);
    assert(strstr(output, "alpha.lua") != NULL);
    assert(strstr(output, "inside.lua") != NULL);
    assert(strstr(output, "beta.cmd") == NULL);
    assert(strstr(output, "link.lua") != NULL);
    const char *inside = strstr(output, "inside.lua");
    assert(strstr(inside + 1, "inside.lua") == NULL);
    assert(scan_calls == 2);
    reset();

    assert(filelist(basic_root, NULL, 0, false, 0, 0) == PM3_SUCCESS);
    const char *alpha = strstr(output, "alpha.lua"), *beta = strstr(output, "beta.cmd");
    assert(alpha != NULL && beta != NULL && alpha < beta);
    reset();

    fail_malloc = true;
    assert(filelist(basic_root, NULL, 0, false, 0, 0) == PM3_EMALLOC);
    assert(strstr(output, "Failed to allocate memory") != NULL);
    reset();

    assert(filelist("filelist-does-not-exist/", NULL, 0, true, 0, 0) == PM3_EFILE);
    assert(output_len == 0);
    reset();
    assert(filelist("filelist-does-not-exist/", NULL, 0, false, 0, 0) == PM3_EFILE);
    assert(strstr(output, "filelist-does-not-exist/") != NULL);
    reset();
    puts("File listing tests: OK");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, help="fileutils source for negative controls")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = (args.source or root / "client/src/fileutils.c").read_text()
    start = source.index("bool path_is_directory(")
    end = source.index("\nbool path_is_regular_file(", start)
    directory_check = source[start:end]
    start = source.index("static int filelist(")
    end = source.index("\nint searchAndList(", start)
    listing = source[start:end]
    with tempfile.TemporaryDirectory(prefix="filelist-test-", dir=os.path.realpath(tempfile.gettempdir())) as directory:
        fixture = Path(directory)
        basic = fixture / "basic"
        basic.mkdir()
        (basic / "alpha.lua").touch()
        (basic / "beta.cmd").touch()
        (basic / "folder").mkdir()
        (basic / "folder/inside.lua").touch()
        (basic / "link.lua").symlink_to("folder", target_is_directory=True)

        parent = fixture / "long"
        parent.mkdir()
        while len(os.fsencode(parent)) < 1022:
            remaining = 1022 - len(os.fsencode(parent))
            size = min(180, remaining - 1)
            if remaining - size - 1 == 1:
                size -= 1
            parent /= "d" * size
            parent.mkdir()
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.mkdir("child", dir_fd=fd)
            child_fd = os.open("child", os.O_RDONLY, dir_fd=fd)
            try:
                leaf_fd = os.open("long.lua", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=child_fd)
                os.close(leaf_fd)
            finally:
                os.close(child_fd)
        finally:
            os.close(fd)

        executable = fixture / "filelist"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c99", "-O2", "-Wall", "-Werror", "-I", str(root / "include"),
            "-x", "c", "-", "-o", str(executable),
        ]
        subprocess.run(command, input=PREAMBLE + directory_check + WRAPPERS + listing + TEST,
                       text=True, check=True)
        subprocess.run([str(executable), str(parent) + "/", str(basic) + "/"], check=True)


if __name__ == "__main__":
    main()
