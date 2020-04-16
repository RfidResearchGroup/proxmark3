MYSRCPATHS =
MYINCLUDES =
# Strange errors on Mingw when compiling with C99
#MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
MYCFLAGS =
MYDEFS =
MYSRCS = \
    cborencoder.c \
    cborencoder_close_container_checked.c \
    cborerrorstrings.c \
    cborparser.c \
    cborparser_dup_string.c \
    cborpretty.c \
    cbortojson.c \
    cborvalidation.c \

LIB_A = tinycbor.a

# Strange errors on Mingw when compiling with -O3
CFLAGS ?= -Wall -Werror -O2

include ../../../Makefile.host
