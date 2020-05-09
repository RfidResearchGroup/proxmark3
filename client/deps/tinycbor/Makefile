MYSRCPATHS =
MYINCLUDES =
# Strange errors on Mingw when compiling with C99
MYCFLAGS = -Wno-bad-function-cast -Wno-incompatible-pointer-types-discards-qualifiers
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

# Transition: remove old directories and objects
MYCLEANOLDPATH = ../../tinycbor

# Strange errors on Mingw when compiling with -O3
CFLAGS ?= -Wall -Werror -O2

include ../../../Makefile.host
