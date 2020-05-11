MYSRCPATHS =
MYINCLUDES =
# Strange errors on Mingw when compiling with C99
MYCFLAGS = -Wno-bad-function-cast -Wno-redundant-decls -Wno-incompatible-pointer-types-discards-qualifiers -Wno-discarded-qualifiers -Wno-unknown-warning-option -Wno-maybe-uninitialized
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

include ../../../Makefile.host
