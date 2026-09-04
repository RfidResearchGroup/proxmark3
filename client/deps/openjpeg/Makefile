MYSRCPATHS =
MYINCLUDES =
# Third party code, don't fail the build on upstream's warnings
MYCFLAGS = -w -O3
# Avoid __declspec(dllimport/dllexport) on Windows, we always link this in statically
MYDEFS = -DOPJ_STATIC
MYSRCS = \
    bio.c \
    cio.c \
    dwt.c \
    event.c \
    function_list.c \
    ht_dec.c \
    image.c \
    invert.c \
    j2k.c \
    jp2.c \
    mct.c \
    mqc.c \
    openjpeg.c \
    opj_clock.c \
    opj_malloc.c \
    pi.c \
    sparse_array.c \
    t1.c \
    t2.c \
    tcd.c \
    tgt.c \
    thread.c \

LIB_A = openjpeg.a

include ../../../Makefile.host
