
LIB_A = tinycbor.a
tinycbor_SOURCES = \
    cborencoder.c \
    cborencoder_close_container_checked.c \
    cborerrorstrings.c \
    cborparser.c \
    cborparser_dup_string.c \
    cborpretty.c \
    cbortojson.c \
    cborvalidation.c \

CFILES = $(filter %.c, $(tinycbor_SOURCES))
CMDOBJS = $(CFILES:%.c=%.o)
CLEAN = $(CMDOBJS)

CC= gcc
CFLAGS= -O2 -Wall -Wno-unused-variable -Wno-unused-function
LIBS=  $(SYSLIBS) $(MYLIBS)
DEFAULT_INCLUDES = -I. -I..
DEFS = -DHAVE_STDINT_H

AR= ar rcs
RANLIB= ranlib
RM= rm -f
TST= echo

SYSLDFLAGS=
SYSLIBS=

MYLIBS=
MYOBJS=

$(LIB_A): $(CMDOBJS)
	$(AR) $(LIB_A) $(CMDOBJS)
	$(RANLIB) $(LIB_A)

all: $(LIB_A)

clean:
	$(RM) $(CLEAN)
	$(RM) $(LIB_A)

%.o: %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(CFLAGS) -c -o $@ $< $(LIBS)

.PHONY: all clean

