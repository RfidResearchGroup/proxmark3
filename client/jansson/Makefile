
include_HEADERS = jansson.h
nodist_include_HEADERS = jansson_config.h

LIB_A = libjansson.a
libjansson_la_SOURCES = \
	dump.c \
	error.c \
	hashtable.c \
	hashtable.h \
	hashtable_seed.c \
	jansson_private.h \
	load.c \
	lookup3.h \
	memory.c \
	pack_unpack.c \
	strbuffer.c \
	strbuffer.h \
	strconv.c \
	utf.c \
	utf.h \
	path.c \
	value.c
libjansson_la_LDFLAGS = \
	-no-undefined \
	-export-symbols-regex '^json_' \
	-version-info 15:0:11


CFILES = $(filter %.c, $(libjansson_la_SOURCES))
CMDOBJS = $(CFILES:%.c=%.o)
CLEAN = $(CMDOBJS)

CC= gcc
CFLAGS= -O2 -Wall -Wno-unused-variable -Wno-unused-function -Wno-format-truncation
LDFLAGS= $(SYSLDFLAGS) $(libjansson_la_LDFLAGS)
LIBS= $(SYSLIBS) $(MYLIBS)
DEFAULT_INCLUDES = -I.
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

