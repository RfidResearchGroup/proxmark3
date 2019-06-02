# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

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
	$(info [=] AR $@)
	$(Q)$(AR) $(LIB_A) $(CMDOBJS)
	$(Q)$(RANLIB) $(LIB_A)

all: $(LIB_A)

clean:
	$(Q)$(RM) $(CLEAN)
	$(Q)$(RM) $(LIB_A)

%.o: %.c
	$(info [-] CC $<)
	$(Q)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(CFLAGS) -c -o $@ $< $(LIBS)

.PHONY: all clean

