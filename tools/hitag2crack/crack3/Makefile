MYSRCPATHS = ../common
MYSRCS = ht2crackutils.c hitagcrypto.c
MYINCLUDES =-I ../common
MYCFLAGS = -D_GNU_SOURCE
MYDEFS =
MYLDLIBS = -lpthread

BINS = ht2crack3 ht2crack3test
INSTALLTOOLS = $(BINS)

include ../../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

ht2crack3 : $(OBJDIR)/ht2crack3.o $(MYOBJS)
ht2crack3test : $(OBJDIR)/ht2crack3test.o $(MYOBJS)
