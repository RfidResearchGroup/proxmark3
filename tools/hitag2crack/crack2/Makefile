MYSRCPATHS = ../common
MYSRCS = ht2crackutils.c hitagcrypto.c
MYINCLUDES =-I ../common
MYCFLAGS = -D_GNU_SOURCE
MYDEFS =
MYLDLIBS = -lpthread

BINS = ht2crack2buildtable ht2crack2search ht2crack2gentest ht2crack2search_multi
INSTALLTOOLS = $(BINS)

include ../../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

ht2crack2buildtable : $(OBJDIR)/ht2crack2buildtable.o $(MYOBJS)
ht2crack2search : $(OBJDIR)/ht2crack2search.o $(MYOBJS)
ht2crack2gentest : $(OBJDIR)/ht2crack2gentest.o $(MYOBJS)
ht2crack2search_multi : $(OBJDIR)/ht2crack2search_multi.o $(MYOBJS)
