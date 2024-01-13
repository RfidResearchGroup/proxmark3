MYSRCPATHS = ../../common ../../common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c iso14443crc.c sleep.c util_posix.c
MYINCLUDES = -I../../include -I../../common
MYCFLAGS = -O3
MYDEFS =
MYLDLIBS =
ifneq ($(SKIPPTHREAD),1)
MYLDLIBS += -lpthread
endif

BINS = mf_nonce_brute mf_trace_brute
INSTALLTOOLS = $(BINS)

include ../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

mf_nonce_brute : $(OBJDIR)/mf_nonce_brute.o $(MYOBJS)

mf_trace_brute : $(OBJDIR)/mf_trace_brute.o $(MYOBJS)
