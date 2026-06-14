ROOTPATH = ../../..
MYSRCPATHS = $(ROOTPATH)/common $(ROOTPATH)/common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c iso14443crc.c sleep.c util_posix.c
MYINCLUDES = -I$(ROOTPATH)/include -I$(ROOTPATH)/common
MYCFLAGS = -O3
MYDEFS =
MYLDLIBS =
ifneq ($(SKIPPTHREAD),1)
MYLDLIBS += -lpthread
endif

BINS = mfkey32 mfkey32v2 mfkey32nested mfkey64 mf_nonce_brute mf_trace_brute
INSTALLTOOLS = $(BINS)

include $(ROOTPATH)/Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

# clang doesn't like these compiler params
ifneq ($(DETECTED_COMPILER), clang)
    MYCFLAGS += --param max-completely-peeled-insns=1000 --param max-completely-peel-times=10000
endif

mfkey32 : $(OBJDIR)/mfkey32.o $(MYOBJS)
mfkey32v2 : $(OBJDIR)/mfkey32v2.o $(MYOBJS)
mfkey32nested : $(OBJDIR)/mfkey32nested.o $(MYOBJS)
mfkey64 : $(OBJDIR)/mfkey64.o $(MYOBJS)
mf_nonce_brute : $(OBJDIR)/mf_nonce_brute.o $(MYOBJS)
mf_trace_brute : $(OBJDIR)/mf_trace_brute.o $(MYOBJS)
