MYSRCPATHS = ../../common ../../common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c nested_util.c
MYINCLUDES = -I../../include -I../../common
MYCFLAGS = -O3
MYDEFS =

BINS = mfkey32 mfkey32v2 mfkey64 staticnested
INSTALLTOOLS = $(BINS)

include ../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

# macOS doesn't like these compiler params
ifneq ($(platform),Darwin)
    MYCFLAGS += --param max-completely-peeled-insns=1000 --param max-completely-peel-times=10000
endif

mfkey32 : $(OBJDIR)/mfkey32.o $(MYOBJS)
mfkey32v2 : $(OBJDIR)/mfkey32v2.o $(MYOBJS)
mfkey64 : $(OBJDIR)/mfkey64.o $(MYOBJS)
staticnested : $(OBJDIR)/staticnested.o $(MYOBJS)
