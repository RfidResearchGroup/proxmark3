MYSRCPATHS = ../../common ../../common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c
MYINCLUDES = -I../../include -I../../common
MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
MYDEFS =

BINS = mfkey32 mfkey32v2 mfkey64
INSTALLTOOLS = $(BINS)

include ../../Makefile.host

mfkey32 : $(OBJDIR)/mfkey32.o $(MYOBJS)
mfkey32v2 : $(OBJDIR)/mfkey32v2.o $(MYOBJS)
mfkey64 : $(OBJDIR)/mfkey64.o $(MYOBJS)
