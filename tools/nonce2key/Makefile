MYSRCPATHS = ../../common ../../common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c
MYINCLUDES = -I../../include -I../../common
MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
MYDEFS =

BINS = nonce2key
INSTALLTOOLS = $(BINS)

include ../../Makefile.host

nonce2key : $(OBJDIR)/nonce2key.o $(MYOBJS)
