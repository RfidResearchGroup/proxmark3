ROOTPATH = ../../..
MYSRCPATHS = $(ROOTPATH)/common $(ROOTPATH)/common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c
MYINCLUDES = -I$(ROOTPATH)/include -I$(ROOTPATH)/common
MYCFLAGS = -O3 -Wno-inline
MYDEFS =
MYLDLIBS =

BINS = mfc-protocol-demo
INSTALLTOOLS = $(BINS)

include $(ROOTPATH)/Makefile.host

mfc-protocol-demo: $(OBJDIR)/mfc-protocol-demo.o $(MYOBJS)
