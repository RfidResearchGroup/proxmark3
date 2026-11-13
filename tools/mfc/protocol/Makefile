ROOTPATH = ../../..
MYSRCPATHS = $(ROOTPATH)/common $(ROOTPATH)/common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c
MYINCLUDES = -I$(ROOTPATH)/include -I$(ROOTPATH)/common
MYCFLAGS = -O3 -Wno-inline
MYDEFS =
MYLDLIBS =
# crapto1.c needs pthread support
ifneq ($(SKIPPTHREAD),1)
MYLDLIBS += -lpthread
endif

BINS = mfc-protocol-demo
INSTALLTOOLS = $(BINS)

include $(ROOTPATH)/Makefile.host

mfc-protocol-demo: $(OBJDIR)/mfc-protocol-demo.o $(MYOBJS)
