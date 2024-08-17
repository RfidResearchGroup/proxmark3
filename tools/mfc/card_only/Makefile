ROOTPATH = ../../..
MYSRCPATHS = $(ROOTPATH)/common $(ROOTPATH)/common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c nested_util.c
MYINCLUDES = -I$(ROOTPATH)/include -I$(ROOTPATH)/common
MYCFLAGS = -O3
MYDEFS =

BINS = nonce2key staticnested_0nt staticnested_1nt staticnested_2nt staticnested_2x1nt_rf08s_1key staticnested_2x1nt_rf08s

INSTALLTOOLS = $(BINS)

include $(ROOTPATH)/Makefile.host

# nested_util.c needs pthread support.  Older glibc needs it externally
ifneq ($(SKIPPTHREAD),1)
    MYLDLIBS += -lpthread
endif

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

nonce2key : $(OBJDIR)/nonce2key.o $(MYOBJS)
staticnested_0nt : $(OBJDIR)/staticnested_0nt.o $(MYOBJS)
staticnested_1nt : $(OBJDIR)/staticnested_1nt.o $(MYOBJS)
staticnested_2nt : $(OBJDIR)/staticnested_2nt.o $(MYOBJS)
staticnested_2x1nt_rf08s_1key : $(OBJDIR)/staticnested_2x1nt_rf08s_1key.o $(MYOBJS)
staticnested_2x1nt_rf08s : $(OBJDIR)/staticnested_2x1nt_rf08s.o $(MYOBJS)
