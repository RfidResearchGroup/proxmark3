MYSRCPATHS = ../../common ../../common/crapto1
MYSRCS = crypto1.c crapto1.c bucketsort.c
MYINCLUDES = -I../../include -I../../common
MYCFLAGS = -O3
MYDEFS =

BINS = rf08s_nested rf08s_nested_known rf08s_nested_known_collision rf08s_nested_known_match

INSTALLTOOLS = $(BINS)

include ../../Makefile.host

# rf08s_nested.c needs pthread support.  Older glibc needs it externally
ifneq ($(SKIPPTHREAD),1)
    MYLDLIBS += -lpthread
endif

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

rf08s_nested : $(OBJDIR)/rf08s_nested.o $(MYOBJS)
rf08s_nested_known : $(OBJDIR)/rf08s_nested_known.o $(MYOBJS)
rf08s_nested_known_collision : $(OBJDIR)/rf08s_nested_known_collision.o $(MYOBJS)
rf08s_nested_known_match : $(OBJDIR)/rf08s_nested_known_match.o $(MYOBJS)
