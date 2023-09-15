MYSRCPATHS = ../../common ../../common/cryptorf
MYSRCS = cryptolib.c util.c
MYINCLUDES = -I../../common/cryptorf
MYCFLAGS =
MYDEFS =

platform = $(shell uname)

# Atomic
# RPi Zero gcc requires -latomic
ifneq ($(platform),Darwin)
    MYLDLIBS += -lpthread
endif

BINS = cm sm sma sma_multi
INSTALLTOOLS = $(BINS)

ifeq ($(platform),Darwin)
    MYCXXFLAGS = -std=c++14
endif

include ../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    MYCFLAGS += -D_ISOC99_SOURCE
endif

cm : $(OBJDIR)/cm.o $(MYOBJS)
sm : $(OBJDIR)/sm.o $(MYOBJS)
sma : $(OBJDIR)/sma.o $(MYOBJS)
sma_multi : $(OBJDIR)/sma_multi.o $(MYOBJS)
