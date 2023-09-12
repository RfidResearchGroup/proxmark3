MYSRCPATHS = ../../common ../../common/cryptorf
MYSRCS = cryptolib.c util.c
MYINCLUDES = -I../../common/cryptorf
MYCFLAGS =
MYDEFS =

# Atomic
# RPi Zero gcc requires -latomic
# but MacOSX /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
# doesn't recognize option --as-needed
ifneq ($(platform),Darwin)
    MYLDLIBS += -lpthread -Wl,--as-needed -latomic -Wl,--no-as-needed
endif

BINS = cm sm sma sma_multi
INSTALLTOOLS = $(BINS)

platform = $(shell uname)

ifeq ($(platform),Darwin)
CXXFLAGS = -std=c++14
endif

include ../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    CFLAGS += -D_ISOC99_SOURCE
endif

cm : $(OBJDIR)/cm.o $(MYOBJS)
sm : $(OBJDIR)/sm.o $(MYOBJS)
sma : $(OBJDIR)/sma.o $(MYOBJS)
sma_multi : $(OBJDIR)/sma_multi.o $(MYOBJS)
