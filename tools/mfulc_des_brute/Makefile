MYCFLAGS = -D_GNU_SOURCE -O3 -Wno-deprecated-declarations
MYLDLIBS = -lcrypto -lpthread

BINS = mfulc_des_brute
INSTALLTOOLS = $(BINS)

include ../../Makefile.host

# checking platform can be done only after Makefile.host
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    MYCFLAGS += -D_ISOC99_SOURCE
endif

# OS X needs linking to openssl
ifeq ($(USE_BREW),1)
    MYCFLAGS += -I$(BREW_PREFIX)/opt/openssl@3/include -I$(BREW_PREFIX)/opt/openssl@3.6/include
    MYLDFLAGS += -L$(BREW_PREFIX)/opt/openssl@3/lib -L$(BREW_PREFIX)/opt/openssl@3.6/lib
endif

ifeq ($(USE_MACPORTS),1)
    MYCFLAGS += -I$(MACPORTS_PREFIX)/include/openssl-3 -I$(MACPORTS_PREFIX)/include/openssl-1.1
    MYLDFLAGS += -L$(MACPORTS_PREFIX)/lib/openssl-3 -L$(MACPORTS_PREFIX)/lib/openssl-1.1
endif

mfulc_des_brute : $(OBJDIR)/mfulc_des_brute.o $(MYOBJS)
