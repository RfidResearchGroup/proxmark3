MYSRCPATHS = ../../common ../../common/mbedtls
MYSRCS = util_posix.c
MYINCLUDES =  -I../../include -I../../common -I../../common/mbedtls
MYCFLAGS = -march=native -Ofast -msse2 -msse -maes
MYDEFS =
MYLDLIBS = -lcrypto

ifneq ($(SKIPPTHREAD),1)
    MYLDLIBS += -lpthread
endif

BINS = brute_key mfd_aes_brute
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
    MYLDFLAGS += -L$(BREW_PREFIX)/opt/openssl@3/lib -L$(BREW_PREFIX)/opt/openssl@1.1/lib
endif

ifeq ($(USE_MACPORTS),1)
    MYLDFLAGS += -L$(MACPORTS_PREFIX)/lib/openssl-3 -L$(MACPORTS_PREFIX)/lib/openssl-1.1
endif

brute_key : $(OBJDIR)/brute_key.o $(MYOBJS)

mfd_aes_brute : $(OBJDIR)/mfd_aes_brute.o $(MYOBJS)
