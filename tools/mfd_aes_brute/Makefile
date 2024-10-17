MYSRCPATHS = ../../common ../../common/mbedtls
MYSRCS = util_posix.c randoms.c
MYINCLUDES =  -I../../include -I../../common -I../../common/mbedtls
MYCFLAGS = -Ofast
MYDEFS =
MYLDLIBS = -lcrypto

SUPPORT_MARCH := $(shell $(CC) -xc /dev/null -c -o /dev/null -march=native > /dev/null 2>/dev/null && echo y)
SUPPORT_MCPU := $(shell $(CC) -xc /dev/null -c -o /dev/null -mcpu=native > /dev/null 2>/dev/null && echo y)

ifeq ($(DONT_BUILD_NATIVE),y)
    # do nothing
else ifeq ($(SUPPORT_MARCH),y)
    MYCFLAGS += -march=native
else ifeq ($(SUPPORT_MCPU),y)
    MYCFLAGS += -mcpu=native
endif

ifneq ($(SKIPPTHREAD),1)
    MYLDLIBS += -lpthread
endif

BINS = brute_key mfd_aes_brute mfd_multi_brute
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
    MYCFLAGS += -I$(BREW_PREFIX)/opt/openssl@3/include -I$(BREW_PREFIX)/opt/openssl@1.1/include
    MYLDFLAGS += -L$(BREW_PREFIX)/opt/openssl@3/lib -L$(BREW_PREFIX)/opt/openssl@1.1/lib
endif

ifeq ($(USE_MACPORTS),1)
    MYCFLAGS += -I$(MACPORTS_PREFIX)/include/openssl-3 -I$(MACPORTS_PREFIX)/include/openssl-1.1
    MYLDFLAGS += -L$(MACPORTS_PREFIX)/lib/openssl-3 -L$(MACPORTS_PREFIX)/lib/openssl-1.1
endif

showinfo: $(info c flags: $(MYCFLAGS))

brute_key : $(OBJDIR)/brute_key.o $(MYOBJS)

mfd_aes_brute : $(OBJDIR)/mfd_aes_brute.o $(MYOBJS)

mfd_multi_brute : $(OBJDIR)/mfd_multi_brute.o $(MYOBJS)
