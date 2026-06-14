MYSRCPATHS =
MYINCLUDES = -I.
# Lua lib requires GNU extensions (implicit declarations of functions): -std=gnu99 or -std=gnu11
MYCFLAGS = -Wno-cast-align -Wno-bad-function-cast -Wno-switch-enum
MYDEFS = -DLUA_COMPAT_ALL $(SYSCFLAGS)
MYSRCS = lapi.c lauxlib.c lbaselib.c lcode.c lcorolib.c lctype.c ldblib.c ldebug.c ldo.c ldump.c \
	 lfunc.c lgc.c linit.c liolib.c llex.c lmathlib.c lmem.c loadlib.c lobject.c lopcodes.c \
	 loslib.c lparser.c lstate.c lstring.c lstrlib.c ltable.c ltablib.c ltm.c lundump.c \
	 lutf8lib.c lvm.c lzio.c

SYSCFLAGS=

LIB_A= liblua.a

# Transition: remove old directories and objects
MYCLEANOLDPATH = ../../liblua

# Your platform. See PLATS for possible values.
PLAT= none

PLATS= aix ansi bsd freebsd generic linux macosx mingw posix solaris

default: $(PLAT)

include ../../../Makefile.host

# Convenience targets for popular platforms
ALL= all

none:
	@echo "Please do 'make PLATFORM' where PLATFORM is one of these:"
	@echo "   $(PLATS)"

aix:
	$(Q)$(MAKE) $(ALL) CC="xlc" CFLAGS="-O2 -DLUA_USE_POSIX -DLUA_USE_DLOPEN"

ansi:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_ANSI"

bsd:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_POSIX -DLUA_USE_DLOPEN"

freebsd:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_LINUX"

generic: $(ALL)

linux:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_LINUX"

macosx:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_MACOSX"

mingw:
	$(Q)$(MAKE) $(ALL)

posix:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_POSIX"

solaris:
	$(Q)$(MAKE) $(ALL) SYSCFLAGS="-DLUA_USE_POSIX -DLUA_USE_DLOPEN -D_REENTRANT"

.PHONY: all $(PLATS) default clean depend none
