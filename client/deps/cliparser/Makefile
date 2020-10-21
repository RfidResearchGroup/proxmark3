MYSRCPATHS =
MYINCLUDES = -I../../../common -I../../../include -I../../src
MYCFLAGS = -Wno-cast-align
MYDEFS =
MYSRCS = \
	argtable3.c \
	cliparser.c

LIB_A = libcliparser.a

include ../../../Makefile.host

$(info PLATFORM $(platform))
ifneq (,$(findstring MINGW,$(platform)))
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    # FTR __USE_MINGW_ANSI_STDIO seems deprecated in Mingw32
    # but not Mingw64 https://fr.osdn.net/projects/mingw/lists/archive/users/2019-January/000199.html
    CFLAGS += -D_ISOC99_SOURCE
endif
