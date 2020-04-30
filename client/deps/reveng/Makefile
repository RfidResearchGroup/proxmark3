# reveng will compile without macros, but these may be useful:
# Add -DBMPMACRO to use bitmap size constant macros (edit config.h)
# Add -DNOFORCE  to disable the -F switch
# Add -DPRESETS  to compile with preset models (edit config.h)

MYSRCPATHS =
MYINCLUDES = -I../cliparser
MYCFLAGS =
MYDEFS = -DPRESETS
MYSRCS = \
	bmpbit.c \
	cli.c \
	model.c \
	poly.c \
	preset.c \
	reveng.c

LIB_A = libreveng.a

# Transition: remove old directories and objects
MYCLEANOLDPATH = ../../reveng

include ../../../Makefile.host

ifneq ($(SKIPREVENGTEST),1)
CLEAN += bmptst

$(BINDIR)/$(LIB_A): $(BINDIR)/bmptst

$(BINDIR)/bmptst: bmpbit.c config.h reveng.h
	$(info [-] CC $<)
	$(Q)$(CC) $(CFLAGS) -DBMPTST -o $@ $<
	$(info [=] TEST $@)
	$(Q)( ./$@ && $(TOUCH) $@ ) || ( $(RM) $@ && $(FALSE) )
endif

.PHONY: all clean
