# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

CC = gcc
CXX = g++
LD = g++
RM = rm -f
MV = mv
CP = cp -a

platform = $(shell uname)

VPATH = ../../common/zlib
OBJDIR = obj

# RPi Zero gcc requires -latomic
# but MacOSX /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
# doesn't recognize option --as-needed
ifneq ($(platform),Darwin)
    LDLIBS += -Wl,--as-needed -latomic -Wl,--no-as-needed
endif

LIBS = -I../../common/zlib
INCLUDES_CLIENT = -I../../common_fpga $(LIBS)

CFLAGS += -std=c99 -D_ISOC99_SOURCE -DPRESETS $(INCLUDES_CLIENT) -Wall -Werror -g -O3

# Flags to generate temporary dependency files
DEPFLAGS = -MT $@ -MMD -MP -MF $(OBJDIR)/$*.Td
# make temporary to final dependency files after successful compilation
POSTCOMPILE = $(MV) -f $(OBJDIR)/$*.Td $(OBJDIR)/$*.d

ZLIBSRCS = deflate.c adler32.c trees.c zutil.c inflate.c inffast.c inftrees.c
ZLIBFLAGS = -DZ_SOLO -DZ_PREFIX -DNO_GZIP -DZLIB_PM3_TUNED
#-DDEBUG -Dverbose=1

ZLIBOBJS = $(ZLIBSRCS:%.c=$(OBJDIR)/%.o)

BINS = fpga_compress
CLEAN = $(BINS) $(DEPENDENCY_FILES) $(ZLIBOBJS) $(OBJDIR)/*.o
# OSX Brew is expecting fpga_compress in client folder, some workaround for now:
ifeq ($(platform),Darwin)
CLEAN += $(foreach bin,$(BINS),../../client/$(bin))
endif

# need to assign dependancies to build these first...
all: $(BINS)

all-static: LDLIBS:=-static $(LDLIBS)
all-static: $(BINS)

fpga_compress: $(OBJDIR)/fpga_compress.o $(ZLIBOBJS)
	$(info [=] LD $@)
	$(Q)$(LD) $(LDFLAGS) $(ZLIBFLAGS) $^ $(LDLIBS) -o $@
# OSX Brew is expecting fpga_compress in client folder, some workaround for now:
ifeq ($(platform),Darwin)
	$(Q)$(CP) $@ ../../client/
endif

clean:
	$(Q)$(RM) $(CLEAN)

.PHONY: all clean

%.o: %.c
$(OBJDIR)/%.o : %.c $(OBJDIR)/%.d
	$(info [-] CC $<)
	$(Q)$(CC) $(DEPFLAGS) $(CFLAGS) $(ZLIBFLAGS) -c -o $@ $<
	$(Q)$(POSTCOMPILE)

DEPENDENCY_FILES = $(patsubst %.c, $(OBJDIR)/%.d, $(ZLIBSRCS)) $(OBJDIR)/fpga_compress.d

$(DEPENDENCY_FILES): ;
.PRECIOUS: $(DEPENDENCY_FILES)

-include $(DEPENDENCY_FILES)

