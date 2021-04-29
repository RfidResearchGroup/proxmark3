#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
# Makefile for bootrom, see ../common_arm/Makefile.common for common settings
#-----------------------------------------------------------------------------

# DO NOT use thumb mode in the phase 1 bootloader since that generates a section with glue code
ARMSRC =
THUMBSRC = usb_cdc.c \
           clocks.c \
           bootrom.c

ASMSRC = ram-reset.s flash-reset.s
VERSIONSRC = version.c

## There is a strange bug with the linker: Sometimes it will not emit the glue to call
## BootROM from ARM mode. The symbol is emitted, but the section will be filled with
## zeroes. As a temporary workaround, do not use thumb for the phase 2 bootloader
## -- Henryk Plötz <henryk@ploetzli.ch> 2009-09-01
# ARMSRC := $(ARMSRC) $(THUMBSRC)
# THUMBSRC :=

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS = -I. -ffunction-sections -fdata-sections

# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc
APP_CFLAGS += -fno-stack-protector -fno-pie


# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common_arm/Makefile.common

INSTALLFW = $(OBJDIR)/bootrom.elf

OBJS = $(OBJDIR)/bootrom.s19

# version.c should be remade on every compilation
version.c: default_version.c
	$(info [=] GEN $@)
	$(Q)$(SH) ../tools/mkversion.sh > $@ || $(PERL) ../tools/mkversion.pl > $@ || $(CP) $< $@

all: showinfo $(OBJS)

showinfo:
	$(info compiler version:  $(shell $(CC) --version|head -n 1))

tarbin: $(OBJS)
	$(info [=] GEN $@)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=bootrom/%) $(OBJS:%.s19=bootrom/%.elf)

$(OBJDIR)/bootrom.elf: $(VERSIONOBJ) $(ASMOBJ) $(ARMOBJ) $(THUMBOBJ)
	$(info [=] LD $@)
	$(Q)$(CC) $(CROSS_LDFLAGS) -Wl,-T,ldscript-flash,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

clean:
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.o
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.elf
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.s19
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.map
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.d
	$(Q)$(RM) version.c

install: all
	$(info [@] Installing bootrom to $(DESTDIR)$(PREFIX)...)
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)

uninstall:
	$(info [@] Uninstalling bootrom from $(DESTDIR)$(PREFIX)...)
	$(Q)$(RM) $(foreach fw,$(INSTALLFW),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(notdir $(fw)))

.PHONY: all clean help install showinfo
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all   - Make $(OBJDIR)/bootrom.s19, the main bootrom
	@echo +	clean - Clean $(OBJDIR)
