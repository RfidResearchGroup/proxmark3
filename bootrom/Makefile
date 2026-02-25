#-----------------------------------------------------------------------------
# Copyright (C) Jonathan Westhues, Mar 2006
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# Makefile for bootrom, see ../common_arm/Makefile.common for common settings
#-----------------------------------------------------------------------------

# DO NOT use thumb mode in the phase 1 bootloader since that generates a section with glue code
ARMSRC =
THUMBSRC = usb_cdc.c \
           clocks.c \
           bootrom.c

ASMSRC = ram-reset.s flash-reset.s
VERSIONSRC = version_pm3.c

## There is a strange bug with the linker: Sometimes it will not emit the glue to call
## BootROM from ARM mode. The symbol is emitted, but the section will be filled with
## zeroes. As a temporary workaround, do not use thumb for the phase 2 bootloader
## -- Henryk Plötz <henryk@ploetzli.ch> 2009-09-01
# ARMSRC := $(ARMSRC) $(THUMBSRC)
# THUMBSRC :=

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS = -I. -ffunction-sections -fdata-sections -DAS_BOOTROM

# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc,  no-common makes sure uninitialized vars don't end up in COMMON area
APP_CFLAGS += -fno-stack-protector -fno-pie -fno-common

ifneq (,$(findstring WITH_FLASH,$(PLATFORM_DEFS)))
	APP_CFLAGS += -DWITH_FLASH
	APP_CFLAGS += -I../common_arm
    THUMBSRC += flashmem.c ticks.c
endif


# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common_arm/Makefile.common

INSTALLFW = $(OBJDIR)/bootrom.elf

OBJS = $(OBJDIR)/bootrom.s19

# version_pm3.c should be checked on every compilation
version_pm3.c: default_version_pm3.c .FORCE
	$(info [=] CHECK $@)
	$(Q)$(SH) ../tools/mkversion.sh $@ || $(CP) $< $@

all: showinfo $(OBJS)

showinfo:
	$(info compiler version:  $(shell $(CROSS_CC) --version|head -n 1))

tarbin: $(OBJS)
	$(info [=] GEN $@)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=bootrom/%) $(OBJS:%.s19=bootrom/%.elf)

$(OBJDIR)/bootrom.elf: $(VERSIONOBJ) $(ASMOBJ) $(ARMOBJ) $(THUMBOBJ)
	$(info [=] LD $@)
	$(Q)$(CROSS_LD) $(CROSS_LDFLAGS) -Wl,-T,ldscript-flash,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

clean:
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.o
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.elf
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.s19
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.map
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.d
	$(Q)$(RM) version_pm3.c version.c

install: all
	$(info [@] Installing bootrom to $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(INSTALLSUDO) $(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)

uninstall:
	$(info [@] Uninstalling bootrom from $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(RM) $(foreach fw,$(INSTALLFW),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(notdir $(fw)))

.PHONY: all clean help install showinfo .FORCE
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all   - Make $(OBJDIR)/bootrom.s19, the main bootrom
	@echo +	clean - Clean $(OBJDIR)
