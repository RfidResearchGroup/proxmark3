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

# Proxmark5 requires armlib.
include ../armlib/Exports.mk

# HAL for platform
ifeq ($(PLATFORM),PM5)
    SRC_SYS        = sys_hw_at32.c
    SRC_TICKS      = ticks_hw_at32.c
    SRC_GPIO       = gpio_hw_at32.c
    SRC_USB_CDC    = usb_cdc_at32.c
    SRC_FLASH_CODE = flash_code_hw_at32.c
    SRC_FLASH_DATA = flashmem_hw_at32.c
    SRC_STARTUP    = flash-reset-at32.s ram-reset-at32.s
    LD_SCRIPT      = ldscript-flash-at32
    APP_CFLAGS     += -mcpu=cortex-m4 -DPM5
    CROSS_LDFLAGS  += -mcpu=cortex-m4
    ARMLIB_OBJ     = $(OBJDIR)/$(ARMLIB_EXPORT_LIBNAME)
    LIBS           += $(ARMLIB_OBJ)
else
    SRC_SYS        = sys_hw_at91.c
    SRC_TICKS      = ticks_hw_at91.c
    SRC_GPIO       = gpio_hw_at91.c
    SRC_USB_CDC    = usb_cdc_at91.c
    SRC_FLASH_CODE = flash_code_hw_at91.c
    SRC_FLASH_DATA = flashmem_hw_at91.c
    SRC_STARTUP    = flash-reset-at91.s ram-reset-at91.s
    LD_SCRIPT      = ldscript-flash-at91
endif

# DO NOT use thumb mode in the phase 1 bootloader since that generates a section with glue code
ARMSRC =
THUMBSRC = bootrom.c $(SRC_SYS) $(SRC_TICKS) $(SRC_GPIO) $(SRC_USB_CDC) $(SRC_FLASH_CODE) usb_cdc_desc.c

ASMSRC = $(SRC_STARTUP)
VERSIONSRC = version_pm3.c

## There is a strange bug with the linker: Sometimes it will not emit the glue to call
## BootROM from ARM mode. The symbol is emitted, but the section will be filled with
## zeroes. As a temporary workaround, do not use thumb for the phase 2 bootloader
## -- Henryk Plötz <henryk@ploetzli.ch> 2009-09-01
# ARMSRC := $(ARMSRC) $(THUMBSRC)
# THUMBSRC :=

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS += -I. -DAS_BOOTROM
# no-common makes sure uninitialized vars don't end up in COMMON area
APP_CFLAGS += -fno-common
# For PM5, armlib is required
APP_CFLAGS += $(ARMLIB_EXPORT_CFLAGS)

ifneq (,$(findstring WITH_FLASH,$(PLATFORM_DEFS)))
	APP_CFLAGS += -DWITH_FLASH
	APP_CFLAGS += -I../common_arm
    THUMBSRC += ticks_core.c flashmem_core.c $(SRC_FLASH_DATA)
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

ifeq ($(PLATFORM),PM5)
$(ARMLIB_OBJ):
	$(info [=] MAKE $(notdir $@))
	@$(MAKE) --no-print-directory -f ../armlib/Makefile
endif

$(OBJDIR)/bootrom.elf: $(VERSIONOBJ) $(ASMOBJ) $(ARMOBJ) $(THUMBOBJ) $(ARMLIB_OBJ)
	$(info [=] LD $@)
# Using -T instead of -Wl,-T is needed to prevent the linker from using the default ldscript when using picolibc instead of newlib
	$(Q)$(CROSS_LD) $(CROSS_LDFLAGS) -T $(LD_SCRIPT) -Wl,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

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
