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
# Makefile for armsrc, see ../common_arm/Makefile.common for common settings
#-----------------------------------------------------------------------------

# This Makefile might have been called directly, not via the root Makefile, so:
ifeq ($(PLTNAME),)
    PLATFORM_FILE ?= ../Makefile.platform
    -include $(PLATFORM_FILE)
    -include ../.Makefile.options.cache
    include ../common_arm/Makefile.hal
# detect if there were changes in the platform definitions, requiring a clean
    ifeq ($(PLATFORM_CHANGED), true)
        $(error platform definitions have been changed, please "make clean" at the root of the project)
    endif
endif

# Proxmark5 requires armlib.
include ../armlib/Exports.mk

#remove one of the following defines and comment out the relevant line
#in the next section to remove that particular feature from compilation.
# NO space,TABs after the "\" sign.
APP_CFLAGS = $(PLATFORM_DEFS)
APP_CFLAGS += $(ARMLIB_EXPORT_CFLAGS)

# HAL for platform
ifeq ($(PLATFORM),PM5)
	SRC_STARTUP    = startup_at32f435_437.s
    SRC_TICKS      = ../common_arm/ticks/ticks_hw_at32.c i2c.c # TODO DXL: It always depends on I2C, so the compilation location of this source file needs to be optimized.
    SRC_GPIO       = ../common_arm/gpio/gpio_hw_at32.c
    SRC_WDT        = ../common_arm/wdt/wdt_hw_at32.c
    SRC_RSSI       = ../common_arm/rssi/rssi_hw_at32.c
    SRC_RGB        = ../common_arm/rgb/rgb_hw_at32.c
    SRC_SYS        = ../common_arm/sys/sys_hw_at32.c
    SRC_FPGA       = ../common_arm/fpga/fpga_hw_at32.c ../common_arm/fpga/fpga_gw_jtag.c
    SRC_USB_CDC    = ../common_arm/usb/usb_cdc_at32.c
    SRC_FLASH_DATA = ../common_arm/flash_data/flashmem_hw_at32.c
    APP_CFLAGS     += -mcpu=cortex-m4
    CROSS_LDFLAGS  += -mcpu=cortex-m4
    LD_SCRIPT      = ldscript.osimage.at32
    ARMLIB_OBJ     = $(OBJDIR)/$(ARMLIB_EXPORT_LIBNAME)
    LIBS           += $(ARMLIB_OBJ)
else
	SRC_STARTUP    =
    SRC_TICKS      = ../common_arm/ticks/ticks_hw_at91.c
    SRC_GPIO       = ../common_arm/gpio/gpio_hw_at91.c
    SRC_WDT        = ../common_arm/wdt/wdt_hw_at91.c
    SRC_RSSI       = ../common_arm/rssi/rssi_hw_at91.c
    SRC_RGB        =
    SRC_SYS        = ../common_arm/sys/sys_hw_at91.c
    SRC_FPGA       = ../common_arm/fpga/fpga_hw_at91.c
    SRC_USB_CDC    = ../common_arm/usb/usb_cdc_at91.c
    SRC_FLASH_DATA = ../common_arm/flash_data/flashmem_hw_at91.c
	LD_SCRIPT      = ldscript.osimage.at91
endif

SRC_LF = lfops.c lfsampling.c pcf7931.c lfdemod.c lfadc.c
SRC_HF = hfops.c
SRC_ISO15693 = iso15693.c iso15693tools.c
SRC_ISO14443a = iso14443a.c secc.c mifareutil.c mifarecmd.c epa.c mifaresim.c

ifneq (,$(findstring WITH_SMARTCARD,$(APP_CFLAGS)))
    SRC_ISO14443a += sam_common.c sam_mfc.c sam_seos.c sam_sc.c
endif

#UNUSED: mifaresniff.c
SRC_ISO14443b = iso14443b.c
SRC_FELICA = felica.c felicasim.c
SRC_CRAPTO1 = crypto1.c des.c desfire_crypto.c mifaredesfire.c aes.c platform_util.c
SRC_CRC = crc.c crc16.c crc32.c
SRC_ICLASS = iclass.c optimized_cipherutils.c optimized_ikeys.c optimized_elite.c optimized_cipher.c
ifneq (,$(findstring WITH_SMARTCARD,$(APP_CFLAGS)))
    SRC_ICLASS += sam_picopass.c
endif
SRC_SEOS = seos.c sha1.c sha256.c
SRC_LEGIC = legicrf.c legicrfsim.c legic_prng.c
SRC_NFCBARCODE = thinfilm.c

#   SRC_BEE = bee.c

# RDV40 or PM5 related hardware support
ifneq (,$(findstring WITH_FLASH,$(APP_CFLAGS)))
    SRC_FLASH = flashmem_core.c $(SRC_FLASH_DATA)
    SRC_SPIFFS = spiffs.c spiffs_cache.c spiffs_check.c spiffs_gc.c spiffs_nucleus.c spiffs_hydrogen.c
else
    SRC_FLASH =
    SRC_SPIFFS =
endif

ifneq (,$(findstring WITH_SMARTCARD,$(APP_CFLAGS)))
    SRC_SMARTCARD = i2c.c i2c_direct.c emvsim.c
else
    SRC_SMARTCARD =
endif

ifneq (,$(findstring WITH_FPC_USART,$(APP_CFLAGS)))
    SRC_FPC = usart.c
else
    SRC_FPC =
endif

ifneq (,$(findstring WITH_BWM_FORWARD,$(APP_CFLAGS)))
    SRC_BWM = bwm_uart_at32.c bwm_forward.c bwm_wifi.c
else
    SRC_BWM =
endif

# BWM charger (AW32001) + fuel gauge (BQ27427), incl. the optional low-batt beep
ifneq (,$(findstring WITH_BWM_STATUS,$(APP_CFLAGS))$(findstring WITH_BWM_CHARGERKICK,$(APP_CFLAGS)))
    SRC_BWM_CHARGER = bwm_charger.c
else
    SRC_BWM_CHARGER =
endif

# Generic PM5 mainboard buzzer (QC self-test + BWM low-batt warning)
ifeq ($(PLATFORM),PM5)
    SRC_BUZZER = buzzer.c
else
    SRC_BUZZER =
endif

# PM5 antenna-RGB power/battery indicator
ifneq (,$(findstring WITH_PM5_PWR_LED,$(APP_CFLAGS)))
    SRC_RGB_INDICATOR = rgb_indicator.c
else
    SRC_RGB_INDICATOR =
endif

ifneq (,$(findstring WITH_HITAG,$(APP_CFLAGS)))
    SRC_HITAG = hitag2_crypto.c hitag_common.c hitag2.c hitagS.c hitagu.c hitag2_crack.c
    APP_CFLAGS += -I../common/hitag2
else
    SRC_HITAG =
endif

ifneq (,$(findstring WITH_EM4x50,$(APP_CFLAGS)))
	SRC_EM4x50 = em4x50.c bruteforce.c
else
	SRC_EM4x50 =
endif

ifneq (,$(findstring WITH_EM4x70,$(APP_CFLAGS)))
	SRC_EM4x70 = em4x70.c
else
	SRC_EM4x70 =
endif

ifneq (,$(findstring WITH_LCD,$(APP_CFLAGS)))
    SRC_LCD = fonts.c LCD.c
else
    SRC_LCD =
endif

ifneq (,$(findstring WITH_ZX8211,$(APP_CFLAGS)))
    SRC_ZX = lfzx.c
else
    SRC_ZX =
endif

# Generic standalone Mode injection of source code
include Standalone/Makefile.inc

#the lz4 source files required for decompressing the fpga config at run time
SRC_LZ4 = lz4.c
#additional defines required to compile lz4
LZ4_CFLAGS = -DLZ4_MEMORY_USAGE=8 -DLZ4_HEAPMODE=0
APP_CFLAGS += $(LZ4_CFLAGS)
# lz4 includes:
APP_CFLAGS += -I../common/lz4

# stdint.h provided locally until GCC 4.5 becomes C99 compliant,
APP_CFLAGS += -I.

# Compile these in thumb mode (small size)
THUMBSRC = start.c \
    $(SRC_LCD) \
    $(SRC_ISO15693) \
    $(SRC_NFCBARCODE) \
    $(SRC_LF) \
    $(SRC_LZ4) \
    $(SRC_LEGIC) \
    $(SRC_FLASH) \
    $(SRC_SMARTCARD) \
    $(SRC_FPC) \
    $(SRC_BWM) \
    $(SRC_BWM_CHARGER) \
    $(SRC_BUZZER) \
    $(SRC_RGB_INDICATOR) \
    $(SRC_HITAG) \
    $(SRC_EM4x50) \
    $(SRC_EM4x70) \
    $(SRC_SPIFFS) \
    $(SRC_HF) \
    $(SRC_ISO14443a) \
    $(SRC_ISO14443b) \
    $(SRC_CRAPTO1) \
    $(SRC_ICLASS) \
    $(SRC_SEOS) \
    $(SRC_EMV) \
    $(SRC_CRC) \
    $(SRC_FELICA) \
    $(SRC_STANDALONE) \
    $(SRC_ZX) \
    $(SRC_RSSI) \
    $(SRC_RGB) \
	$(SRC_TICKS) \
	$(SRC_GPIO) \
	$(SRC_WDT) \
	$(SRC_SYS) \
    appmain.c \
    printf.c \
    dbprint.c \
    commonutil.c \
    util.c \
    string.c \
    BigBuf.c \
    ticks_core.c \
	rssi_core.c \
    hfsnoop.c \
    generator.c \
    cmac_calc.c \
    cmac_3des.c


# These are to be compiled in ARM mode
ARMSRC = fpga_loader.c \
	fpga_core.c \
	$(SRC_FPGA) \
	usb_cdc_desc.c \
	usb_read_ng.c \
	$(SRC_USB_CDC) \
    cmd.c

ASMSRC = $(SRC_STARTUP)

VERSIONSRC = version_pm3.c \
    fpga_version_info.c

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common_arm/Makefile.common

INSTALLFW = $(OBJDIR)/fullimage.elf
ifneq (,$(FWTAG))
    INSTALLFWTAG = $(notdir $(INSTALLFW:%.elf=%-$(FWTAG).elf))
else
    INSTALLFWTAG = $(notdir $(INSTALLFW))
endif

# On some platforms, the FPGA firmware does not need to be packaged into the ARM, because the FPGA has its own flash.
ifneq ($(strip $(SKIP_FPGA_EMBED)),true)
	FPGA_ALL_O_DEP = $(OBJDIR)/fpga_all.o
endif

OBJS = $(OBJDIR)/fullimage.s19
FPGA_COMPRESSOR = ../tools/fpga_compress/fpga_compress

all: showinfo $(OBJS)

showinfo:
	$(info compiler version:  $(shell $(CROSS_CC) --version|head -n 1))

.DELETE_ON_ERROR:

# version_pm3.c should be checked on every time fullimage.stage1.elf should be remade
version_pm3.c: default_version_pm3.c $(OBJDIR)/fpga_version_info.o $(FPGA_ALL_O_DEP) $(THUMBOBJ) $(ARMOBJ) $(ASMOBJ) .FORCE
	$(info [-] CHECK $@)
	$(Q)$(SH) ../tools/mkversion.sh $@ || $(CP) $< $@

fpga_version_info.c: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
	$(Q)$(FPGA_COMPRESSOR) -v $(filter %.bit,$^) $@

$(OBJDIR)/fpga_all.o: $(OBJDIR)/fpga_all.bit.z
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit $^ $@

$(OBJDIR)/fpga_all.bit.z: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@
endif

$(FPGA_COMPRESSOR):
	$(error [!] MISSING $@ => To build it, go the root of the repo and do "make $(notdir $@)")
	$(error [!] MISSING $@)

ifeq ($(PLATFORM),PM5)
$(ARMLIB_OBJ):
	$(info [=] MAKE $(notdir $@))
	@$(MAKE) --no-print-directory -f ../armlib/Makefile
endif

$(OBJDIR)/fullimage.stage1.elf: $(VERSIONOBJ) $(FPGA_ALL_O_DEP) $(THUMBOBJ) $(ARMOBJ) $(ASMOBJ) $(ARMLIB_OBJ)
	$(info [=] LD $@)
# Using -T instead of -Wl,-T is needed to prevent the linker from using the default ldscript when using picolibc instead of newlib
	$(Q)$(CROSS_LD) $(CROSS_LDFLAGS) -T $(LD_SCRIPT) -Wl,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

$(OBJDIR)/fullimage.data.bin: $(OBJDIR)/fullimage.stage1.elf
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O binary -I elf32-littlearm --only-section .data $^ $@

$(OBJDIR)/fullimage.data.bin.z: $(OBJDIR)/fullimage.data.bin $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@
endif

$(OBJDIR)/fullimage.elf: $(OBJDIR)/fullimage.stage1.elf $(OBJDIR)/fullimage.data.bin.z
ifneq (,$(findstring WITH_COMPRESSION,$(APP_CFLAGS)))
	$(info [=] LD $@)
	$(Q)$(CROSS_OBJCOPY) -O elf32-littlearm -I elf32-littlearm --strip-all --update-section .data=$(OBJDIR)/fullimage.data.bin.z $(OBJDIR)/fullimage.stage1.elf $@
else
	$(Q)$(CP) $(OBJDIR)/fullimage.stage1.elf $@
endif

tarbin: $(OBJS)
	$(info TAR $@)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=armsrc/%) $(OBJS:%.s19=armsrc/%.elf)

clean:
	$(Q)$(RM) $(DEPENDENCY_FILES)
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.o
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.a
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.elf
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.s19
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.map
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.d
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.z
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.bin
	$(Q)$(RM) version_pm3.c version.c fpga_version_info.c

install: all
	$(info [@] Installing fullimage to $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(INSTALLSUDO) $(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

uninstall:
	$(info [@] Uninstalling fullimage from $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(RM) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

.PHONY: all clean help install uninstall .FORCE
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all    - Build the full image $(OBJDIR)/fullimage.s19
	@echo +	clean             - Clean $(OBJDIR)
