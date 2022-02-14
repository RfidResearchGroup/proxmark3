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
    -include ../Makefile.platform
    -include ../.Makefile.options.cache
    include ../common_arm/Makefile.hal
# detect if there were changes in the platform definitions, requiring a clean
    ifeq ($(PLATFORM_CHANGED), true)
        $(error platform definitions have been changed, please "make clean" at the root of the project)
    endif
endif

#remove one of the following defines and comment out the relevant line
#in the next section to remove that particular feature from compilation.
# NO space,TABs after the "\" sign.
APP_CFLAGS = $(PLATFORM_DEFS) \
             -ffunction-sections -fdata-sections

SRC_LF = lfops.c lfsampling.c pcf7931.c lfdemod.c lfadc.c
SRC_ISO15693 = iso15693.c iso15693tools.c
SRC_ISO14443a = iso14443a.c mifareutil.c mifarecmd.c epa.c mifaresim.c
#UNUSED: mifaresniff.c
SRC_ISO14443b = iso14443b.c
SRC_FELICA = felica.c
SRC_CRAPTO1 = crypto1.c des.c desfire_crypto.c mifaredesfire.c aes.c platform_util.c
SRC_CRC = crc.c crc16.c crc32.c
SRC_ICLASS = iclass.c optimized_cipherutils.c optimized_ikeys.c optimized_elite.c optimized_cipher.c
SRC_LEGIC = legicrf.c legicrfsim.c legic_prng.c
SRC_NFCBARCODE = thinfilm.c

#   SRC_BEE = bee.c

# RDV40 related hardware support
ifneq (,$(findstring WITH_FLASH,$(APP_CFLAGS)))
    SRC_FLASH = flashmem.c
    SRC_SPIFFS = spiffs.c spiffs_cache.c spiffs_check.c spiffs_gc.c spiffs_nucleus.c spiffs_hydrogen.c
else
    SRC_FLASH =
    SRC_SPIFFS =
endif

ifneq (,$(findstring WITH_SMARTCARD,$(APP_CFLAGS)))
    SRC_SMARTCARD = i2c.c
else
    SRC_SMARTCARD =
endif

ifneq (,$(findstring WITH_FPC_USART,$(APP_CFLAGS)))
    SRC_FPC = usart.c
else
    SRC_FPC =
endif

ifneq (,$(findstring WITH_HITAG,$(APP_CFLAGS)))
    SRC_HITAG = hitag2_crypto.c hitag2.c hitagS.c
else
    SRC_HITAG =
endif

ifneq (,$(findstring WITH_EM4x50,$(APP_CFLAGS)))
	SRC_EM4x50 = em4x50.c
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

#the FPGA bitstream files. Note: order matters!
FPGA_BITSTREAMS = fpga_lf.bit fpga_hf.bit fpga_felica.bit

#the lz4 source files required for decompressing the fpga config at run time
SRC_LZ4 = lz4.c
#additional defines required to compile lz4
LZ4_CFLAGS = -DLZ4_MEMORY_USAGE=8
APP_CFLAGS += $(LZ4_CFLAGS)
# lz4 includes:
APP_CFLAGS += -I../common/lz4

# stdint.h provided locally until GCC 4.5 becomes C99 compliant,
# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc
APP_CFLAGS += -I. -fno-stack-protector -fno-pie

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
    $(SRC_HITAG) \
	$(SRC_EM4x50) \
    $(SRC_EM4x70) \
    $(SRC_SPIFFS) \
    $(SRC_ISO14443a) \
    $(SRC_ISO14443b) \
    $(SRC_CRAPTO1) \
    $(SRC_ICLASS) \
    $(SRC_EMV) \
    $(SRC_CRC) \
    $(SRC_FELICA) \
    $(SRC_STANDALONE) \
    $(SRC_ZX) \
    appmain.c \
    printf.c \
    dbprint.c \
    commonutil.c \
    util.c \
    string.c \
    BigBuf.c \
    ticks.c \
    clocks.c \
    hfsnoop.c


# These are to be compiled in ARM mode
ARMSRC = fpgaloader.c \
    usb_cdc.c \
    cmd.c

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

OBJS = $(OBJDIR)/fullimage.s19
FPGA_COMPRESSOR = ../tools/fpga_compress/fpga_compress

all: showinfo $(OBJS)

showinfo:
	$(info compiler version:  $(shell $(CROSS_CC) --version|head -n 1))

.DELETE_ON_ERROR:

# version_pm3.c should be remade on every time fullimage.stage1.elf should be remade
version_pm3.c: default_version_pm3.c $(OBJDIR)/fpga_version_info.o $(OBJDIR)/fpga_all.o $(THUMBOBJ) $(ARMOBJ)
	$(info [-] GEN $@)
	$(Q)$(SH) ../tools/mkversion.sh > $@ || $(CP) $< $@

fpga_version_info.c: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
	$(Q)$(FPGA_COMPRESSOR) -v $(filter %.bit,$^) $@

$(OBJDIR)/fpga_all.o: $(OBJDIR)/fpga_all.bit.z
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit $^ $@

$(OBJDIR)/fpga_all.bit.z: $(FPGA_BITSTREAMS) | $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@
endif

$(FPGA_COMPRESSOR):
	$(error [!] MISSING $@ => To build it, go the root of the repo and do "make $(notdir $@)")
	$(error [!] MISSING $@)

$(OBJDIR)/fullimage.stage1.elf: $(VERSIONOBJ) $(OBJDIR)/fpga_all.o $(THUMBOBJ) $(ARMOBJ)
	$(info [=] LD $@)
	$(Q)$(CROSS_LD) $(CROSS_LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

$(OBJDIR)/fullimage.nodata.bin: $(OBJDIR)/fullimage.stage1.elf
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O binary -I elf32-littlearm --remove-section .data $^ $@

$(OBJDIR)/fullimage.nodata.o: $(OBJDIR)/fullimage.nodata.bin
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=stage1_image $^ $@

$(OBJDIR)/fullimage.data.bin: $(OBJDIR)/fullimage.stage1.elf
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O binary -I elf32-littlearm --only-section .data $^ $@

$(OBJDIR)/fullimage.data.bin.z: $(OBJDIR)/fullimage.data.bin | $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@
endif

$(OBJDIR)/fullimage.data.o: $(OBJDIR)/fullimage.data.bin.z
	$(info [-] GEN $@)
	$(Q)$(CROSS_OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=compressed_data $^ $@

$(OBJDIR)/fullimage.elf: $(OBJDIR)/fullimage.nodata.o $(OBJDIR)/fullimage.data.o
ifeq (,$(findstring WITH_NO_COMPRESSION,$(APP_CFLAGS)))
	$(info [=] LD $@)
	$(Q)$(CROSS_LD) $(CROSS_LDFLAGS) -Wl,-T,ldscript,-e,_osimage_entry,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^
else
	$(Q)$(CP) $(OBJDIR)/fullimage.stage1.elf $@
endif

tarbin: $(OBJS)
	$(info TAR $@)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=armsrc/%) $(OBJS:%.s19=armsrc/%.elf)

clean:
	$(Q)$(RM) $(DEPENDENCY_FILES)
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.o
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.elf
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.s19
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.map
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.d
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.z
	$(Q)$(RM) $(OBJDIR)$(PATHSEP)*.bin
	$(Q)$(RM) version_pm3.c version.c fpga_version_info.c

install: all
	$(info [@] Installing fullimage to $(DESTDIR)$(PREFIX)...)
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

uninstall:
	$(info [@] Uninstalling fullimage from $(DESTDIR)$(PREFIX)...)
	$(Q)$(RM) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

.PHONY: all clean help install uninstall
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all    - Build the full image $(OBJDIR)/fullimage.s19
	@echo +	clean             - Clean $(OBJDIR)

