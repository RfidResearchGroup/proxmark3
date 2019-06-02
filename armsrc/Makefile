# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
# Makefile for armsrc, see ../common/Makefile.common for common settings
#-----------------------------------------------------------------------------

APP_INCLUDES = apps.h

# This Makefile might have been called directly, not via the root Makefile, so:
ifeq ($(PLTNAME),)
    -include ../Makefile.platform
    -include ../.Makefile.options.cache
    include ../common/Makefile.hal
# detect if there were changes in the platform definitions, requiring a clean
    ifeq ($(PLATFORM_CHANGED), true)
        $(error platform definitions have been changed, please "make clean" at the root of the project)
    endif
endif

#remove one of the following defines and comment out the relevant line
#in the next section to remove that particular feature from compilation.
# NO space,TABs after the "\" sign.
APP_CFLAGS = $(PLATFORM_DEFS) \
             -DON_DEVICE \
             -fno-strict-aliasing -ffunction-sections -fdata-sections

SRC_LF = lfops.c lfsampling.c pcf7931.c lfdemod.c
SRC_ISO15693 = iso15693.c iso15693tools.c
SRC_ISO14443a = iso14443a.c mifareutil.c mifarecmd.c epa.c mifaresim.c
SRC_ISO14443b = iso14443b.c
SRC_FELICA = felica.c
SRC_CRAPTO1 = crypto1.c des.c aes.c desfire_key.c desfire_crypto.c mifaredesfire.c
SRC_CRC = crc.c crc16.c crc32.c
SRC_ICLASS = iclass.c optimized_cipher.c
SRC_LEGIC = legicrf.c legicrfsim.c legic_prng.c
#   SRC_BEE = bee.c

# RDV40 related hardware support
ifneq (,$(findstring WITH_FLASH,$(APP_CFLAGS)))
    SRC_FLASH = flashmem.c
else
    SRC_FLASH =
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

ifneq (,$(findstring WITH_LCD,$(APP_CFLAGS)))
    SRC_LCD = fonts.c LCD.c
else
    SRC_LCD =
endif

# Generic standalone Mode injection of source code


SRC_STANDALONE = placeholder.c
# WITH_STANDALONE_LF_ICERUN
ifneq (,$(findstring WITH_STANDALONE_LF_ICERUN,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_icerun.c
endif
# WITH_STANDALONE_LF_SAMYRUN
ifneq (,$(findstring WITH_STANDALONE_LF_SAMYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_samyrun.c
endif
# WITH_STANDALONE_LF_PROXBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_PROXBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_proxbrute.c
endif
# WITH_STANDALONE_LF_HIDBRUTE
ifneq (,$(findstring WITH_STANDALONE_LF_HIDBRUTE,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_hidbrute.c
endif
# WITH_STANDALONE_HF_YOUNG
ifneq (,$(findstring WITH_STANDALONE_HF_YOUNG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_young.c
endif
# WITH_STANDALONE_HF_MATTYRUN
ifneq (,$(findstring WITH_STANDALONE_HF_MATTYRUN,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_mattyrun.c
endif
# WITH_STANDALONE_HF_COLIN
ifneq (,$(findstring WITH_STANDALONE_HF_COLIN,$(APP_CFLAGS)))
    SRC_STANDALONE = vtsend.c hf_colin.c
endif
# WITH_STANDALONE_HF_BOG
ifneq (,$(findstring WITH_STANDALONE_HF_BOG,$(APP_CFLAGS)))
    SRC_STANDALONE = hf_bog.c
endif

#the FPGA bitstream files. Note: order matters!
FPGA_BITSTREAMS = fpga_lf.bit fpga_hf.bit

#the zlib source files required for decompressing the fpga config at run time
SRC_ZLIB = inflate.c inffast.c inftrees.c adler32.c zutil.c
#additional defines required to compile zlib
ZLIB_CFLAGS = -DZ_SOLO -DZ_PREFIX -DNO_GZIP -DZLIB_PM3_TUNED
APP_CFLAGS += $(ZLIB_CFLAGS)
# zlib includes:
APP_CFLAGS += -I../zlib

# stdint.h provided locally until GCC 4.5 becomes C99 compliant,
# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc
APP_CFLAGS += -I. -fno-stack-protector -fno-pie

# Compile these in thumb mode (small size)
THUMBSRC = start.c \
    protocols.c \
    $(SRC_LCD) \
    $(SRC_ISO15693) \
    $(SRC_LF) \
    $(SRC_ZLIB) \
    $(SRC_LEGIC) \
    $(SRC_FLASH) \
    $(SRC_SMARTCARD) \
    $(SRC_FPC) \
    $(SRC_HITAG) \
    appmain.c \
    printf.c \
    commonutil.c \
    util.c \
    string.c \
    BigBuf.c \
    ticks.c \
    hfsnoop.c


# These are to be compiled in ARM mode
ARMSRC = fpgaloader.c \
    $(SRC_ISO14443a) \
    $(SRC_ISO14443b) \
    $(SRC_CRAPTO1) \
    $(SRC_ICLASS) \
    $(SRC_EMV) \
    $(SRC_CRC) \
    $(SRC_FELICA) \
    $(SRC_STANDALONE) \
    parity.c \
    usb_cdc.c \
    cmd.c

VERSIONSRC = version.c \
    fpga_version_info.c

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

COMMON_FLAGS =  -Os

OBJS = $(OBJDIR)/fullimage.s19
FPGA_COMPRESSOR = ../client/fpga_compress

all: $(OBJS)

.DELETE_ON_ERROR:

# version.c should be remade on every time fullimage.stage1.elf should be remade
version.c: default_version.c $(OBJDIR)/fpga_version_info.o $(OBJDIR)/fpga_all.o $(THUMBOBJ) $(ARMOBJ)
	$(info [-] GEN $@)
	$(Q)perl ../tools/mkversion.pl .. > $@ || $(COPY) $^ $@

fpga_version_info.c: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
	$(Q)$(FPGA_COMPRESSOR) -v $(filter %.bit,$^) $@

$(OBJDIR)/fpga_all.o: $(OBJDIR)/fpga_all.bit.z
	$(info [-] GEN $@)
	$(Q)$(OBJCOPY) -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit $^ $@

$(OBJDIR)/fpga_all.bit.z: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@
endif

$(FPGA_COMPRESSOR):
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C ../client $(notdir $(FPGA_COMPRESSOR))

$(OBJDIR)/fullimage.stage1.elf: $(VERSIONOBJ) $(OBJDIR)/fpga_all.o $(THUMBOBJ) $(ARMOBJ)
	$(info [=] LD $@)
	$(Q)$(CC) $(LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

$(OBJDIR)/fullimage.nodata.bin: $(OBJDIR)/fullimage.stage1.elf
	$(info [-] GEN $@)
	$(Q)$(OBJCOPY) -O binary -I elf32-littlearm --remove-section .data $^ $@

$(OBJDIR)/fullimage.nodata.o: $(OBJDIR)/fullimage.nodata.bin
	$(info [-] GEN $@)
	$(Q)$(OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=stage1_image $^ $@

$(OBJDIR)/fullimage.data.bin: $(OBJDIR)/fullimage.stage1.elf
	$(info [-] GEN $@)
	$(Q)$(OBJCOPY) -O binary -I elf32-littlearm --only-section .data $^ $@

$(OBJDIR)/fullimage.data.bin.z: $(OBJDIR)/fullimage.data.bin $(FPGA_COMPRESSOR)
	$(info [-] GEN $@)
ifeq ($(Q),@)
	@$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@ >/dev/null
else
	$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@
endif

$(OBJDIR)/fullimage.data.o: $(OBJDIR)/fullimage.data.bin.z
	$(info [-] GEN $@)
	$(Q)$(OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=compressed_data $^ $@

$(OBJDIR)/fullimage.elf: $(OBJDIR)/fullimage.nodata.o $(OBJDIR)/fullimage.data.o
	$(info [=] LD $@)
	$(Q)$(CC) $(LDFLAGS) -Wl,-T,ldscript,-e,_osimage_entry,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^

tarbin: $(OBJS)
	$(info TAR $@)
	$(Q)$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=armsrc/%) $(OBJS:%.s19=armsrc/%.elf)

clean:
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.map
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.d
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.z
	$(Q)$(DELETE) $(OBJDIR)$(PATHSEP)*.bin
	$(Q)$(DELETE) version.c

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all    - Build the full image $(OBJDIR)/fullimage.s19
	@echo +	clean             - Clean $(OBJDIR)
