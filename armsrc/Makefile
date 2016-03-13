#-----------------------------------------------------------------------------
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
# Makefile for armsrc, see ../common/Makefile.common for common settings
#-----------------------------------------------------------------------------

APP_INCLUDES = apps.h

#remove one of the following defines and comment out the relevant line
#in the next section to remove that particular feature from compilation  
APP_CFLAGS	= -DWITH_ISO14443a_StandAlone -DWITH_LF \
			 -DWITH_ISO15693 -DWITH_ISO14443a -DWITH_ISO14443b -DWITH_ICLASS \
			-DWITH_LEGICRF -DWITH_HITAG -DWITH_CRC -DON_DEVICE -DWITH_HFSNOOP \
			-fno-strict-aliasing -ffunction-sections -fdata-sections
#-DWITH_LCD

#SRC_LCD = fonts.c LCD.c
SRC_LF = lfops.c hitag2.c hitagS.c lfsampling.c pcf7931.c lfdemod.c protocols.c
SRC_ISO15693 = iso15693.c iso15693tools.c
SRC_ISO14443a = epa.c iso14443a.c mifareutil.c mifarecmd.c mifaresniff.c
SRC_ISO14443b = iso14443b.c
SRC_CRAPTO1 = crapto1.c crypto1.c des.c aes.c desfire_key.c desfire_crypto.c mifaredesfire.c
SRC_CRC = iso14443crc.c crc.c crc16.c crc32.c 
SRC_EMV = tlv.c emvdataels.c emvutil.c emvcmd.c 									 

#the FPGA bitstream files. Note: order matters!
FPGA_BITSTREAMS = fpga_lf.bit fpga_hf.bit

#the zlib source files required for decompressing the fpga config at run time
SRC_ZLIB = inflate.c inffast.c inftrees.c adler32.c zutil.c
#additional defines required to compile zlib
ZLIB_CFLAGS = -DZ_SOLO -DZ_PREFIX -DNO_GZIP -DZLIB_PM3_TUNED
APP_CFLAGS += $(ZLIB_CFLAGS)
# zlib includes:
APP_CFLAGS += -I../zlib

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS += -I.

# Compile these in thumb mode (small size)
THUMBSRC = start.c \
	$(SRC_LCD) \
	$(SRC_ISO15693) \
	$(SRC_LF) \
	$(SRC_ZLIB) \
	appmain.c \
	printf.c \
	util.c \
	string.c \
	usb_cdc.c \
	cmd.c

# These are to be compiled in ARM mode
ARMSRC = fpgaloader.c \
	legicrf.c \
	$(SRC_ISO14443a) \
	$(SRC_ISO14443b) \
	$(SRC_CRAPTO1) \
	$(SRC_CRC) \
	legic_prng.c \
	iclass.c \
	BigBuf.c \
	optimized_cipher.c \
	hfsnoop.c \
	parity.c
#  $(SRC_EMV)

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

OBJS = $(OBJDIR)/fullimage.s19 
FPGA_COMPRESSOR = ../client/fpga_compress

all: $(OBJS)

.DELETE_ON_ERROR:

$(OBJDIR)/fpga_all.o: $(OBJDIR)/fpga_all.bit.z
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit $^ $@

$(OBJDIR)/fpga_all.bit.z: $(FPGA_BITSTREAMS) $(FPGA_COMPRESSOR)
	$(FPGA_COMPRESSOR) $(filter %.bit,$^) $@  

$(FPGA_COMPRESSOR):
		make -C ../client $(notdir $(FPGA_COMPRESSOR))
		
$(OBJDIR)/fullimage.stage1.elf: $(VERSIONOBJ) $(OBJDIR)/fpga_all.o $(THUMBOBJ) $(ARMOBJ)
	$(CC) $(LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

$(OBJDIR)/fullimage.nodata.bin: $(OBJDIR)/fullimage.stage1.elf
	$(OBJCOPY) -O binary -I elf32-littlearm --remove-section .data $^ $@
	
$(OBJDIR)/fullimage.nodata.o: $(OBJDIR)/fullimage.nodata.bin
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=stage1_image $^ $@

$(OBJDIR)/fullimage.data.bin: $(OBJDIR)/fullimage.stage1.elf
	$(OBJCOPY) -O binary -I elf32-littlearm --only-section .data $^ $@

$(OBJDIR)/fullimage.data.bin.z: $(OBJDIR)/fullimage.data.bin $(FPGA_COMPRESSOR)
	$(FPGA_COMPRESSOR) $(filter %.bin,$^) $@  
	
$(OBJDIR)/fullimage.data.o: $(OBJDIR)/fullimage.data.bin.z
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --rename-section .data=compressed_data $^ $@

$(OBJDIR)/fullimage.elf: $(OBJDIR)/fullimage.nodata.o $(OBJDIR)/fullimage.data.o
	$(CC) $(LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^

tarbin: $(OBJS)
	$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=armsrc/%) $(OBJS:%.s19=armsrc/%.elf)

clean:
	$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(DELETE) $(OBJDIR)$(PATHSEP)*.map
	$(DELETE) $(OBJDIR)$(PATHSEP)*.d
	$(DELETE) $(OBJDIR)$(PATHSEP)*.z
	$(DELETE) $(OBJDIR)$(PATHSEP)*.bin
	$(DELETE) version.c

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all    - Build the full image $(OBJDIR)/fullimage.s19
	@echo +	clean             - Clean $(OBJDIR)

