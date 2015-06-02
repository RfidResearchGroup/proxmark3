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
APP_CFLAGS	= -DWITH_LF -DWITH_ISO15693 -DWITH_ISO14443a -DWITH_ISO14443b -DWITH_ICLASS -DWITH_LEGICRF -DWITH_HITAG  -DWITH_CRC -DON_DEVICE -fno-strict-aliasing -ffunction-sections -fdata-sections
#-DWITH_LCD 

#SRC_LCD = fonts.c LCD.c
SRC_LF = lfops.c hitag2.c lfsampling.c
SRC_ISO15693 = iso15693.c iso15693tools.c
SRC_ISO14443a = epa.c iso14443a.c mifareutil.c mifarecmd.c mifaresniff.c
SRC_ISO14443b = iso14443b.c
SRC_CRAPTO1 = crapto1.c crypto1.c des.c aes.c desfire_key.c desfire_crypto.c mifaredesfire.c
SRC_CRC = iso14443crc.c crc.c crc16.c crc32.c 

THUMBSRC = start.c \
	$(SRC_LCD) \
	$(SRC_ISO15693) \
	$(SRC_LF) \
	appmain.c \
	printf.c \
	util.c \
	string.c \
	usb_cdc.c \
	cmd.c

# These are to be compiled in ARM mode
ARMSRC = fpgaloader.c \
	legicrf.c \
	lfdemod.c \
	$(SRC_ISO14443a) \
	$(SRC_ISO14443b) \
	$(SRC_CRAPTO1) \
	$(SRC_CRC) \
	legic_prng.c \
	iclass.c \
	BigBuf.c \
	optimized_cipher.c

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS += -I.

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

OBJS = $(OBJDIR)/osimage.s19 
#$(OBJDIR)/fpgaimage.s19

all: $(OBJS)

$(OBJDIR)/fpga_lf.o: fpga_lf.bit
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --redefine-sym _binary____fpga_fpga_lf_bit_start=_binary_fpga_lf_bit_start --redefine-sym _binary____fpga_fpga_lf_bit_end=_binary_fpga_lf_bit_end --prefix-sections=fpga_lf_bit  $^ $@

$(OBJDIR)/fpga_hf.o: fpga_hf.bit
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --redefine-sym _binary____fpga_fpga_hf_bit_start=_binary_fpga_hf_bit_start --redefine-sym _binary____fpga_fpga_hf_bit_end=_binary_fpga_hf_bit_end --prefix-sections=fpga_hf_bit  $^ $@

$(OBJDIR)/fullimage.elf: $(VERSIONOBJ) $(OBJDIR)/fpga_lf.o $(OBJDIR)/fpga_hf.o $(THUMBOBJ) $(ARMOBJ)
	$(CC) $(LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

#$(OBJDIR)/fpgaimage.elf: $(OBJDIR)/fullimage.elf
#	$(OBJCOPY) -F elf32-littlearm --only-section .fpgaimage $^ $@  

$(OBJDIR)/osimage.elf: $(OBJDIR)/fullimage.elf
	$(OBJCOPY) -F elf32-littlearm $^ $@

tarbin: $(OBJS)
	$(TAR) $(TARFLAGS) ../proxmark3-$(platform)-bin.tar $(OBJS:%=armsrc/%) $(OBJS:%.s19=armsrc/%.elf)


clean:
	$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(DELETE) $(OBJDIR)$(PATHSEP)*.map
	$(DELETE) $(OBJDIR)$(PATHSEP)*.d
	$(DELETE) version.c

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all               - Make both:
	@echo +	$(OBJDIR)/osimage.s19   - The OS image
	@echo +	$(OBJDIR)/fpgaimage.s19 - The FPGA image
	@echo +	clean             - Clean $(OBJDIR)

