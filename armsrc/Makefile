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
APP_CFLAGS	= -O6 -DWITH_LF -DWITH_ISO15693 -DWITH_ISO14443a -DWITH_ISO14443b
#-DWITH_LCD 

#SRC_LCD = fonts.c LCD.c
SRC_LF = lfops.c hitag2.c
SRC_ISO15693 = iso15693.c
SRC_ISO14443a = iso14443a.c
SRC_ISO14443b = iso14443.c

THUMBSRC = start.c \
	$(SRC_LCD) \
	$(SRC_ISO15693) \
	$(SRC_LF) \
	appmain.c printf.c \
	util.c \
	string.c \
	usb.c

# These are to be compiled in ARM mode
ARMSRC = fpgaloader.c \
	legicrf.c \
	iso14443crc.c \
	crc16.c \
	$(SRC_ISO14443a) \
	$(SRC_ISO14443b) \
        legic_prng.c \
	crc.c

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
APP_CFLAGS += -I.

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

all: $(OBJDIR)/osimage.s19 $(OBJDIR)/fpgaimage.s19

$(OBJDIR)/fpga.o: fpga.bit
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --redefine-sym _binary____fpga_fpga_bit_start=_binary_fpga_bit_start --redefine-sym _binary____fpga_fpga_bit_end=_binary_fpga_bit_end --prefix-sections=fpga_bit  $^ $@

$(OBJDIR)/fullimage.elf: $(VERSIONOBJ) $(OBJDIR)/fpga.o $(THUMBOBJ) $(ARMOBJ)
	$(CC) $(LDFLAGS) -Wl,-T,ldscript,-Map,$(patsubst %.elf,%.map,$@) -o $@ $^ $(LIBS)

$(OBJDIR)/fpgaimage.elf: $(OBJDIR)/fullimage.elf
	$(OBJCOPY) -F elf32-littlearm --only-section .fpgaimage $^ $@  

$(OBJDIR)/osimage.elf: $(OBJDIR)/fullimage.elf
	$(OBJCOPY) -F elf32-littlearm --remove-section .fpgaimage $^ $@

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

