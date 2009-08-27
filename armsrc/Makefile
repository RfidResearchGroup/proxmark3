# Makefile for armsrc, see ../common/Makefile.common for common settings

APP_INCLUDES = apps.h

# Add the "-DWITH_LCD" flag in APP_CLFAGS to add support for LCD
# and add SRC_LCD to THUMBSRC
APP_CFLAGS	= -O6

SRC_LCD = fonts.c LCD.c

THUMBSRC = start.c \
	appmain.c \
	lfops.c \
	iso15693.c \
	util.c \
	usb.c

# These are to be compiled in ARM mode
ARMSRC =  iso14443.c \
	iso14443a.c \
	fpgaloader.c

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

all: $(OBJDIR)/osimage.s19 $(OBJDIR)/fpgaimage.s19

$(OBJDIR)/fpga.o: fpga.bit
	$(OBJCOPY) -O elf32-littlearm -I binary -B arm --redefine-sym _binary____fpga_fpga_bit_start=_binary_fpga_bit_start --redefine-sym _binary____fpga_fpga_bit_end=_binary_fpga_bit_end --prefix-sections=fpga_bit  $^ $@

$(OBJDIR)/fullimage.elf: $(OBJDIR)/fpga.o $(THUMBOBJ) $(ARMOBJ) $(ARMLIB)/libgcc.a
	$(LD) -g -Tldscript -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/fpgaimage.elf: $(OBJDIR)/fullimage.elf
	$(OBJCOPY) -F elf32-littlearm --only-section fpgaimage $^ $@  

$(OBJDIR)/osimage.elf: $(OBJDIR)/fullimage.elf
	$(OBJCOPY) -F elf32-littlearm --remove-section fpgaimage $^ $@

clean:
	$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(DELETE) $(OBJDIR)$(PATHSEP)*.map
	$(DELETE) $(OBJDIR)$(PATHSEP)*.d

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all               - Make both:
	@echo +	$(OBJDIR)/osimage.s19   - The OS image
	@echo +	$(OBJDIR)/fpgaimage.s19 - The FPGA image
	@echo +	clean             - Clean $(OBJDIR)

