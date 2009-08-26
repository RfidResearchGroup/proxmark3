# Makefile for armsrc, see ../common/Makefile.common for common settings
include ../common/Makefile.common

APP_INCLUDES = apps.h

# Add the "-DWITH_LCD" flag in APP_CLFAGS to add support for LCD
# and add OBJLCD to OBJ too
APP_CFLAGS	= -O6

OBJLCD = $(OBJDIR)/fonts.o \
		$(OBJDIR)/LCD.o

OBJ =	$(OBJDIR)/start.o \
		$(OBJDIR)/appmain.o \
		$(OBJDIR)/fpga.o \
		$(OBJDIR)/lfops.o \
		$(OBJDIR)/iso14443.o \
		$(OBJDIR)/iso14443a.o \
		$(OBJDIR)/iso15693.o \
		$(OBJDIR)/util.o \
		$(OBJDIR)/usb.o

OBJFPGA = \
		$(OBJDIR)/fpgaimg.o

all: $(OBJDIR)/osimage.s19 $(OBJDIR)/fpgaimage.s19

$(OBJDIR)/fpgaimage.elf: $(OBJDIR)/fpgaimg.o
	$(LD) -g -Tldscript-fpga -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/osimage.elf: $(OBJ) $(OBJCOMMON) $(ARMLIB)/libgcc.a
	$(LD) -g -Tldscript -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/%.s19: $(OBJDIR)/%.elf
	$(OBJCOPY) -Osrec --srec-forceS3 $^ $@

$(OBJ) $(OBJFPGA): $(OBJDIR)/%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -mthumb -mthumb-interwork $< -o $@

clean:
	$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(DELETE) $(OBJDIR)$(PATHSEP)*.map

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all           - Make both:
	@echo +	osimage.s19   - The OS image
	@echo +	fpgaimage.s19 - The FPGA image
	@echo +	clean         - Clean $(OBJDIR)
