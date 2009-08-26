# Makefile for armsrc, see ../common/Makefile.common for common settings

APP_INCLUDES = apps.h

# Add the "-DWITH_LCD" flag in APP_CLFAGS to add support for LCD
# and add SRC_LCD to SRC_MAIN
APP_CFLAGS	= -O6

SRC_LCD = fonts.c LCD.c

SRC_MAIN = start.c \
	appmain.c \
	fpga.c \
	lfops.c \
	iso15693.c \
	util.c \
	usb.c

# These are to be compiled in ARM mode
SRC_MAIN_FAST =  iso14443.c \
	iso14443a.c

SRC_FPGA = fpgaimg.c

THUMBSRC = $(SRC_MAIN) $(SRC_FPGA)
ARMSRC = $(SRC_MAIN_FAST)

MAIN_OBJ = $(patsubst %.c,$(OBJDIR)/%.o,$(SRC_MAIN) $(SRC_MAIN_FAST))

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}{OBJ,SRC}
include ../common/Makefile.common

all: $(OBJDIR)/osimage.s19 $(OBJDIR)/fpgaimage.s19

$(OBJDIR)/fpgaimage.elf: $(OBJDIR)/fpgaimg.o
	$(LD) -g -Tldscript-fpga -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/osimage.elf: $(MAIN_OBJ) $(ARMLIB)/libgcc.a
	$(LD) -g -Tldscript -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

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
	@echo +	all           - Make both:
	@echo +	osimage.s19   - The OS image
	@echo +	fpgaimage.s19 - The FPGA image
	@echo +	clean         - Clean $(OBJDIR)

