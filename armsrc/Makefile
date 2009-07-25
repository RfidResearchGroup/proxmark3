PATH=..\..\devkitARM\bin;%PATH%
CC	= arm-elf-gcc
AS	= arm-elf-as
LD	= arm-elf-ld
OBJCOPY = arm-elf-objcopy

OBJDIR	= obj

INCLUDE = -I../include

INCLUDES = ../include/proxmark3.h ../include/at91sam7s128.h ../include/config_gpio.h ../include/usb_cmd.h apps.h
LIB = "..\..\devkitARM\lib\gcc\arm-elf\4.1.0\interwork"

# Add the "-DWITH_LCD" flag in CLFAGS to add support for LCD
# and add OBJLCD to OBJ too
CFLAGS	= -O6 -c $(INCLUDE) -Wall

OBJLCD = $(OBJDIR)/fonts.o \
		$(OBJDIR)/LCD.o

OBJ =	$(OBJDIR)/start.o \
		$(OBJDIR)/appmain.o \
		$(OBJDIR)/fpga.o \
		$(OBJDIR)/lfops.o \
		$(OBJDIR)/iso14443.o \
		$(OBJDIR)/iso14443a.o \
		$(OBJDIR)/iso15693.o \
		$(OBJDIR)/util.o

OBJFPGA = \
		$(OBJDIR)/fpgaimg.o

OBJCOMMON = \
		$(OBJDIR)/usb.o

all: osimage.s19

$(OBJDIR)/fpgaimage.s19: $(OBJDIR)/fpgaimg.o
	@echo obj/fpgaimage.s19
	@$(LD) -g -Tldscript-fpga -o $(OBJDIR)\fpgaimage.elf $(OBJDIR)/fpgaimg.o
	@$(OBJCOPY) -Osrec --srec-forceS3 $(OBJDIR)\fpgaimage.elf $(OBJDIR)\fpgaimage.s19

$(OBJDIR)/osimage.s19: $(OBJ) $(OBJCOMMON)
	@echo obj/osimage.s19
	@$(LD) -g -Tldscript -o $(OBJDIR)\osimage.elf $(OBJ) $(OBJCOMMON) $(LIB)\libgcc.a
	@$(OBJCOPY) -Osrec --srec-forceS3 $(OBJDIR)\osimage.elf $(OBJDIR)\osimage.s19

osimage.s19: $(OBJDIR)/osimage.s19 $(OBJDIR)/fpgaimage.s19
	@echo osimage.s19

$(OBJ): $(@B).c $(INCLUDES)
	@echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork $(@B).c -o $(OBJDIR)/$(@B).o

$(OBJCOMMON): ../common/$(@B).c $(INCLUDES)
	@echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork ../common/$(@B).c -o $(OBJDIR)/$(@B).o

$(OBJFPGA): $(@B).c $(INCLUDES)
	@echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork $(@B).c -o $(OBJDIR)/$(@B).o

clean:
	del /q obj\*.o
	del /q obj\*.elf
	del /q obj\*.s19
