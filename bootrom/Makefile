CC	  = arm-elf-gcc
AS	  = arm-elf-as
LD	  = arm-elf-ld
OBJCOPY = arm-elf-objcopy

OBJDIR  = obj

INCLUDE = -I../include

INCLUDES = ../include/proxmark3.h ../include/at91sam7s128.h ../include/config_gpio.h ../include/usb_cmd.h

CFLAGS  = -g -c $(INCLUDE) -Wall

OBJJTAG = $(OBJDIR)/bootrom.o $(OBJDIR)/ram-reset.o $(OBJDIR)/usb.o

OBJFLASH = $(OBJDIR)/flash-reset.o $(OBJDIR)/fromflash.o

all: bootrom.s19

bootrom.s19: $(OBJDIR)/bootrom.s19 $(OBJDIR)/bootrom-forjtag.s19
    @echo bootrom.s19
	@perl ..\tools\merge-srec.pl $(OBJDIR)\bootrom.s19 $(OBJDIR)\bootrom-forjtag.s19 > $(OBJDIR)\bootrom-merged.s19
	@perl ..\tools\srecswap.pl $(OBJDIR)\bootrom-forjtag.s19 > $(OBJDIR)\bootrom-forjtag-swapped.s19

$(OBJDIR)/bootrom.s19: $(OBJFLASH)
    @echo obj/bootrom.s19
	@$(LD) -g -Tldscript-flash --oformat elf32-littlearm -Map=obj/bootrom.map -o $(OBJDIR)/bootrom.elf $(OBJFLASH)
	@$(OBJCOPY) -Osrec --srec-forceS3 $(OBJDIR)/bootrom.elf $(OBJDIR)/bootrom.s19

$(OBJDIR)/bootrom-forjtag.s19: $(OBJJTAG)
    @echo obj/bootrom-forjtag.s19
	@$(LD) -g -Tldscript-ram-jtag --oformat elf32-littlearm -Map=obj/bootrom-forjtag.map -o $(OBJDIR)/bootrom-forjtag.elf $(OBJJTAG)
	@$(OBJCOPY) -Osrec --srec-forceS3 $(OBJDIR)/bootrom-forjtag.elf $(OBJDIR)/bootrom-forjtag.s19

$(OBJDIR)/bootrom.o: bootrom.c $(INCLUDES)
    @echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork bootrom.c -o $(OBJDIR)/bootrom.o

$(OBJDIR)/fromflash.o: fromflash.c $(INCLUDES)
    @echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork fromflash.c -o $(OBJDIR)/fromflash.o

$(OBJDIR)/usb.o: ../common/usb.c $(INCLUDES)
    @echo $(@B).c
	@$(CC) $(CFLAGS) -mthumb -mthumb-interwork ../common/usb.c -o $(OBJDIR)/usb.o

$(OBJDIR)/ram-reset.o: ram-reset.s
    @echo $(@B).s
	@$(CC) $(CFLAGS) -mthumb-interwork -o $(OBJDIR)/ram-reset.o ram-reset.s

$(OBJDIR)/flash-reset.o: flash-reset.s
    @echo $(@B).s
	@$(CC) $(CFLAGS) -mthumb-interwork -o $(OBJDIR)/flash-reset.o flash-reset.s

clean:
	del /q obj\*.o
	del /q obj\*.elf
	del /q obj\*.s19
