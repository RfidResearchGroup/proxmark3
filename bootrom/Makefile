# Makefile for bootrom, see ../common/Makefile.common for common settings
include ../common/Makefile.common

OBJJTAG = $(OBJDIR)/bootrom.o $(OBJDIR)/ram-reset.o $(OBJDIR)/usb.o
OBJFLASH = $(OBJDIR)/flash-reset.o $(OBJDIR)/fromflash.o

THUMBSRC = usb.c fromflash.c bootrom.c
ASMSRC   = ram-reset.s flash-reset.s

THUMBOBJ = $(patsubst %.c,$(OBJDIR)/%.o,$(THUMBSRC))
ASMOBJ   = $(patsubst %.s,$(OBJDIR)/%.o,$(ASMSRC))

all: bootrom-merged.s19

bootrom-merged.s19: $(OBJDIR)/bootrom.s19 $(OBJDIR)/bootrom-forjtag.s19
	perl ../tools/merge-srec.pl $(OBJDIR)/bootrom.s19 $(OBJDIR)/bootrom-forjtag.s19 > bootrom-merged.s19

$(OBJDIR)/bootrom.elf: $(OBJFLASH)
	$(LD) -g -Tldscript-flash --oformat elf32-littlearm -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/bootrom-forjtag.elf: $(OBJJTAG)
	$(LD) -g -Tldscript-ram-jtag --oformat elf32-littlearm -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

$(OBJDIR)/%.s19: $(OBJDIR)/%.elf
	$(OBJCOPY) -Osrec --srec-forceS3 $^ $@

$(THUMBOBJ): $(OBJDIR)/%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -mthumb -mthumb-interwork -o $@ $< 

$(ASMOBJ): $(OBJDIR)/%.o: %.s
	$(CC) $(CFLAGS) -mthumb-interwork -o $@ $<

clean:
	$(DELETE) $(OBJDIR)$(PATHSEP)*.o
	$(DELETE) $(OBJDIR)$(PATHSEP)*.elf
	$(DELETE) $(OBJDIR)$(PATHSEP)*.s19
	$(DELETE) $(OBJDIR)$(PATHSEP)*.map
	$(DELETE) bootrom-merged.s19

.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all   - Make bootrom-merged.s19, the main bootrom
	@echo +	clean - Clean $(OBJDIR)
