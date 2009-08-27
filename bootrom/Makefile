# Makefile for bootrom, see ../common/Makefile.common for common settings

# DO NOT use thumb mode in the phase 1 bootloader since that generates a section with glue code
ARMSRC = fromflash.c 
THUMBSRC = usb.c bootrom.c
ASMSRC = ram-reset.s flash-reset.s

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include ../common/Makefile.common

all: $(OBJDIR)/bootrom.s19

$(OBJDIR)/bootrom.elf: $(ASMOBJ) $(ARMOBJ) $(THUMBOBJ)
	$(LD) -g -Tldscript-flash --oformat elf32-littlearm -Map=$(patsubst %.elf,%.map,$@) -o $@ $^

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
	@echo +	all   - Make $(OBJDIR)/bootrom.s19, the main bootrom
	@echo +	clean - Clean $(OBJDIR)
