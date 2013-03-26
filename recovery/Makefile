include ../common/Makefile.common

BINS = bootrom.bin fullimage.bin proxmark3_recovery.bin

all: $(BINS)
#%: ../bootrom/% ../armsrc/% $(BINS)
#clean: %: ../bootrom/% ../armsrc/%
#	rm *.bin

bootrom.bin: ../bootrom/obj/bootrom.elf
	$(OBJCOPY) --gap-fill=0xff --pad-to 0x00102000 -O binary $^ $@

fullimage.bin: ../armsrc/obj/fullimage.elf
	$(OBJCOPY) --gap-fill=0xff -O binary $^ $@

proxmark3_recovery.bin: bootrom.bin fullimage.bin
	cat bootrom.bin fullimage.bin > $@
	chmod 755 $@

clean: 
	rm -f $(BINS)

