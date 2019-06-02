include ../common/Makefile.common

BINS = bootrom.bin fullimage.bin proxmark3_recovery.bin

all: $(BINS)

bootrom.bin: ../bootrom/obj/bootrom.elf
	$(info [=] GEN $@)
	$(Q)$(OBJCOPY) --gap-fill=0xff --pad-to 0x00102000 -O binary $^ $@

fullimage.bin: ../armsrc/obj/fullimage.elf
	$(info [=] GEN $@)
	$(Q)$(OBJCOPY) --gap-fill=0xff -O binary $^ $@

proxmark3_recovery.bin: bootrom.bin fullimage.bin
	$(info [=] GEN $@)
	$(Q)cat bootrom.bin fullimage.bin > $@

clean:
	$(Q)rm -f $(BINS)

