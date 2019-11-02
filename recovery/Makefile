include ../common_arm/Makefile.common

INSTALLFW = proxmark3_recovery.bin
ifneq (,$(FWTAG))
    INSTALLFWTAG = $(notdir $(INSTALLFW:%.bin=%-$(FWTAG).bin))
else
    INSTALLFWTAG = $(notdir $(INSTALLFW))
endif

BINS = bootrom.bin fullimage.bin $(INSTALLFW)

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
	$(Q)$(RM) $(BINS)

install: all
	$(info [@] Installing recovery to $(DESTDIR)$(PREFIX)...)
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

uninstall:
	$(info [@] Uninstalling recovery from $(DESTDIR)$(PREFIX)...)
	$(Q)$(RM) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

.PHONY: all clean install uninstall
