include ../common_arm/Makefile.common

INSTALLFW = proxmark3_recovery.bin
ifneq (,$(FWTAG))
    INSTALLFWTAG = $(notdir $(INSTALLFW:%.bin=%-$(FWTAG).bin))
else
    INSTALLFWTAG = $(notdir $(INSTALLFW))
endif
FWMAXSIZE = $(shell echo $$(($(PLATFORM_SIZE)*1024)))

BINS = bootrom.bin fullimage.bin $(INSTALLFW)

all: $(BINS)
	@FWSIZE=$$(wc -c < $(INSTALLFW));\
	if [ $$FWSIZE -gt $(FWMAXSIZE) ]; then \
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"; \
	    echo "ERROR: Firmware image too large for your platform! $$FWSIZE > $(FWMAXSIZE)"; \
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"; \
		exit 1; \
	fi

bootrom.bin: ../bootrom/obj/bootrom.elf
	$(info [=] GEN $@)
	$(Q)$(CROSS_OBJCOPY) --gap-fill=0xff --pad-to 0x00102000 -O binary $^ $@

fullimage.bin: ../armsrc/obj/fullimage.elf
	$(info [=] GEN $@)
	$(Q)$(CROSS_OBJCOPY) --gap-fill=0xff -O binary $^ $@

proxmark3_recovery.bin: bootrom.bin fullimage.bin
	$(info [=] GEN $@)
	$(Q)cat bootrom.bin fullimage.bin > $@

clean:
	$(Q)$(RM) $(BINS)

install: all
	$(info [@] Installing recovery to $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(INSTALLSUDO) $(CP) $(INSTALLFW) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

uninstall:
	$(info [@] Uninstalling recovery from $(DESTDIR)$(PREFIX)...)
	$(Q)$(INSTALLSUDO) $(RM) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(INSTALLFWTAG)

.PHONY: all clean install uninstall
