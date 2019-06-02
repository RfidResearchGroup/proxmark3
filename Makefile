# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

GZIP=gzip
# Windows' echo echos its input verbatim, on Posix there is some
#  amount of shell command line parsing going on. echo "" on
#  Windows yields literal "", on Linux yields an empty line
ifeq ($(shell echo ""),)
    # This is probably a proper system, so we can use uname
    DELETE=rm -rf
    FLASH_TOOL=client/flasher
    platform=$(shell uname)
    ifneq (,$(findstring MINGW,$(platform)))
        FLASH_PORT=com3
        PATHSEP=\\#
    else
        FLASH_PORT=/dev/ttyACM0
        PATHSEP=/
    endif
else
    # Assume that we are running on native Windows
    DELETE=del /q
    FLASH_TOOL=client/flasher.exe
    platform=Windows
    FLASH_PORT=com3
    PATHSEP=\\#
endif

-include Makefile.platform
-include .Makefile.options.cache
include common/Makefile.hal

all clean: %: client/% bootrom/% armsrc/% recovery/% mfkey/% nonce2key/%

mfkey/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/mfkey $(patsubst mfkey/%,%,$@)
nonce2key/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/nonce2key $(patsubst nonce2key/%,%,$@)
bootrom/%: FORCE cleanifplatformchanged
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C bootrom $(patsubst bootrom/%,%,$@)
armsrc/%: FORCE cleanifplatformchanged
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C armsrc $(patsubst armsrc/%,%,$@)
client/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C client $(patsubst client/%,%,$@)
recovery/%: FORCE cleanifplatformchanged bootrom/% armsrc/%
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C recovery $(patsubst recovery/%,%,$@)
FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.PHONY: all clean help _test bootrom flash-bootrom os flash-os flash-all recovery client mfkey nounce2key style checks FORCE udev accessrights cleanifplatformchanged

help:
	@echo "Multi-OS Makefile"
	@echo
	@echo "Possible targets:"
	@echo "+ all           - Make all targets: bootrom, armsrc and OS-specific host tools"
	@echo "+ clean         - Clean in all targets"
	@echo
	@echo "+ bootrom       - Make bootrom"
	@echo "+ os            - Make armsrc (includes fpga)"
	@echo "+ flash-bootrom - Make bootrom and flash it"
	@echo "+ flash-os      - Make armsrc and flash os image (includes fpga)"
	@echo "+ flash-all     - Make bootrom and armsrc and flash bootrom and os image"
	@echo "+ recovery      - Make bootrom and armsrc images for JTAG flashing"
	@echo
	@echo "+ client        - Make only the OS-specific host client"
	@echo "+ mfkey         - Make tools/mfkey"
	@echo "+ nounce2key    - Make tools/nounce2key"
	@echo
	@echo "+ style         - Apply some automated source code formatting rules"
	@echo "+ checks        - Detect various encoding issues in source code"
	@echo
	@echo "Possible platforms: try \"make PLATFORM=\" for more info, default is PM3RDV4"
	@echo "To activate verbose mode, use make V=1"

client: client/all

bootrom: bootrom/all

os: armsrc/all

recovery: recovery/all

mfkey: mfkey/all

nonce2key: nonce2key/all

flash-bootrom: bootrom/obj/bootrom.elf $(FLASH_TOOL)
	$(FLASH_TOOL) $(FLASH_PORT) -b $(subst /,$(PATHSEP),$<)

flash-os: armsrc/obj/fullimage.elf $(FLASH_TOOL)
	$(FLASH_TOOL) $(FLASH_PORT) $(subst /,$(PATHSEP),$<)

flash-all: bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf $(FLASH_TOOL)
	$(FLASH_TOOL) $(FLASH_PORT) -b $(subst /,$(PATHSEP),$(filter-out $(FLASH_TOOL),$^))

newtarbin:
	$(DELETE) proxmark3-$(platform)-bin.tar proxmark3-$(platform)-bin.tar.gz
	@touch proxmark3-$(platform)-bin.tar

tarbin: newtarbin client/tarbin armsrc/tarbin bootrom/tarbin
	$(info GEN proxmark3-$(platform)-bin.tar)
	$(Q)$(GZIP) proxmark3-$(platform)-bin.tar

# detect if there were changes in the platform definitions, requiring a clean
cleanifplatformchanged:
ifeq ($(PLATFORM_CHANGED), true)
	$(info [!] Platform definitions changed, cleaning bootrom/armsrc/recovery first...)
	$(Q)$(MAKE) --no-print-directory -C bootrom clean
	$(Q)$(MAKE) --no-print-directory -C armsrc clean
	$(Q)$(MAKE) --no-print-directory -C recovery clean
	$(Q)echo CACHED_PLATFORM=$(PLATFORM) > .Makefile.options.cache
	$(Q)echo CACHED_PLATFORM_EXTRAS=$(PLATFORM_EXTRAS) >> .Makefile.options.cache
	$(Q)echo CACHED_PLATFORM_DEFS=$(PLATFORM_DEFS) >> .Makefile.options.cache
endif

# configure system to ignore PM3 device as a modem (ModemManager blacklist, effective *only* if ModemManager is not using _strict_ policy)
# Read doc/md/ModemManager-Must-Be-Discarded.md for more info
udev:
	sudo cp -rf driver/77-pm3-usb-device-blacklist.rules /etc/udev/rules.d/77-pm3-usb-device-blacklist.rules
	sudo udevadm control --reload-rules

# configure system to add user to the dialout group
# you need to logout, relogin to get this access right correct.
# Finally,  you might need to run the proxmark3 client under SUDO on some systems
accessrights:
ifneq ($(wildcard /etc/arch-release),) #If user is running ArchLinux
	sudo usermod -aG uucp $(USER) #Use specific command and group
else
	sudo adduser $(USER) dialout
endif

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

style:
	# Make sure astyle is installed
	@which astyle >/dev/null || ( echo "Please install 'astyle' package first" ; exit 1 )
	# Remove spaces & tabs at EOL, add LF at EOF if needed on *.c, *.h, *.cpp. *.lua, *.py, *.pl, Makefile
	find . \( -name "*.[ch]" -or -name "*.cpp" -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" \) \
	    -exec perl -pi -e 's/[ \t]+$$//' {} \; \
	    -exec sh -c "tail -c1 {} | xxd -p | tail -1 | grep -q -v 0a$$" \; \
	    -exec sh -c "echo >> {}" \;
	# Apply astyle on *.c, *.h, *.cpp
	find . \( -name "*.[ch]" -or -name "*.cpp" \) -exec astyle --formatted --mode=c --suffix=none \
	    --indent=spaces=4 --indent-switches \
	    --keep-one-line-blocks --max-instatement-indent=60 \
	    --style=google --pad-oper --unpad-paren --pad-header \
	    --align-pointer=name {} \;

# Detecting weird codepages.
checks:
	find . \( -name "*.[ch]" -or -name "*.cpp" -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" \) \
	      -exec sh -c "cat {} |recode utf8.. >/dev/null || echo {}" \;

# Dummy target to test for GNU make availability
_test:
