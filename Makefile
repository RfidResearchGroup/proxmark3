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

ifeq ($(PLATFORM),)
  -include Makefile.platform
  ifeq ($(PLATFORM),)
    PLATFORM=PM3RDV4
  else
    ${info using saved PLATFORM '$(PLATFORM)'}
  endif
endif

include common/Makefile.hal

$(info ===================================================================)
$(info PLATFORM: $(PLATFORM))
$(info $(PLTNAME))
$(info Included supports: $(PLATFORM_DEFS))
$(info ===================================================================)

all clean: %: client/% bootrom/% armsrc/% recovery/% mfkey/% nonce2key/%

mfkey/%: FORCE
	$(MAKE) -C tools/mfkey $(patsubst mfkey/%,%,$@)
nonce2key/%: FORCE
	$(MAKE) -C tools/nonce2key $(patsubst nonce2key/%,%,$@)
bootrom/%: FORCE
	$(MAKE) -C bootrom $(patsubst bootrom/%,%,$@)
armsrc/%: FORCE
	$(MAKE) -C armsrc $(patsubst armsrc/%,%,$@)
client/%: FORCE
	$(MAKE) -C client $(patsubst client/%,%,$@)
recovery/%: FORCE
	$(MAKE) -C recovery $(patsubst recovery/%,%,$@)
FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.PHONY: all clean help _test bootrom flash-bootrom os flash-os flash-all recovery client mfkey nounce2key style FORCE

help:
	@echo "Multi-OS Makefile"
	@echo
	@echo "Possible targets:"
	@echo "+ all           - Make all targets: bootrom, armsrc and OS-specific host tools"
	@echo "+ clean         - Clean in all targets"
	@echo
	@echo "+ bootrom       - Make bootrom"
	@echo "+ os            - Make armsrc \(includes fpga\)"
	@echo "+ flash-bootrom - Make bootrom and flash it"
	@echo "+ flash-os      - Make armsrc and flash os image \(includes fpga\)"
	@echo "+ flash-all     - Make bootrom and armsrc and flash bootrom and os image"
	@echo "+ recovery      - Make bootrom and armsrc images for JTAG flashing"
	@echo
	@echo "+ client        - Make only the OS-specific host client"
	@echo "+ mfkey         - Make tools/mfkey"
	@echo "+ nounce2key    - Make tools/nounce2key"
	@echo
	@echo "Possible platforms: try \"make PLATFORM=\" for more info, default is PM3RDV4"

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
	$(GZIP) proxmark3-$(platform)-bin.tar

# configure system
#  - to ignore PM3 device as a modem (blacklist)
#  - add user to the dialout group
# you may need to logout, relogin to get this access right correct.
# Finally,  you might need to run the proxmark3 client under SUDO on some systems
udev:
	sudo cp -rf driver/77-pm3-usb-device-blacklist.rules /etc/udev/rules.d/77-pm3-usb-device-blacklist.rules
	sudo udevadm control --reload-rules
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
	    -exec perl -pi -e 's/[ \t\r]+$$//' {} \; \
	    -exec sh -c "tail -c1 {} | xxd -p | tail -1 | grep -q -v 0a$$" \; \
	    -exec sh -c "echo >> {}" \;
	# Apply astyle on *.c, *.h, *.cpp
	find . \( -name "*.[ch]" -or -name "*.cpp" \) -exec astyle --formatted --mode=c --suffix=none \
	    --indent=spaces=4 --indent-switches --indent-preprocessor \
	    --keep-one-line-blocks --max-instatement-indent=60 \
	    --style=google --pad-oper --unpad-paren --pad-header \
	    --align-pointer=name {} \;

# Dummy target to test for GNU make availability
_test:
