# Hide full compilation line:
ifneq ($(V),1)
  Q?=@
endif
# To see full command lines, use make V=1

COPY=cp
GZIP=gzip
-include Makefile.platform
-include .Makefile.options.cache
include common_arm/Makefile.hal

all clean install uninstall: %: client/% bootrom/% armsrc/% recovery/% mfkey/% nonce2key/% fpga_compress/%

mfkey/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/mfkey $(patsubst mfkey/%,%,$@)
nonce2key/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/nonce2key $(patsubst nonce2key/%,%,$@)
fpga_compress/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/fpga_compress $(patsubst fpga_compress/%,%,$@)
bootrom/%: FORCE cleanifplatformchanged
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C bootrom $(patsubst bootrom/%,%,$@)
armsrc/%: FORCE cleanifplatformchanged fpga_compress/%
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C armsrc $(patsubst armsrc/%,%,$@)
client/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C client $(patsubst client/%,%,$@)
recovery/%: FORCE cleanifplatformchanged bootrom/% armsrc/%
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C recovery $(patsubst recovery/%,%,$@)
FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.PHONY: all clean install uninstall help _test bootrom fullimage recovery client mfkey nonce2key style checks FORCE udev accessrights cleanifplatformchanged

help:
	@echo "Multi-OS Makefile"
	@echo
	@echo "Possible targets:"
	@echo "+ all             - Make all targets: bootrom, fullimage and OS-specific host tools"
	@echo "+ clean           - Clean in all targets"
	@echo "+ .../clean       - Clean in specified target and its deps, e.g. bootrom/clean"
	@echo
	@echo "+ bootrom         - Make bootrom"
	@echo "+ fullimage       - Make armsrc fullimage (includes fpga)"
	@echo "+ recovery        - Make bootrom and fullimage files for JTAG flashing"
	@echo
	@echo "+ client          - Make only the OS-specific host client"
	@echo "+ mfkey           - Make tools/mfkey"
	@echo "+ nonce2key       - Make tools/nonce2key"
	@echo "+ fpga_compress   - Make tools/fpga_compress"
	@echo
	@echo "+ style           - Apply some automated source code formatting rules"
	@echo "+ checks          - Detect various encoding issues in source code"
	@echo
	@echo "Possible platforms: try \"make PLATFORM=\" for more info, default is PM3RDV4"
	@echo "To activate verbose mode, use make V=1"

client: client/all

bootrom: bootrom/all

fullimage: armsrc/all

fullimage/clean: armsrc/clean

recovery: recovery/all

mfkey: mfkey/all

nonce2key: nonce2key/all

fpga_compress: fpga_compress/all

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
	find . \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" -or -name "*.v" \) \
	    -exec perl -pi -e 's/[ \t]+$$//' {} \; \
	    -exec sh -c "tail -c1 {} | xxd -p | tail -1 | grep -q -v 0a$$" \; \
	    -exec sh -c "echo >> {}" \;
	# Apply astyle on *.c, *.h, *.cpp
	find . \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) \) -exec astyle --formatted --mode=c --suffix=none \
	    --indent=spaces=4 --indent-switches \
	    --keep-one-line-blocks --max-instatement-indent=60 \
	    --style=google --pad-oper --unpad-paren --pad-header \
	    --align-pointer=name {} \;

# Detecting weird codepages and tabs.
checks:
	@echo "Files with suspicious chars:"
	@find . \( -name "*.[ch]" -or -name "*.cpp" -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" -or -name "*.v" \) \
	      -exec sh -c "cat {} |recode utf8.. >/dev/null || echo {}" \;
	@echo "Files with tabs:"
# to remove tabs within lines, one can try with: vi $file -c ':set tabstop=4' -c ':set et|retab' -c ':wq'
	@find . \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "*.md" -or -name "*.txt" -or -name "*.awk" -or -name "*.v" \) \
	      -exec grep -lP '\t' {} \;
#	@echo "Files with printf \\\\t:"
#	@find . \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "*.md" -or -name "*.txt" -or -name "*.awk" -or -name "*.v" \) \
#	      -exec grep -lP '\\t' {} \;

# Dummy target to test for GNU make availability
_test:
