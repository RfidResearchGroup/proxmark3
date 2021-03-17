
include Makefile.defs
-include Makefile.platform
-include .Makefile.options.cache
include common_arm/Makefile.hal

# preserve relative DESTDIR path for subdir makes
ifneq (,$(DESTDIR))
    # realpath needs the directory to exist
    $(shell $(MKDIR) $(DESTDIR))
    MYDESTDIR:=$(realpath $(DESTDIR))
    ifeq (,$(MYDESTDIR))
        $(error Can't create $(DESTDIR))
    endif
endif

all clean install uninstall check: %: client/% bootrom/% armsrc/% recovery/% mfkey/% nonce2key/% mf_nonce_brute/% fpga_compress/%
# hitag2crack toolsuite is not yet integrated in "all", it must be called explicitly: "make hitag2crack"
#all clean install uninstall check: %: hitag2crack/%

INSTALLTOOLS=pm3_eml2lower.sh pm3_eml2upper.sh pm3_mfdread.py pm3_mfd2eml.py pm3_eml2mfd.py findbits.py rfidtest.pl xorcheck.py
INSTALLSIMFW=sim011.bin sim011.sha512.txt
INSTALLSCRIPTS=pm3 pm3-flash pm3-flash-all pm3-flash-bootrom pm3-flash-fullimage
INSTALLSHARES=tools/jtag_openocd traces
INSTALLDOCS=doc/*.md doc/md

install: all common/install

common/install:
	$(info [@] Installing common resources to $(MYDESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLSCRIPTS))
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
	$(Q)$(CP) $(INSTALLSCRIPTS) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)
endif
ifneq (,$(INSTALLSHARES))
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
	$(Q)$(CP) $(INSTALLSHARES) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)
endif
ifneq (,$(INSTALLDOCS))
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLDOCSRELPATH)
	$(Q)$(CP) $(INSTALLDOCS) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLDOCSRELPATH)
endif
ifneq (,$(INSTALLTOOLS))
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLTOOLSRELPATH)
	$(Q)$(CP) $(foreach tool,$(INSTALLTOOLS),tools/$(tool)) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLTOOLSRELPATH)
endif
ifneq (,$(INSTALLSIMFW))
	$(Q)$(MKDIR) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
	$(Q)$(CP) $(foreach fw,$(INSTALLSIMFW),client/resources/$(fw)) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
endif
ifeq ($(platform),Linux)
	$(Q)$(MKDIR) $(DESTDIR)$(UDEV_PREFIX)
	$(Q)$(CP) driver/77-pm3-usb-device-blacklist.rules $(DESTDIR)$(UDEV_PREFIX)/77-pm3-usb-device-blacklist.rules
endif

uninstall: common/uninstall

common/uninstall:
	$(info [@] Uninstalling common resources from $(MYDESTDIR)$(PREFIX)...)
ifneq (,$(INSTALLSCRIPTS))
	$(Q)$(RM) $(foreach script,$(INSTALLSCRIPTS),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLBINRELPATH)$(PATHSEP)$(notdir $(script)))
endif
ifneq (,$(INSTALLSHARES))
	$(Q)$(RMDIR) $(foreach share,$(INSTALLSHARES),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)$(PATHSEP)$(notdir $(share)))
endif
ifneq (,$(INSTALLDOCS))
	$(Q)$(RMDIR) $(foreach doc,$(INSTALLDOCS),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLDOCSRELPATH)$(PATHSEP)$(notdir $(doc)))
	$(Q)$(RMDIR_SOFT) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLDOCSRELPATH)
endif
ifneq (,$(INSTALLTOOLS))
	$(Q)$(RM) $(foreach tool,$(INSTALLTOOLS),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLTOOLSRELPATH)$(PATHSEP)$(notdir $(tool)))
endif
	$(Q)$(RMDIR_SOFT) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLTOOLSRELPATH)
ifneq (,$(INSTALLSIMFW))
	$(Q)$(RM) $(foreach fw,$(INSTALLSIMFW),$(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)$(PATHSEP)$(notdir $(fw)))
endif
	$(Q)$(RMDIR_SOFT) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLFWRELPATH)
ifeq ($(platform),Linux)
	$(Q)$(RM) $(DESTDIR)$(UDEV_PREFIX)/77-pm3-usb-device-blacklist.rules
endif
	$(Q)$(RMDIR_SOFT) $(DESTDIR)$(PREFIX)$(PATHSEP)$(INSTALLSHARERELPATH)

# tests
mfkey/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
nonce2key/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
mf_nonce_brute/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
fpga_compress/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
bootrom/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
armsrc/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
client/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
recovery/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
hitag2crack/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
common/check: FORCE
	$(info [*] CHECK $(patsubst %/check,%,$@))
	$(Q)$(BASH) tools/pm3_tests.sh $(CHECKARGS) $(patsubst %/check,%,$@)
check: common/check
	$(info [*] ALL CHECKS DONE)

mfkey/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/mfkey $(patsubst mfkey/%,%,$@) DESTDIR=$(MYDESTDIR)
nonce2key/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/nonce2key $(patsubst nonce2key/%,%,$@) DESTDIR=$(MYDESTDIR)
mf_nonce_brute/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/mf_nonce_brute $(patsubst mf_nonce_brute/%,%,$@) DESTDIR=$(MYDESTDIR)
fpga_compress/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/fpga_compress $(patsubst fpga_compress/%,%,$@) DESTDIR=$(MYDESTDIR)
bootrom/%: FORCE cleanifplatformchanged
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C bootrom $(patsubst bootrom/%,%,$@) DESTDIR=$(MYDESTDIR)
armsrc/%: FORCE cleanifplatformchanged fpga_compress/%
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C armsrc $(patsubst armsrc/%,%,$@) DESTDIR=$(MYDESTDIR)
client/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C client $(patsubst client/%,%,$@) DESTDIR=$(MYDESTDIR)
recovery/all: bootrom/all armsrc/all
recovery/install: bootrom/all armsrc/all
recovery/%: FORCE cleanifplatformchanged
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C recovery $(patsubst recovery/%,%,$@) DESTDIR=$(MYDESTDIR)
hitag2crack/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C tools/hitag2crack $(patsubst hitag2crack/%,%,$@) DESTDIR=$(MYDESTDIR)
FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.PHONY: all clean install uninstall help _test bootrom fullimage recovery client mfkey nonce2key mf_nonce_brute hitag2crack style miscchecks release FORCE udev accessrights cleanifplatformchanged

help:
	@echo "Multi-OS Makefile"
	@echo
	@echo "Possible targets:"
	@echo "+ all             - Make all targets: bootrom, fullimage and OS-specific host tools"
	@echo "+ clean           - Clean in all targets"
	@echo "+ .../clean       - Clean in specified target and its deps, e.g. bootrom/clean"
	@echo "+ (un)install     - Install/uninstall Proxmark files in the system, default to /usr/local/share,"
	@echo "                    else provide a PREFIX. See Maintainers.md for more options"
	@echo
	@echo "+ bootrom         - Make bootrom"
	@echo "+ fullimage       - Make armsrc fullimage (includes fpga)"
	@echo "+ recovery        - Make bootrom and fullimage files for JTAG flashing"
	@echo
	@echo "+ client          - Make only the OS-specific host client"
	@echo "+ mfkey           - Make tools/mfkey"
	@echo "+ nonce2key       - Make tools/nonce2key"
	@echo "+ mf_nonce_brute  - Make tools/mf_nonce_brute"
	@echo "+ hitag2crack     - Make tools/hitag2crack"
	@echo "+ fpga_compress   - Make tools/fpga_compress"
	@echo
	@echo "+ style           - Apply some automated source code formatting rules"
	@echo "+ cliparser       - Generate cliparser TODO"
	@echo "+ check           - Run offline tests. Set CHECKARGS to pass arguments to the test script"
	@echo "+ .../check       - Run offline tests against specific target. See above."
	@echo "+ miscchecks      - Detect various encoding issues in source code"
	@echo
	@echo "+ udev            - Sets udev rules on *nix"
	@echo "+ accessrights    - Ensure user belongs to correct group on *nix"
	@echo
	@echo "Possible platforms: try \"make PLATFORM=\" for more info, default is PM3RDV4"
	@echo "To activate verbose mode, use make V=1"

client: client/all

bootrom: bootrom/all

# aliases fullimage = armsrc

fullimage: armsrc/all

fullimage/all: armsrc/all

fullimage/clean: armsrc/clean

fullimage/install: armsrc/install

fullimage/uninstall: armsrc/uninstall

recovery: recovery/all

mfkey: mfkey/all

nonce2key: nonce2key/all

mf_nonce_brute: mf_nonce_brute/all

fpga_compress: fpga_compress/all

hitag2crack: hitag2crack/all

newtarbin:
	$(RM) proxmark3-$(platform)-bin.tar proxmark3-$(platform)-bin.tar.gz
	@touch proxmark3-$(platform)-bin.tar

tarbin: newtarbin client/tarbin armsrc/tarbin bootrom/tarbin
	$(info GEN proxmark3-$(platform)-bin.tar)
	$(Q)$(GZIP) proxmark3-$(platform)-bin.tar

# detect if there were changes in the platform definitions, requiring a clean
cleanifplatformchanged:
ifeq ($(PLATFORM_CHANGED),true)
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
	sudo usermod -aG bluetooth $(USER) #Use specific command and group
else
	sudo adduser $(USER) dialout
	sudo adduser $(USER) bluetooth
endif

# easy printing of MAKE VARIABLES
print-%: ; @echo $* = $($*)

cliparser:
	# Get list of all commands
	cat doc/commands.md | grep -e ^\|\` | cut -f 2 -d "\`" | grep -v 'help\|list\|mem spiffs\|quit\|exit' | awk '{$$1=$$1};1' > cliparser_all_commands.tmp
	# Get list of cliparserized commands
	grep -r CLIParserInit ./client/src/ | cut -f 2 -d "\"" | awk '{$$1=$$1};1' > cliparser_done.tmp
	# Determine commands that still need cliparser conversion
	grep -xvf cliparser_done.tmp cliparser_all_commands.tmp > ./doc/cliparser_todo.txt

style:
	# Make sure astyle is installed
	@which astyle >/dev/null || ( echo "Please install 'astyle' package first" ; exit 1 )
	# Remove spaces & tabs at EOL, add LF at EOF if needed on *.c, *.h, *.cpp. *.lua, *.py, *.pl, Makefile, *.v
	find . \( -not -path "./cov-int/*" -and -not -path "./fpga/xst/*" -and \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" -or -name "*.v" \) \) \
	    -exec perl -pi -e 's/[ \t]+$$//' {} \; \
	    -exec sh -c "tail -c1 {} | xxd -p | tail -1 | grep -q -v 0a$$" \; \
	    -exec sh -c "echo >> {}" \;
	# Apply astyle on *.c, *.h, *.cpp
	find . \( -not -path "./cov-int/*" -and \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) \) \) -exec astyle --formatted --mode=c --suffix=none \
	    --indent=spaces=4 --indent-switches \
	    --keep-one-line-blocks --max-instatement-indent=60 \
	    --style=google --pad-oper --unpad-paren --pad-header \
	    --align-pointer=name {} \;
	# Update commands.md
	[ -x client/proxmark3 ] && client/proxmark3 -m > doc/commands.md

# Detecting weird codepages and tabs.
ifeq ($(platform),Darwin)
miscchecks: TABSCMD=egrep -l  '\t' {}
else
miscchecks: TABSCMD=grep -lP '\t' {}
endif
ifneq (,$(EDIT))
miscchecks: TABSCMD+= && vi {} -c ':set tabstop=4' -c ':set et|retab' -c ':wq'
endif
miscchecks:
# Make sure recode is installed
	@which recode >/dev/null || ( echo "Please install 'recode' package first" ; exit 1 )
	@echo "Files with suspicious chars:"
	@find . \( -not -path "./cov-int/*" -and -not -path "./client/deps/*" -and \( -name "*.[ch]" -or -name "*.cpp" -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "Makefile" -or -name "*.v" \) \) \
	      -exec sh -c "cat {} |recode utf8.. >/dev/null || echo {}" \;
ifneq (,$(EDIT))
	@echo "Files with tabs: (EDIT enabled, files will be rewritten!)"
else
	@echo "Files with tabs: (rerun with EDIT=1 if you want to convert them with vim)"
endif
# to remove tabs within lines, one can try with: vi $file -c ':set tabstop=4' -c ':set et|retab' -c ':wq'
	@find . \( -not -path "./cov-int/*" -and -not -path "./client/deps/*" -and \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "*.md" -or -name "*.txt" -or -name "*.awk" -or -name "*.v" \) \) \
	      -exec sh -c "$(TABSCMD)" \;
#	@echo "Files with printf \\\\t:"
#	@find . \( -name "*.[ch]" -or \( -name "*.cpp" -and -not -name "*.moc.cpp" \) -or -name "*.lua" -or -name "*.py" -or -name "*.pl" -or -name "*.md" -or -name "*.txt" -or -name "*.awk" -or -name "*.v" \) \
#	      -exec grep -lP '\\t' {} \;

release: VERSION="v4.$(shell git log --oneline master | wc -l)"
release:
	$(if $(findstring master,$(shell git rev-parse --abbrev-ref HEAD)),,$(error "!!! you are not on master branch, aborting"))
	$(if $(findstring dirty,$(shell git describe --dirty --always)),$(error "!!! you have pending changes, aborting"))
	$(if $(RELEASE_NAME),,$(error "!!! missing RELEASE_NAME, aborting"))
	# Preparing a commit for release tagging, to be reverted after tagging.
	@echo "# - Release Tag:  $(VERSION)"
	@echo "# - Release Name: $(RELEASE_NAME)"
	# - Removing -Werror...
	@find . \( -path "./Makefile.defs" -or -path "./client/Makefile" -or -path "./common_arm/Makefile.common" -or -path "./tools/hitag2crack/*/Makefile" \) -exec sed -i 's/ -Werror//' {} \;
	@find . \( -path "./client/deps/*.cmake" -or -path "./client/CMakeLists.txt" \) -exec sed -i 's/ -Werror//' {} \;
	# - Changing banner...
	@sed -i "s/^#define BANNERMSG3 .*/#define BANNERMSG3 \"Release $(VERSION) - $(RELEASE_NAME)\"/" client/src/proxmark3.c
	@echo -n "#   ";grep "^#define BANNERMSG3" client/src/proxmark3.c
	# - Committing temporarily...
	@git commit -a -m "Release $(VERSION) - $(RELEASE_NAME)"
	# - Tagging temporarily...
	@git tag -a -m "Release $(VERSION) - $(RELEASE_NAME)" $(VERSION)
	# - Changing default version information based on new tag
	@$(SH) tools/mkversion.sh > common/default_version.c.tmp && $(MV) common/default_version.c.tmp common/default_version.c
	# - Removing mkversion calls
	@sed -i 's#^.*\.\./tools/mkversion.sh.*|| #\t$$(Q)#' client/Makefile bootrom/Makefile armsrc/Makefile
	@sed -i '/COMMAND/s/sh .*|| //' client/CMakeLists.txt
	# - Deleting tag...
	@git tag -d $(VERSION)
	# - Amending commit...
	@git commit -a --amend -m "Release $(VERSION) - $(RELEASE_NAME)"
	# - Tagging again...
	@git tag -a -m "Release $(VERSION) - $(RELEASE_NAME)" $(VERSION)
	# - Reverting tagged commit...
	@git revert --no-edit HEAD
	@echo "==================================================================="
	@echo "Done! You can now execute 'git push && git push origin $(VERSION)'"

# Dummy target to test for GNU make availability
_test:
