include common/Makefile.common

ifeq ($(DETECTED_OS),Linux)
HOST_BINARY=linux
else
HOST_BINARY=winsrc
endif

all clean: %:
	$(MAKE) -C bootrom $@
	$(MAKE) -C armsrc $@
	$(MAKE) -C $(HOST_BINARY) $@

.PHONY: all clean help _test
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all   - Make bootrom, armsrc and the OS-specific host directory 
	@echo +	clean - Clean in bootrom, armsrc and the OS-specific host directory

# Dummy target to test for GNU make availability
_test:
