include ../../Makefile.defs

all clean install uninstall check: %: crack2/% crack3/% crack4/% crack5/%
ifneq ($(SKIPOPENCL),1)
all clean install uninstall check: %: crack5opencl/%
endif

crack2/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack2 $(patsubst crack2/%,%,$@) DESTDIR=$(MYDESTDIR)

crack3/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack3 $(patsubst crack3/%,%,$@) DESTDIR=$(MYDESTDIR)

crack4/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack4 $(patsubst crack4/%,%,$@) DESTDIR=$(MYDESTDIR)

crack5/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack5 $(patsubst crack5/%,%,$@) DESTDIR=$(MYDESTDIR)

crack5opencl/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack5opencl $(patsubst crack5opencl/%,%,$@) DESTDIR=$(MYDESTDIR)

FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.phony: crack2 crack3 crack4 crack5 crack5opencl FORCE
