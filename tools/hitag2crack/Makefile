# Must be called before any Makefile include
ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

include ../../Makefile.defs

all clean install uninstall check: %: crack2/% crack3/% crack4/% crack5/%
ifneq ($(SKIPGPU),1)
all clean install uninstall check: %: crack5gpu/%
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

crack5gpu/%: FORCE
	$(info [*] MAKE $@)
	$(Q)$(MAKE) --no-print-directory -C crack5gpu $(patsubst crack5gpu/%,%,$@) DESTDIR=$(MYDESTDIR)

FORCE: # Dummy target to force remake in the subdirectories, even if files exist (this Makefile doesn't know about the prerequisites)

.phony: crack2 crack3 crack4 crack5 crack5gpu FORCE
