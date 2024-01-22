#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# An ELF file builder for testing MCU flash writing issues.
#-----------------------------------------------------------------------------

include ../../common_arm/Makefile.common

# 00002000 is the start of osimage, immediately after the bootloader,
# 00040000 is the start of the second flash memory half ('plane')
# 00080000 is the end of flash memory

VARIATIONS = \
	00002000_00080000_FF \
	00040000_00080000_FF \
	00040000_00080000_AA55 \
	00040000_00080000_ADDR \
	00040000_00080000_ADDRI

SCRIPTS = $(addsuffix .ld, ${VARIATIONS})
ELFS = $(addsuffix .elf, ${VARIATIONS})
ELFGZS = $(addsuffix .gz, ${ELFS})

%.elf: %.ld
	$(info [=] LD $@)
	$(CROSS_LD) $(CROSS_LDFLAGS) -Wl,-T,$< -o $@ /dev/null

%.ld: generator.pl
	$(info [=] PERL generate $@)
	$(PERL) $< $(basename $@) >$@

%.gz: %
	gzip --keep $<

clean:
	$(RM) $(ELFGZS) $(ELFS) $(SCRIPTS)

all: $(ELFS)
release: $(ELFGZS)

#.PRECIOUS: $(SCRIPTS)

.PHONY: all clean
