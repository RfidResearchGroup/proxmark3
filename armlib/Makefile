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

ifeq ($(PLATFORM),PM5)

# Flags + Inc
include ../armlib/Exports.mk

# Toolchain + dirs
include ../common_arm/Makefile.common

# Allow standalone invocation when parent make doesn't export toolchain vars.
CROSS ?= arm-none-eabi-
CROSS_CC ?= $(CROSS)gcc
CROSS_CFLAGS ?=
CROSS_AR ?= $(CROSS)ar
OBJDIR ?= obj

ARMLIBSRC = \
	../armlib/at32_sys/cmsis/cm4/device_support/system_at32f435_437.c \
	../armlib/at32_sys/drivers/src/at32f435_437_crm.c \
	../armlib/at32_sys/drivers/src/at32f435_437_misc.c \
	../armlib/at32_sys/drivers/src/at32f435_437_gpio.c \
	../armlib/at32_sys/drivers/src/at32f435_437_usb.c \
	../armlib/at32_sys/drivers/src/at32f435_437_qspi.c \
	../armlib/at32_sys/drivers/src/at32f435_437_tmr.c \
	../armlib/at32_sys/drivers/src/at32f435_437_ertc.c \
	../armlib/at32_sys/drivers/src/at32f435_437_pwc.c \
	../armlib/at32_sys/drivers/src/at32f435_437_spi.c \
	../armlib/at32_sys/drivers/src/at32f435_437_i2c.c \
	../armlib/at32_sys/drivers/src/at32f435_437_dma.c \
	../armlib/at32_sys/drivers/src/at32f435_437_adc.c \
	../armlib/at32_sys/drivers/src/at32f435_437_usart.c \
	../armlib/at32_sys/drivers/src/at32f435_437_exint.c \
	../armlib/at32_sys/drivers/src/at32f435_437_scfg.c \
	../armlib/at32_sys/drivers/src/at32f435_437_flash.c \
	../armlib/at32_sys/drivers/src/at32f435_437_crc.c \
	../armlib/at32_sys/drivers/src/at32f435_437_wdt.c \
	../armlib/at32_sys/drivers/src/at32f435_437_wwdt.c \
	../armlib/at32_sys/drivers/src/at32f435_437_can.c \
	../armlib/at32_sys/drivers/src/at32f435_437_dac.c \
	../armlib/at32_sys/drivers/src/at32f435_437_debug.c \
	../armlib/at32_sys/drivers/src/at32f435_437_dvp.c \
	../armlib/at32_sys/drivers/src/at32f435_437_edma.c \
	../armlib/at32_sys/drivers/src/at32f435_437_sdio.c \
	../armlib/at32_sys/drivers/src/at32f435_437_acc.c \
	../armlib/at32_usb/usb_drivers/src/usb_core.c \
	../armlib/at32_usb/usb_drivers/src/usbd_core.c \
	../armlib/at32_usb/usb_drivers/src/usbd_int.c \
	../armlib/at32_usb/usb_drivers/src/usbd_sdr.c \
	../armlib/at32_usb/usbd_class/cdc/cdc_class.c \
	../armlib/at32_i2c/at32f435_437_i2c_app.c

ARMLIB = $(OBJDIR)/$(ARMLIB_EXPORT_LIBNAME)
ARMLIB_OBJ_FROM_SRC = $(OBJDIR)/armlib_$(subst /,_,$(patsubst ../armlib/%.c,%,$(1))).o
ARMLIB_OBJ = $(foreach src,$(ARMLIBSRC),$(call ARMLIB_OBJ_FROM_SRC,$(src)))
ARMLIB_DEP = $(ARMLIB_OBJ:.o=.d)
.DEFAULT_GOAL := $(ARMLIB)

# TODO Artery's library has many warnings, which we can only ignore for now, unfortunately.
ARMLIB_PRIVATE_CFLAGS = -mcpu=cortex-m4 -Wno-missing-prototypes -Wno-missing-declarations
ARMLIB_CFLAGS = $(ARMLIB_EXPORT_CFLAGS) $(ARMLIB_PRIVATE_CFLAGS)

define ARMLIB_COMPILE_RULE
$(2): $(1) $(INCLUDES) | $(OBJDIR)
	$$(info [-] CC $$(notdir $(1)))
	$$(Q)$$(CROSS_CC) $$(CROSS_CFLAGS) $$(ARMLIB_CFLAGS) -MMD -MP -MF $(2:.o=.d) -mthumb -c -o $(2) $(1)
endef

define ARMLIB_REGISTER_RULES
$(foreach src,$(ARMLIBSRC),$(eval $(call ARMLIB_COMPILE_RULE,$(src),$(call ARMLIB_OBJ_FROM_SRC,$(src)))))
endef

$(OBJDIR):
	$(Q)mkdir -p $@

$(ARMLIB): $(ARMLIB_OBJ) | $(OBJDIR)
	$(info [-] AR $@)
	$(Q)$(CROSS_AR) rcs $@ $^

$(call ARMLIB_REGISTER_RULES)
-include $(ARMLIB_DEP)

endif
