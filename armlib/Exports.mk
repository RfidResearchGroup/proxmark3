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

ARMLIB_EXPORT_DEFS = -DCHIP_AT32F435_37 -DAT32F435RGT7 -DUSE_STDPERIPH_DRIVER -DAT_START_F435_V1 -DUSBD_SUPPORT_WINUSB=1
ARMLIB_EXPORT_DEFS += -DCRM_MODULE_ENABLED -DMISC_MODULE_ENABLED -DGPIO_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DUSB_MODULE_ENABLED -DQSPI_MODULE_ENABLED -DTMR_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DERTC_MODULE_ENABLED -DPWC_MODULE_ENABLED -DSPI_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DI2C_MODULE_ENABLED -DDMA_MODULE_ENABLED -DADC_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DUSART_MODULE_ENABLED -DEXINT_MODULE_ENABLED -DSCFG_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DFLASH_MODULE_ENABLED -DCRC_MODULE_ENABLED -DWDT_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DWWDT_MODULE_ENABLED -DCAN_MODULE_ENABLED -DDAC_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DDEBUG_MODULE_ENABLED -DDVP_MODULE_ENABLED -DEDMA_MODULE_ENABLED
ARMLIB_EXPORT_DEFS += -DSDIO_MODULE_ENABLED -DACC_MODULE_ENABLED

ARMLIB_EXPORT_INCLUDES = -I.
ARMLIB_EXPORT_INCLUDES += -isystem ../armlib/at32_sys -isystem ../armlib/at32_sys/cmsis/cm4/core_support
ARMLIB_EXPORT_INCLUDES += -isystem ../armlib/at32_sys/cmsis/cm4/device_support -isystem ../armlib/at32_sys/drivers/inc
ARMLIB_EXPORT_INCLUDES += -isystem ../armlib/at32_usb -isystem ../armlib/at32_usb/usb_drivers/inc -isystem ../armlib/at32_usb/usbd_class/cdc
ARMLIB_EXPORT_INCLUDES += -isystem ../armlib/at32_i2c

ARMLIB_EXPORT_CFLAGS = $(ARMLIB_EXPORT_DEFS) $(ARMLIB_EXPORT_INCLUDES)

ARMLIB_EXPORT_LIBNAME = libarmlib.a

endif
