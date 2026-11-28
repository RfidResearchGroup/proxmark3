# Introduction

In order to simplify development, some peripheral devices are operated using the firmware library provided by AT32
official.

The directory where the basic firmware library for AT32 is stored is `at32_sys`.

There are some additional USB (middleware) implementations stored in the ` at32_usb ` directory.

The source is opensource on
GitHub, [AT32F435_437_Firmware_Library](https://github.com/ArteryTek/AT32F435_437_Firmware_Library)

- `AT32F435_437_Firmware_Library/libraries/cmsis` > `armlib/at32_sys/cmsis`
- `AT32F435_437_Firmware_Library/libraries/drivers` > `armlib/at32_sys/drivers`

> `core` dir is from gpio example, it is related by project, in general, it is not necessary to modify it.

---

# What's change

## Change of `at32f435_437_conf.h`

We would like to use the official library directly for the current ARM project without modifying it.
However, in reality, some of the official libraries are not well-designed and have a serious impact on the buildingof
the project.
Such as, the UART related libraries may conflict with some function/variable names in the current PM3.

- Annotate all module definitions and includes definitions.
- including `at32f435_437.h` does not include all definitions of drivers/base libraries. include your drivers/base
  libraries if needed.
- If the driver library reports an error, it may be because the driver library does not include the required header
  file (which was originally included by the `at32f435_437_comf.h` header file).

## Change of files

- Some datasheet pdf deleted
- `startup_at32f435_437.s` 
  - delete `.bss` clear
  - delete `.data` copy
  - delete call `__libc_init_array()` function
  - stack top change to symbol `_stack_end`
  > This startup file is specifically designed for the osimage of PM3 and is no longer compatible with the official example of AT32.
- delete dir: `startup/gcc/linker`
- delete dir: `startup/iar`
- delete dir: `startup/mdk`

## Change of the USB host drivers

The host part of `at32_usb/usb_drivers` (`usbh_*`) is built only for a PM5 with `PLATFORM_EXTRAS=USB_HOST_CCID`, through
`armsrc/pm5_cep_usbh_*.c`. The device part is not changed.

- `usb_conf.h`
  - the host configuration (`USE_OTG_HOST_MODE`, OTGFS1, no `USB_VBUS_IGNORE`) is selected by the sources that build
    the host part, the default stays the device configuration on OTGFS2
  - `USBH_DEBUG()` is defined empty for the host part when no source defines it
- `usbh_core.c`, `usbh_core.h`
  - the port reset runs in steps on the host timer (`port_state`, `port_timer`) instead of `usb_delay_ms()`
  - a port reset left asserted by a disconnect is released
  - the enumeration stops on an EP0 size that is not 8, 16, 32 or 64
  - the enumeration stops when the configuration descriptor does not parse
- `usbh_ctrl.c`
  - `usbh_parse_configure_desc()` checks every length against the buffer and the interface and endpoint counts against
    the tables, a malformed tail ends the parse
  - `usbh_parse_string_desc()` ignores a `bLength` below 2
- `usbh_int.c`
  - a channel halted by a NAK or by a transfer error is restarted only while a device is connected
  - a transfer that reached the error limit (`URB_ERROR`) is not restarted
