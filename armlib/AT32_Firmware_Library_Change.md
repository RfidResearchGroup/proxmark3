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
