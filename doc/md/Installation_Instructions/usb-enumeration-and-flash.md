<a id="Top"></a>

# Getting to stable COM ports

aka, Why I stopped using a PM3Easy without flash.

## Table of Contents
- [Getting to stable COM ports](#getting-to-stable-com-ports)
  - [Table of Contents](#table-of-contents)
  - [TLDR](#tldr)
  - [Three types of USB enumeration](#three-types-of-usb-enumeration)
    - [`Anonymous` devices](#anonymous-devices)
    - [`Sticky` devices](#sticky-devices)
    - [`Collision` devices](#collision-devices)
  - [What type of device is the PM3?](#what-type-of-device-is-the-pm3)
    - [Finding a hardware-based unique serial number](#finding-a-hardware-based-unique-serial-number)
    - [Two firmwares on one device?](#two-firmwares-on-one-device)
  - [Safer method to test and enable `FLASH` on PM3Easy](#safer-method-to-test-and-enable-flash-on-pm3easy)
  - [Conclusion](#conclusion)

## TLDR
^[Top](#top)

If your device has the extra external flash, and you
enable `PLATFORM_EXTRAS=FLASH` for the main firmware,
you should flash the the bootloader ***at least once***
with a flash-enabled bootloader build.

(e.g., `./pm3-flash-all` or `./pm3-flash-bootrom`)

## Three types of USB enumeration
^[Top](#top)

Shorthand notation:
1. No unique serial number reported == `Anonymous`
2. Unique serial number reported == `Sticky`
3. Fake unique serial number reported == `Collision`

When a USB device enumerates on the USB bus (and is thus
discoverable and usable by the operating system), one of
the optional bits of information that can be provided is
a serial number.  The specification requires that, if such
a serial number is provided, it must be unique for that
type (VID/PID) of device.

### `Anonymous` devices
^[Top](#top)

On Windows, when a device does ***not*** report a unique
serial number, to uniquely identify the device, Windows
adds information from the topology of the USB bus to
make the device's ID unique.

This means that a device without a unique serial number
will have a first ID when plugged into one USB port, and
be seen as a totally different device when plugged into
a second USB port.  If there are one or more USB hubs in
between, the entire "path" from the PC to the device is
included ... so plugging such device into each port on
an eight-port hub would result in eight different devices
being seen by Windows. (only one being "active" at a
time, of course.)

### `Sticky` devices
^[Top](#top)

In contrast, when a device reports a unique serial number,
Windows (and presumably other operating systems) will
use that serial number to uniquely identify the device.
As a result, device-specific settings will "follow" the
device even when it's plugged into a different USB port.

### `Collision` devices
^[Top](#top)

There is a third situation, where the device pretends
to have a unique serial number, but actually every
device of that type reports the same serial number.
This is a violation of the USB specification, but
it does happen.

In this case, when only one of that type of device
is ever connected to a given computer, it acts like
a "Sticky" device.

However, as soon as a second of these devices is plugged
in, the operating system discovers it was lied to...
the unique serial number is a lie.  This means the OS
cannot rely on the serial number to uniquely name the
device.  On older OSes, this could cause the kernel to
crash.  Even on newer OSes, the name collision can cause
delays while the collision is detected and resolved.
On Windows, this could add delays from when the second
device is plugged in, until the second device is usable.

## What type of device is the PM3?
^[Top](#top)

This is not a simple question, and has changed over time.

### Finding a hardware-based unique serial number
^[Top](#top)

The Proxmark3 CPU and FPGA devices do not have a unique
hardware serial number available.  As a result, until
February 2023, all the Proxmark3 devices should have
reported no serial number.  However, an easter egg was
used as the serial number.  As a result, rather than
being of type `Anonymous`, all Proxmark3 devices were
actually of the `Collision` type.  This was no problem
for single-device users, but anyone connecting more than
one Proxmark3 to a computer would have seen, in the
best case, delays in enumeration (>10 seconds at times).

Since February 2023, code was added to retrieve a unique
serial number from the external flash chip, and use that
as the proxmark's USB serial number also.
(See PR [#1914](https://github.com/RfidResearchGroup/proxmark3/pull/1914).)

For the RDV4, the unique serial number feature was
enabled by default, because all RDV4 shipped with
external flash chips.

However, enabling this on PM3Easy devices requires editing
`Makefile.platform` to include the line
`PLATFORM_EXTRAS=FLASH`. This is ***NOT*** enabled by
default for PM3Easy, mostly because the implementor did not
have hardware to verify it would fail gracefully when
the flash was not present.


### Two firmwares on one device?
^[Top](#top)

Whether a Proxmark3 device enumerates with a true unique
serial number or a non-unique serial number (`Collision`)
depends on whether the firmware was built with the
`FLASH` feature enabled.

Actually, there's one more layer of complexity:
the bootloader and the main firmware are separate
executable entities.  Therefore, the bootloader might
have been built without `FLASH` feature enabled, and
therefore enumerate as the `Collision` type device
with the fake serial number, while the main firmware
may have been built with the `FLASH` feature enabled,
and thus report the true unique serial number.

## Safer method to test and enable `FLASH` on PM3Easy
^[Top](#top)

Many users won't know if their PM3Easy has the external
flash chip.  For example, if the PM3Easy firmware was
not built with this feature defined, the bootloader and
firmware shipped on the device might be of `Collision`
type.  However, enabling the `FLASH` feature when the
device doesn't have the extra flash chip may prevent
the device from booting.

The good news is that the bootloader can be left
unmodified, while the main firmware is flashed with
a version with the `FLASH` feature enabled.  This allows
to verify that the flash chip exists and provides the
unique serial number (or hangs) without removing the
ability to get into the bootloader.  Then, only when
the serial number's existence is confirmed, the bootloader
can be updated to include the proper serial number also.

Here's some steps that do just that.

1. Clone / build / update the device with the latest
   Proxmark3 firmware.  This ensures a "known good"
   configuration and update process exists.  Get this
   working first.
2. Edit `Makefile.platform` to include the line
    `PLATFORM_EXTRAS=FLASH`.  This will enable the
   features in the proxmark firmware that use the flash
   memory, including using the flash's unique serial number
   during USB enumeration.
3. Re-build everything:
   `make clean && make -j`
4. Flash ONLY the main firmware image:
   `./pm3-flash-fullimage`
   This ensures the bootloader remains in "known good"
   state, in case there is an incompatibility.
5. Let the device come up normally, and connect to
   the device with the proxmark client:  `./pm3`
6. Verify the device sees the firmware, and has detected
   a reasonable serial number: `hw status`
   The output should include something similar to:
```text
[#] Flash memory
[#]   Baudrate................ 24 MHz
[#]   Init.................... OK
[#]   Unique ID (be).......... 0x1032547698BADCFE
```
7. If the device failed to boot, the above command did
   not report anything about flash memory, or the listed
   Unique ID is all `0` or `F`, then your device might
   not have the extra flash memory.  In this case, revert
   the changes to `Makefile.platform`, rebuild, and re-flash
   the main firmware image to restore to the "known good"
   state.
8. Otherwise, if you do see the flash information and a
   reasonable serial number, then you could choose to 
   update the bootloader (which was already built with
   the `FLASH` feature): `./pm3-flash-bootrom`.


## Conclusion

Updating the bootloader incorrectly can make it more
difficult to recover the device (e.g., requires JTAG).
However, by updating only the main firmware first,
you can reduce this risk, while still enabling the
flash-based features in your PM3Easy by verifying the
functionality works for at least the main firmware first.


