# GDB_GATEWAY

GDB Remote Serial Protocol server on the USB CDC link (PM5).
No probe or extra wiring. Reads flash and SRAM, writes SRAM and flash. No breakpoints, no step.

## Build

```
PLATFORM=PM5
STANDALONE=GDB_GATEWAY
```

## Use

```
pm3 --> hw standalone
```

Quit the client (the port stays up), then:

```
arm-none-eabi-gdb -ex 'target remote /dev/ttyACM0'
(gdb) x/16xw 0x08000000
(gdb) dump memory flash.bin 0x08000000 0x08100000
(gdb) monitor info
(gdb) load patch.elf                # flash above the running image
(gdb) monitor unlock-app            # allow writes to the app area
(gdb) monitor lock
(gdb) monitor exit
```

Leave with `monitor exit` or a button press.

## Readable ranges

| Range | Size |
|-------|------|
| `0x08000000` | 1 MB flash |
| `0x20000000` | 512 KB SRAM |

Other addresses return `E14`. Peripheral space is not exposed.

## Writes

| Target | Allowed |
|--------|---------|
| SRAM (`M`) | always |
| Flash above the running image (`load`, `vFlashErase`/`vFlashWrite`) | always |
| Flash from `0x08004000` (app area) | after `monitor unlock-app` |
| Bootrom, `0x08000000`-`0x08003fff` | never |

Refused writes return `E02`. `monitor lock` restores the default; the gateway starts locked.
Erasing the running image crashes the PM5, recover it through the bootrom.

## Notes

- Flash is erased in 2 KB sectors.
- Register reads return zeros, the core is not halted.
- `c`/`s` return an immediate stop reply; nothing is executed.
- Debug output is off while running, it would corrupt the RSP stream.
- Set `remotetimeout 60` in gdb for large dumps.
