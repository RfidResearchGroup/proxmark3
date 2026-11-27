# hw cep logic — PM5 CEP Bus Logger

A PM5-only feature that records every byte moved over the CEP (Type-C Extended Port) link and lets you pull it as a VCD file or a data table.

## Overview

PM5's CEP (Type-C Extended Port) link lets an external board (a Flipper Zero, or a custom dev board) talk to the Proxmark5 over USART1 (a one-shot handshake) and then SPI1 (the actual PM3 NG-frame transport, PM5 always the SPI slave). Anyone building a CEP peripheral board has had no way to see what's actually going over that link when it doesn't work.

`hw cep logic` records every byte that crosses it: SPI1 MOSI, SPI1 MISO, and the USART1 handshake byte, each with a capture timestamp (free-running `DWT->CYCCNT`, converted to a 1.5 MHz unit - not `GetTicks()`, which other subsystems reset mid-capture via `StartTicks()`), into a 4096-entry ring buffer on the device. This is byte/timestamp resolution, not an electrical capture — there's no clock or chip-select trace, because PM5 has no spare GPIO/DMA path to capture sub-bit timing without extra hardware.

See also the [PM5 VERE Hardware Reference Manual, §5.3](md/Development/PM5_VERE_Hardware_RM.md#53-cep-interface-typec_external_port) for the CEP interface's hardware description.

## Commands

All of these need a PM5 built with `PLATFORM_EXTRAS=CEPLOGIC` (RDV4 never builds this code at all). This is opt-in and separate from plain CEP support (`WITH_CEP`, on by default on PM5): it adds a 4096-entry ring buffer plus a fetch staging buffer (~27KB total RAM) that records every SPI1/USART1 byte on the bus with a timestamp, so it costs RAM you don't pay for otherwise. See `Makefile.platform.sample`.

`hw cep logic` is gated on `IfCep` (plain CEP support, on by default on PM5), not a dedicated CEPLOGIC capability bit, so the subcommands always show up in the client's command tree on a PM5-capable device — this is intentional, to avoid bumping `CAPABILITIES_VERSION` for every PM5 build whether or not it opted into CEPLOGIC. A firmware without `PLATFORM_EXTRAS=CEPLOGIC` still shows the commands; it replies `PM3_ENOTIMPL` when you actually run one.

| Command | What it does |
| --- | --- |
| `hw cep logic start` | Start recording. Doesn't clear a previous capture. `-i`/`--skipidle` skips 0xFF/0x00 MOSI idle-poll filler, so the 4096-entry ring lasts for real traffic instead of filling with poll noise in seconds. |
| `hw cep logic stop` | Stop recording. |
| `hw cep logic clear` | Stop recording and discard the captured trace. |
| `hw cep logic status` | Show whether it's running, how many entries recorded, and whether the ring buffer has wrapped (oldest entries overwritten). |
| `hw cep logic fetch` | Pull the trace off the device and render it — see below. |

Typical session:

```
hw cep logic clear
hw cep logic start
... trigger the CEP traffic you want to see ...
hw cep logic stop
hw cep logic fetch -a -f trace
```

## fetch options

`fetch` always pulls the whole trace first and prints the entry count; these flags pick what else happens, and both can be given together:

| Flag | Output |
| --- | --- |
| (none) | Just the entry count. |
| `-f <fn>` | A VCD file (all three channels), for PulseView or GTKWave. |
| `-a` | Data table to the terminal (Type/Start/mosi/miso/data columns). |

## Timestamps

A timestamp is taken when a byte is *consumed* off the SPI1/USART1 ring, not when it physically appears on the wire — `cep_spi_read_byte()` (MOSI) and the idle-filler skip loop in `cep_spi_rx_pending()` both call `cep_logic_record()` at that point, same as `cep_spi_tx_byte()` (MISO) and `USART1_IRQHandler()` (UART). Under load this can lag the real wire time by however long the byte sat in the ring before the main loop got to it.

Reply bytes (what PM5 itself sends back on MISO) are always logged, via `cep_spi_tx_byte()`. Bytes discarded by `cep_spi_resync()` (AT32 errata ES0003 recovery, or an implausible frame length) are not logged — they never reach `cep_spi_read_byte()`.

## Known limitations

- **Byte/timestamp resolution, not electrical capture.** No clock or chip-select trace — only what `cep_logic_record()` actually timestamps.
- **VCD output covers all three channels** (mosi/miso/uart).
- **Frame decoding is best-effort.** It scans for the PM3 NG preamble magic (`COMMANDNG_PREAMBLE_MAGIC` / `RESPONSENG_PREAMBLE_MAGIC` in `pm3_cmd.h`) and reads length/cmd/status directly off the bytes; a frame cut off by the ring buffer wrapping is still shown, marked `(cut)`.

## Testing

Hardware-verified by Tom on real CEP traffic (Flipper Zero attached over CEP), cross-checked against a Saleae Logic 2 capture of the same session for byte content and relative ordering.
