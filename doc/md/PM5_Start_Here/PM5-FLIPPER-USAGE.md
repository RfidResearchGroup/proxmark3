# Proxmark5 CEP — Flipper Zero link

The **CEP (Type-C Extended Port)** is the side USB-C port on the PM5 — the one
**not** used for flashing/DFU. It lets a Flipper Zero, running the
[Proxmark5_FlipperZero_FAP](https://github.com/RfidResearchGroup/Proxmark5_FlipperZero_FAP)
app, talk to the PM5 over a one-shot UART handshake followed by standard PM3
NG command/response frames carried over SPI. Everything below is **PM5-only**
and is compiled in by default when building for PM5.

## Contents

- [Build](#build)
- [Physical hookup](#physical-hookup)
- [What works today](#what-works-today)
- [What doesn't (yet)](#what-doesnt-yet)
- [Status / debugging](#status--debugging)
- [Notes](#notes)

---

## Build

Build as usual, CEP is available by default. (`SKIP_CEP=1` to remove CEP support)

---

## Physical hookup

- Use the **side** USB-C port.
- Attach a Flipper Zero fitted with the Flipper transfer module/cable, running
  the Proxmark5_FlipperZero_FAP app.
- The Flipper supplies 5V to the PM5 via USB OTG when the app launches.

---

## What works today

- The FAP handshake completing (app leaves "connecting").
- Standard commands — `hw version`, `hw status`, memory/flash operations,
  `CMD_CEP_STATUS` (compact binary snapshot: CEP link state, BWM battery,
  firmware version — feeds the FAP's Hardware Status dashboard).
- `hf`/`lf` reads in general, same as over USB, once the device's one-time
  FPGA bitstream step is done (see `Getting_Started_With_PM5.md`) — CEP
  itself doesn't block RF.

## What doesn't (yet)

- The FAP's "Read Hitag2" menu item specifically. Every attempt over CEP
  replies `PM3_EFAILED` with stale cached UID data, even though the same
  reader succeeds moments later over plain USB against the same tag.
  Firmware-side, root cause open, out of scope for the CEP transport itself.

---

## Status / debugging

- `hw status` reports a **CEP (Flipper) link** line: `attached` /
  `not attached`.
- **Flipper side**: `./fbt cli` → `log debug`, then watch the
  `Proxmark5_COM` tag while the FAP runs.
- **PM5 side**: keep the normal button-side USB-C cable attached to a PC
  running the standard client at the same time as the Flipper is on CEP —
  `Dbprintf()` output in the new CEP code surfaces there as usual, regardless
  of what's happening over CEP.

---

## Notes

- CEP uses its own reply-routing flag (`g_reply_via_cep`).
- SPI bit-order/clock-phase settings are confirmed correct against real
  Flipper traffic (logic analyzer): MSB-first, mode 0, CS active-low.
