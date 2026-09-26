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
- Standard commands that don't touch the antenna frontend — `hw
  version`, `hw status`, memory/flash operations, etc.

## What doesn't (yet)

- Any RF operation over this link — `hf`/`lf` reads, the FAP's "Read Hitag2"
  menu item. These need the real PM5 FPGA/RF configuration, which isn't
  shipped in this repo. Tracked separately, out of scope for the CEP
  transport itself.

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
- The SPI bit-order/clock-phase settings are a best-effort port from prior
  bring-up code, pending confirmation against real Flipper traffic (logic
  analyzer). If the handshake never completes, this is the first thing to
  check.
