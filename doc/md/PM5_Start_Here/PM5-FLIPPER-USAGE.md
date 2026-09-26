# Proxmark5 CEP — Flipper Zero link

The **CEP (Type-C Extended Port)** is the side USB-C port on the PM5 — the one
**not** used for flashing/DFU. It lets a Flipper Zero, running the
[Proxmark5_FlipperZero_FAP](https://github.com/RfidResearchGroup/Proxmark5_FlipperZero_FAP)
app, talk to the PM5 over a one-shot UART handshake followed by standard PM3
NG command/response frames carried over SPI. Everything below is **PM5-only**
and is compiled in by default when building for PM5.

See [GH issue #3667](https://github.com/RfidResearchGroup/proxmark3/issues/3667)
for the full protocol writeup and open hardware-verification items.

## Contents

- [Build](#build)
- [Physical hookup](#physical-hookup)
- [What works today](#what-works-today)
- [What doesn't (yet)](#what-doesnt-yet)
- [Status / debugging](#status--debugging)
- [Notes](#notes)

---

## Build

```
make clean
make PLATFORM=PM5
make client        # or your usual client build
```

CEP is independent of `BWM` — disable it with `SKIP_CEP` if you don't want it,
with or without BWM:

```
make PLATFORM=PM5 PLATFORM_EXTRAS="BWM SKIP_CEP"
```

Or set it persistently in `Makefile.platform`:

```
PLATFORM=PM5
PLATFORM_EXTRAS=SKIP_CEP
```

> [!NOTE]
> With `PLATFORM_EXTRAS=SKIP_CEP` the firmware ignores the Flipper entirely —
> the CEP port stays inert, same as before this feature existed.

---

## Physical hookup

- Use the **side** USB-C port (the button-side port stays reserved for
  flashing/DFU).
- Attach a Flipper Zero fitted with the Flipper transfer module/cable, running
  the Proxmark5_FlipperZero_FAP app.
- The Flipper supplies 5V to the PM5 via USB OTG when the app launches.

---

## What works today

- The FAP handshake completing (app leaves "connecting").
- Standard PM3 NG commands that don't touch the antenna frontend — `hw
  version`, `hw status`, memory/flash operations, etc.

## What doesn't (yet)

- Any RF operation over this link — `hf`/`lf` reads, the FAP's "Read Hitag2"
  menu item. These need the real PM5 FPGA/RF configuration, which isn't
  shipped in this repo. Tracked separately, out of scope for the CEP
  transport itself — see GH issue #3667.

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

- CEP uses its own reply-routing flag (`g_reply_via_cep`), independent of
  BWM's (`g_reply_via_fpc`) — this is what lets both transports run
  concurrently on hardware that has both fitted.
- The SPI bit-order/clock-phase settings are a best-effort port from prior
  bring-up code, pending confirmation against real Flipper traffic (logic
  analyzer). If the handshake never completes, this is the first thing to
  check — see GH issue #3667.
