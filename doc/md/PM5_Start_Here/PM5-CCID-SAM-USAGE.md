# Proxmark5 CEP — HID SAM in a USB smart card reader

The **CEP (Type-C Extended Port)** is the side USB-C port on the PM5 — the one
**not** used for flashing/DFU. Built with the `USB_HOST_CCID` platform extra, it
is also a USB host for a CCID smart card reader holding a HID SAM, and the `sam`
commands of the client work on the PM5 as they do with the SIM module of an
RDV4. Everything below is **PM5-only**.

## Contents

- [Build](#build)
- [Physical hookup](#physical-hookup)
- [Reader requirements](#reader-requirements)
- [What works today](#what-works-today)
- [What doesn't (yet)](#what-doesnt-yet)
- [Status / debugging](#status--debugging)
- [Notes](#notes)

---

## Build

Build the firmware with the `USB_HOST_CCID` extra, alone or next to `BWM`:

```
make clean
make PLATFORM=PM5 PLATFORM_EXTRAS="USB_HOST_CCID BWM"
make client        # or your usual client build
```

Or set it persistently in `Makefile.platform`:

```
PLATFORM=PM5
PLATFORM_EXTRAS=USB_HOST_CCID BWM
```

> [!NOTE]
> The reader and the [Flipper Zero link](./PM5-FLIPPER-USAGE.md) are built
> independently: `USB_HOST_CCID` adds the reader, `SKIP_CEP=1` removes the Flipper
> link. With both in the firmware the port serves the one that is plugged in:
> the PM5 powers a reader, a Flipper powers the PM5.

> [!NOTE]
> A firmware has one smart card hardware. With `USB_HOST_CCID` it is the reader:
> the one of the `SMARTCARD` extra is left out.

---

## Physical hookup

- Use the **side** USB-C port.
- Plug in the USB CCID reader with the HID SAM in its slot. The PM5 powers the
  reader.
- A reader with a USB-A plug goes through a USB-C OTG adapter (USB-C plug,
  USB-A socket). An adapter wired for USB 3.x is fine with a USB 2.0 reader,
  whose plug has no SuperSpeed contacts.
- Use a USB 2.0 reader and cable. The port is a standard Type-C only on its
  USB 2.0, power and CC contacts: the SuperSpeed and SBU contacts carry the SPI
  and UART signals of the Flipper link, see the
  [hardware manual](../Development/PM5_VERE_Hardware_RM.md#53-cep-interface-typec_external_port).
- Keep the normal button-side USB-C cable, or the BWM link, for the client.
- The reader can be plugged in and out while the client is connected, and the
  SAM can be put in and taken out while the reader is plugged in. Without the
  reader the `sam` and `smart` commands print
  `SC: no USB reader on the CEP port`.

---

## Reader requirements

The reader is taken when it:

- is a USB CCID class device with bulk endpoints;
- exchanges TPDUs with the card;
- selects the card voltage by itself, or activates the card by itself;
- runs the PPS that a `SetParameters` message asks for.

T=0 and T=1 both work: the reader handles the T=0 procedure bytes, the T=1
block protocol runs in the PM5 (LRC only).

---

## What works today

Tested on a PM5 with a BWM and a HID SAM with firmware 7.53, in each of these
readers:

- `04e6:5810` CLOUD 2700 R Smart Card Reader, release 2.01
- `072f:b501` ACR40T ICC Reader, release 30.08

With both:

- `hw status`: the reader and its release number.
- `hf iclass sam --info`: firmware version, firmware ID, ATR and serial number
  of the SAM.
- `hf iclass sam`, `hf mf sam` and `hf mfdes sam`, also with `-v`: the PACS of
  an iCLASS legacy, a MIFARE Classic SE and a DESFire credential.
- `hf seos sam`: the PACS of a Seos card.
- `smart info` and `smart brute`, and `smart raw`, `smart pps` and
  `emv select -w` in T=0 and in T=1: the SAM answers.
- The `sam` commands run the SAM in T=1 at Fi/Di `96` and power it down when
  they end. The `smart` commands leave the card powered.
- `smart raw --t1`, `smart pps --t1` and `emv ... --t1` without a `--ta1` run
  the card at the Fi of its ATR and the fastest Di the reader declares for it,
  `97` for this SAM in both readers.

---

## What doesn't (yet)

- A reader other than the two above is untested. One without automatic PPS, or
  with neither automatic voltage selection nor automatic activation, is refused.
- A SAM that only speaks T=0 is untested.
- T=0 with the HID SAM: its `A0 DA` commands get no answer through a reader.
  Where the status is due the ACR40T returns `DA 0A`, the INS byte and the
  first byte of the SAM's answer, and the CLOUD 2700 R fails the exchange. The
  `sam` commands run in T=1 and are not affected.
- Raw frames: the reader frames every byte, so `smart raw` without `--t0` or
  `--t1` sends an APDU in the protocol the card runs.
- `smart setclock` changes nothing, the reader picks the card clock. The
  firmware says so, the client still prints `Clock changed`.
- The secure channel transport (`CMD_HF_SAM_SC`) was not exercised over the
  reader.
- The reader is never suspended: it keeps drawing its idle current while
  plugged in.

---

## Status / debugging

- `hw status` reports the reader in the **Smart card module (ISO 7816)**
  section. `version` is its release number, shown while a reader is ready.
  The `reader` line is one of:
  - `none`
  - `enumerating`
  - `CCID reader 04e6:5810 CLOUD 2700 R Smart Card Reader`
  - `<vid>:<pid> <name> not usable ( not a CCID reader )`, or another reason:
    `no CCID class descriptor`, `not a TPDU level reader`,
    `no automatic PPS or voltage selection`, `reader does not answer`,
    `unexpected answer from the reader`, `USB transfer error`,
    `enumeration failed`.
- A command without a reader on the port prints
  `SC: no USB reader on the CEP port`.
- Without a SAM in the slot it prints `CCID: no card in the reader`, or
  `CCID: the card does not answer` with a reader that reports an empty slot as
  a card that is there. `hw dbg -2` adds the status and error bytes of the
  reader.
- `hw dbg -2` prints the APDUs exchanged with the SAM and the speed the SAM
  runs at (`CCID: card runs T=1, Fi/Di 96`).

---

## Notes

- `armsrc/pm5_cep_usb_host.c` runs the USB host on the port,
  `armsrc/ccid_reader.c` is the CCID class driver, with T=0 and the T=1 block
  protocol, `common_arm/smartcard/smartcard_hw_ccid.c` puts it behind the smart
  card layer.
- The token turns on `WITH_SMARTCARD`: the firmware reports
  `compiled_with_smartcard`, and `hw_available_smartcard` with or without a
  reader on the port, so the client keeps the commands available.
