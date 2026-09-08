# Notes on `hf mfu ndefformat`
<a id="Top"></a>

# Table of Contents
- [Notes on hf mfu ndefformat](#notes-on-hf-mfu-ndefformat)
- [Table of Contents](#table-of-contents)
  - [Why the command exists](#why-the-command-exists)
  - [Capability Container basics](#capability-container-basics)
  - [Per-type delivery content](#per-type-delivery-content)
  - [Lock Control TLV](#lock-control-tlv)
  - [NTAG215 / NTAG216 under-reporting](#ntag215--ntag216-under-reporting)
  - [NTAG213C](#ntag213c)

## Why the command exists
^[Top](#top)

`hf mfu ndefwrite` refuses a tag with no Capability Container (CC). Before this command the only way to add one was a hand computed `hf mfu wrbl -b 3 -d <cc>` — block 3 is One Time Programmable (OTP), so a wrong value is permanent.

`hf mfu ndefformat` writes the NXP factory delivery content (CC + an empty NDEF message) for the detected tag type, restoring what the tag looked like before anything was written to it.

## Capability Container basics
^[Top](#top)

Page 3 (`E1 10 <MLEN> 00`) is OTP on every type below: a WRITE is bit-wise OR'ed with the current content, so a bit already set to 1 can never be cleared again. `MLEN * 8` is the size of the NDEF data area in bytes.

Consequences for the implementation, in `mfu_get_ndef_format()` / `CmdHF14AMfUFormat()` in `client/src/cmdhfmfu.c`:

- an unknown tag type is refused rather than guessed at
- a target CC that the current OTP content cannot reach (checked with the same bit-wise OR) is refused before anything is written
- `-d` on a *known* type is capped at that type's own MLEN unless `--force` is given, so a typo cannot silently announce more memory than the tag holds
- `--erase`'s end block is derived from the table's MLEN, never from `-d`, so it cannot run past the user memory into the lock bytes or configuration pages
- after writing, the command re-selects and reads blocks 3-5 back to confirm the OTP write actually took — a tag can ACK a WRITE and still not commit the page (weak field, tearing, a lock bit already set)

## Per-type delivery content
^[Top](#top)

Only the NTAG21x family ships with a CC at all. UL / UL-C / UL EV1 and NTAG203 leave page 3 blank at delivery, so their CC is derived from the user memory range instead of copied from a data sheet.

| Type | Part | MLEN | User memory | Data sheet |
|---|---|---|---|---|
| MIFARE Ultralight | MF0ICU1 | 06h (48B) | pages 04h-0Fh | [MF0ICU1.pdf](https://www.nxp.com/docs/en/data-sheet/MF0ICU1.pdf) rev 3.9, §7.5 Table 5 (p.10/31, OTP blank) |
| MIFARE Ultralight C | MF0ICU2 | 12h (144B) | pages 04h-27h | [MF0ICU2.pdf](https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf) rev 3.5, §7.5 Table 5 (p.8/35), §7.5.4 (p.11/35, OTP blank) |
| MIFARE Ultralight EV1 48 | MF0UL11 | 06h (48B) | pages 04h-0Fh | [MF0ULX1.pdf](https://www.nxp.com/docs/en/data-sheet/MF0ULX1.pdf) rev 3.3, §8.5 Fig 5 (p.10/45), §8.5.4 (p.13-14/45, OTP blank) |
| MIFARE Ultralight EV1 128 | MF0UL21 | 10h (128B) | pages 04h-23h | [MF0ULX1.pdf](https://www.nxp.com/docs/en/data-sheet/MF0ULX1.pdf) rev 3.3, §8.5 Fig 6 (p.11/45), §8.5.4 (p.13-14/45, OTP blank) |
| NTAG203 | NT2H0301 | 12h (144B) | pages 04h-27h | [NTAG203.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG203.pdf) rev 3.0, §8.5 Table 5 (p.10/30), §8.5.3 (p.13/30, OTP blank) |
| NTAG210 | NT2H1011 | 06h (48B) | pages 04h-0Fh | [NTAG210_212.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG210_212.pdf) rev 3.0, §8.5.6 Table 4 (p.14/46) |
| NTAG210u | NT2L1001 / NT2H1001 | 06h (48B) | pages 04h-0Fh | [NT2L1001_NT2H1001.pdf](https://www.nxp.com/docs/en/data-sheet/NT2L1001_NT2H1001.pdf) rev 3.0, §9.5.5 Table 4 (p.11/32) |
| NTAG212 | NT2L1211 | 10h (128B) | pages 04h-23h | [NTAG210_212.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG210_212.pdf) rev 3.0, §8.5.6 Table 5 (p.14/46) |
| NTAG213 | NT2H1311 | 12h (144B) | pages 04h-27h | [NTAG213_215_216.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf) rev 3.2, §8.5.6 Table 5 (p.17/60) |
| NTAG213F | NT2H1311F | 12h (144B) | pages 04h-27h | [NTAG213F_216F.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG213F_216F.pdf) rev 3.6, §8.5.6 Table 5 (p.17/55) |
| NTAG213TT | NT2H1311TT | 12h (144B) | pages 04h-27h | [NT2H1311TT.pdf](https://www.nxp.com/docs/en/data-sheet/NT2H1311TT.pdf) rev 1.1, §8.5.6 Table 5 (p.15/57) |
| NTAG213C | NT2H1311C1DTL | 12h (144B) | pages 04h-27h | none — see [NTAG213C](#ntag213c) |
| NTAG215 | NT2H1511 | 3Eh (496B) | pages 04h-81h | [NTAG213_215_216.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf) rev 3.2, §8.5.6 Table 6 (p.17/60) |
| NTAG216 | NT2H1611 | 6Dh (872B) | pages 04h-E1h | [NTAG213_215_216.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf) rev 3.2, §8.5.6 Table 7 (p.17/60) |
| NTAG216F | NT2H1611F | 6Dh (872B) | pages 04h-E1h | [NTAG213F_216F.pdf](https://www.nxp.com/docs/en/data-sheet/NTAG213F_216F.pdf) rev 3.6, §8.5.6 Table 6 (p.17/55) |

## Lock Control TLV
^[Top](#top)

Standards ref: NFC Forum Type 2 Tag Operation, and the Capability Container layout in the data sheets cited above.

NTAG212, NTAG213, NTAG213F and NTAG213TT are delivered with a 5 byte Lock Control TLV ahead of the NDEF TLV (`01 03 <pages/offset> <size> <bytes-per-lockbit/page> ...`). The other types in the table are not. This TLV tells an NFC device where the *dynamic* lock bytes live so it can lock the tag read-only — on these parts the dynamic lock bytes sit just past the user memory (e.g. NTAG213 at page 40h, right after the page 04h-27h data area), so the TLV exists purely for that use case, not because a writer needs to avoid overwriting anything.

`hf mfu ndefformat` copies this TLV verbatim from the factory content; it does not construct one. `hf mfu ndefwrite` preserves any control TLV (type `01` or `02`) it finds ahead of the NDEF TLV before overwriting the data area — see the code for the exact scan.

## NTAG215 / NTAG216 under-reporting
^[Top](#top)

The factory MLEN announces less than the physical user memory: NTAG215 announces 496 bytes of a 504 byte area, NTAG216 announces 872 of 888. The data sheet does not explain the 8/16 byte gap. The NXP value is used as-is rather than corrected upward, since under-reporting can never let a write run past the user memory while a larger value could.

## NTAG213C
^[Top](#top)

NXP publishes no data sheet for this part number (NT2H1311C1DTL) and none could be found anywhere else. It was added to the client in commit `ad19f8384` (2020-09-26, "add accurate detection for NT2H1311C1DTL") from an observed tag's `GET_VERSION` response, which differs from a plain NTAG213 only in the minor product version byte (`01h` vs `00h`); the storage size byte — the one that encodes the 144 byte user memory — is identical. The NTAG213 content is used on that basis.
