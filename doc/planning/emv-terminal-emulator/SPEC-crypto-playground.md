# SPEC: EMV Crypto Playground (`emv terminal crypto`)

## Purpose

Laboratory command suite for **card-side cryptographic operations** on EMV payment applets: challenge, GEN AC (ARQC/TC/AAC), DDA internal authenticate, UN/amount sweeps, and crypto TLV export — without running the full terminal phase pipeline.

**Not** a general signing oracle. All operations respect EMV DOL templates (CDOL1/2, DDOL, UDOL) and transaction state (SELECT → GPO → records before GEN AC).

## Command tree

```
emv terminal crypto help
emv terminal crypto run       # full lab bench (init + optional ops)
emv terminal crypto summary     # print CDOL/AIP/crypto context (session or live)
emv terminal crypto challenge   # GET CHALLENGE (00 84)
emv terminal crypto genac       # GENERATE AC (80 AE) from CDOL1
emv terminal crypto genac2      # GENERATE AC from CDOL2 (after ARQC + online stub)
emv terminal crypto vary        # repeat GEN AC with different 9F37 values
emv terminal crypto intauth     # INTERNAL AUTHENTICATE (00 88) / DDA
emv terminal crypto checksum    # COMPUTE CRYPTOGRAPHIC CHECKSUM (80 2A) if UDOL present
emv terminal crypto export      # JSON snapshot of crypto-relevant TLVs
```

## Common flags

| Flag | Meaning |
|------|---------|
| `-s` / `--select` | Activate HF field and select card |
| `-a` / `--apdu` | Log APDUs |
| `-t` / `--tlv` | TLV-decode responses |
| `-w` / `--wired` | Contact (ISO7816) |
| `-j` / `--jload` | Load terminal profile / defaults |
| `--session <file>` | Restore session AID/TLV; skip live init |
| `-o` / `--output <file>` | JSON export path |
| `--amount <cents>` | Override 9F02 (BCD, numeric cents) |
| `--un <hex>` | Override 9F37 unpredictable number (4 bytes) |
| `--decision <aac\|tc\|arqc>` | GEN AC terminal decision (P1) |
| `--cda` | Request CDA in GEN AC P1 |
| `--count <n>` | Repeat count (`vary`, `run --vary`) |

## REQ-CRYPTO-001: Init / context

- Live path: `EMVPrepareContactless` → `emv_transaction_init` (SELECT, GPO, READ RECORDs).
- Session path: `emv_term_session_load_json` + terminal param defaults.
- Terminal tags live in `ctx->terminal`, synced to `ctx->card` for DOL.

## REQ-CRYPTO-002: Summary

Print without card I/O when `--session` has TLV:

- AID, AIP (82), AFL (94)
- CDOL1 (8C), CDOL2 (8D), DDOL (9F49), UDOL if present
- Last AC (9F26), ATC (9F36), CID (9F27), IAD (9F10)
- AIP capability bits: SDA, DDA, CVM, TRM, CDA

## REQ-CRYPTO-003: GET CHALLENGE

- APDU: `00 84 00 00`
- Requires SELECT + GPO (and MC path may need this before GEN AC).
- Store result as 9F4C in card context when used before GEN AC.

## REQ-CRYPTO-004: GENERATE AC

- Build CDOL from tag **8C** (AC1) or **8D** (AC2) via `dol_process`.
- Field overrides applied to **terminal** tree then synced: 9F02, 9F37, 9A, 9F1A, 5F2A.
- P1: `--decision` + optional `--cda`.
- Parse response: 9F27, 9F36, 9F26, 9F10, 9F4B.
- Mastercard M/Chip: auto GET CHALLENGE before GEN AC when vendor is MC and CDOL1 path used.

## REQ-CRYPTO-005: Vary UN

- For `--count N`: set 9F37 to `00 00 00 i` (or random), run GEN AC, print AC+ATC line per iteration.
- Does not reset card session between iterations (ATC must increment on real cards).

## REQ-CRYPTO-006: INTERNAL AUTHENTICATE

- Build DDOL from 9F49 (or default 9F37 04).
- Requires DDA-capable AIP (bit 0x20).
- Display returned dynamic signature / TLV.

## REQ-CRYPTO-007: MSC checksum

- If UDOL tag exists on card context, run `MSCComputeCryptoChecksum`.
- Otherwise print informative skip message.

## REQ-CRYPTO-008: Export JSON

```json
{
  "AID": "...",
  "AIP": "...",
  "CDOL1": "...",
  "ATC": "...",
  "AC": "...",
  "CID": "...",
  "IAD": "...",
  "Runs": [ { "un": "...", "ac": "...", "atc": "...", "sw": "9000" } ]
}
```

PIN and keys are never exported.

## REQ-CRYPTO-009: Run bench

`emv terminal crypto run` executes in order:

1. Init / session load
2. `summary`
3. `challenge` (if `--challenge` or MC auto)
4. `genac` (unless `--no-genac`)
5. `intauth` (if `--intauth` and AIP DDA)
6. `vary` (if `--vary` or `--count > 1`)
7. `export` (if `-o`)

## Security

- Lab / authorized test cards only.
- Export redacts nothing extra beyond excluding PIN material.
- APDU log must not contain PIN blocks (existing redaction).

## Files

| File | Role |
|------|------|
| `emv_term_crypto.c/h` | Core crypto playground logic |
| `emv_term_crypto_cmd.c` | CLI subcommands |
| `emv/test/terminal_crypto_test.c` | Offline unit tests |
| `emv/test/fixtures/crypto_cdol_build/` | CDOL override fixture |
