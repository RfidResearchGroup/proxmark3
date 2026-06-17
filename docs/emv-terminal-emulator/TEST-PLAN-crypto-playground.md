# TEST-PLAN: EMV Crypto Playground

## Automated (offline, `make client/check`)

### AC-CRYPTO-001: BCD amount encode/decode

- Given amount 100 cents, CDOL build contains 9F02 `000000000100`.

### AC-CRYPTO-002: UN override in CDOL

- Given CDOL1 `9F37 04` and `--un 01020304`, CDOL data includes `01020304` at correct offset.

### AC-CRYPTO-003: Export JSON shape

- `emv_term_crypto_export_json` writes AID, CDOL1 hex, no PIN fields.

### AC-CRYPTO-004: Summary without card

- Load `fixtures/crypto_cdol_build/card_tlv.json`, summary prints CDOL1 and AIP.

### AC-CRYPTO-005: Golden / CI

- `emv terminal test --golden` still passes.
- `exec_terminal_crypto_test` passes in `emv test`.

## Manual (hardware + test card)

### AC-CRYPTO-M01: Challenge

```
emv terminal crypto run -s -j --challenge --no-genac -a
```

- Expect 4 or 8 byte challenge, SW 9000.

### AC-CRYPTO-M02: ARQC collection

```
emv terminal crypto genac -s -j --decision arqc --amount 100 -t -o /tmp/c.json -a
```

- Expect 9F26, 9F36 increment on repeat.

### AC-CRYPTO-M03: Vary UN

```
emv terminal crypto vary -s -j --count 5 --decision arqc -a
```

- Five GEN AC lines; ATC increases (or card returns error if state invalid).

### AC-CRYPTO-M04: DDA intauth

- Card with AIP DDA bit set:
```
emv terminal crypto intauth -s -j -t -a
```

### AC-CRYPTO-M05: Full bench

```
emv terminal crypto run -s -j --decision arqc --vary --count 3 -o /tmp/bench.json -a
```

### AC-CRYPTO-M06: Session-only summary

```
emv terminal run -j -o s.json --full-tlv --stop-after init
emv terminal crypto summary --session s.json
```

## Regression

- Existing `emv genac`, `emv challenge`, `emv terminal probe` unchanged.
- No firmware changes required.
