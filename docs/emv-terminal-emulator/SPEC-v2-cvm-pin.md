# SPEC v2: CVM, PIN, Security Audit

## Scope

Features **F-003** (online PIN — see also [SPEC-v2-host-online.md](./SPEC-v2-host-online.md)), **F-006**, **F-029**, **F-040**

---

## Interactive PIN — REQ-CVM-001–009

### REQ-CVM-001

When `--pin` omitted and CVM requires PIN, terminal shall prompt: `Enter offline PIN:` with **no echo**.

### REQ-CVM-002

Platform implementations:

| Platform | API |
|----------|-----|
| Linux / macOS | `getpass()` or termios `ECHO off` |
| Windows | `_getch()` loop, no echo |
| CI / non-TTY | fail with `PM3_EIO` and message "use --pin or EMV_TEST_PIN" |

### REQ-CVM-003

PIN length 4–12 digits; reject non-numeric before VERIFY.

### REQ-CVM-004

`emv terminal pin` without `--offline` shall prompt interactively.

### REQ-CVM-005

Environment variable `EMV_TEST_PIN` takes precedence over prompt (existing behavior preserved).

---

## Enciphered PIN — REQ-CVM-010–014

### REQ-CVM-010

Enciphered offline PIN (CVM `04`) shall use ICC PIN encipherment public key from card (`9F2D` / certificate chain).

### REQ-CVM-011

On key recovery failure, set TVR "ICC data missing" or "PIN pad fault" per EMV bit definitions and continue CVM list.

### REQ-CVM-012

Unit test vectors in `pin_verify_test.c` for format 2 block structure.

---

## PIN Zeroization Audit — REQ-CVM-020–029

### REQ-CVM-020

All PIN buffers (ASCII, BCD, enciphered block) shall be zeroized on: success, failure, timeout, and context free.

### REQ-CVM-021

Use `memset_s` or volatile wipe wrapper `emv_term_secure_zero()`.

### REQ-CVM-022

APDU log (`-a`) shall **never** contain PIN digits or full PIN block — redact VERIFY command data as `[PIN REDACTED]`.

### REQ-CVM-023

Session JSON shall never contain PIN or PIN block tags.

### REQ-CVM-024

Add debug self-test `emv test --pin-audit` verifying wipe after mock VERIFY.

---

## CVM List Walk Extensions — REQ-CVM-030–039

### REQ-CVM-030

Support CVM codes: `01` plain offline, `04` enciphered offline, `02` online, `1E` signature, `3F` fail CVM.

### REQ-CVM-031

`1E` signature: set CVM Results "signature" without APDU.

### REQ-CVM-032

`3F` fail: stop CVM processing, set TVR "Cardholder verification was not successful".

### REQ-CVM-033

Amount-based CVM rules: compare `(X,Y)` against `(9F02)` BCD using profile currency exponent.

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-CVM-001 | TTY stdin, no --pin | CVM plain | Prompt, no echo |
| AC-CVM-002 | CI non-TTY | CVM plain | Error with hint |
| AC-CVM-003 | `-a` + VERIFY | after command | Log shows REDACTED |
| AC-CVM-004 | After VERIFY | ctx free | PIN buffer all zero |
| AC-CVM-005 | Enciphered CVM card | VERIFY | SW 9000 or documented fail |

---

## Files

| File | Change |
|------|--------|
| `emv_term_pin_prompt.c/h` | Interactive PIN |
| `phase_cvm.c` | CVM codes, audit hooks |
| `emv_term_secure.c/h` | Zeroization helpers |
