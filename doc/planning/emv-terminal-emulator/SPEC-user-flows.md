# SPEC: User Flows

## Purpose

Describe operator workflows for lab EMV terminal emulation on PM3Easy.

## Scope

Contactless-first flows on PM3GENERIC client + PM3Easy device.

## Non-Goals

Merchant checkout UX, receipt printing, tipping, cashback

## User / Actor Stories

See individual flows below.

## Functional Requirements

REQ-UI-001: Each flow shall be completable from the standard `proxmark3` interactive client.

REQ-UI-002: Flows shall document required hardware: PM3Easy, USB cable, HF antenna, optional smartcard mod.

REQ-UI-003: Error messages shall suggest the next diagnostic command (`emv reader`, `hf 14a info`).

## Main Flows

### UF-01 — First terminal transaction (contactless)

**Actor:** PM3Easy owner, first time

1. Build firmware: `PLATFORM=PM3GENERIC`, `LED_ORDER=PM3EASY` in `Makefile.platform`
2. Flash fullimage; connect USB; verify `hw status`
3. Place EMV test card on antenna
4. Run: `emv terminal run -j -a -t -o session.json --amount 100 --qvsdc`
5. If CVM prompts for PIN, enter test PIN
6. Review outcome and `session.json` phases

**Success:** Outcome printed; session file created; field drops

### UF-02 — Step-debug failing ODA

**Actor:** Developer

1. `emv terminal step init -j -o /tmp/s.json --qvsdc`
2. Inspect TLV: `emv list` or session file
3. `emv terminal step oda --session /tmp/s.json -a`
4. If CA key missing, add key to resources or use `--no-oda-required`
5. Continue with `step restrict`, `step cvm`, etc.

### UF-03 — PIN verification only

**Actor:** Researcher testing CVM

1. Complete init phase on card with offline PIN CVM
2. `emv terminal pin --offline 1234` with active field/session
3. Verify SW 9000 and updated CVMR in session

### UF-04 — Compare with legacy exec

**Actor:** Maintainer regression

1. `emv exec -sat --qvsdc` — record APDU log
2. `emv terminal run -at --qvsdc -o session.json` — compare APDU sequence through GEN AC1
3. Differences documented in CHANGELOG if intentional

### UF-05 — Scan card then terminal replay (research)

**Actor:** Lab operator

1. `emv scan -at card.json` — capture card static data
2. `emv terminal load card.json` — offline card tree
3. Note: GEN AC still requires live card or emulator; load aids static analysis only

### UF-06 — Contact wired EMV (SMARTCARD mod)

**Actor:** Operator with hardware mod

1. Build with `PLATFORM_EXTRAS=SMARTCARD`
2. Insert chip card in smartcard slot
3. `emv terminal run -w -j -o session.json`

### UF-07 — Online lab completion (v0.4)

**Actor:** Researcher with test host stub

1. Run terminal through ARQC outcome
2. `emv terminal online --session session.json --arpc <hex>`
3. Complete issuer scripts if presentacion
4. Second GEN AC if required

## Edge Cases

- Card not detected: UF-01 step 3 fails → run `hf 14a info` first
- Multiple cards in field: remove extras; use `-s` select pattern from `emv exec`

## Failure Handling

Documented in [SPEC-error-handling.md](./SPEC-error-handling.md); flows include retry step where safe (re-run init).

## Security / Privacy Notes

Use test cards in private lab; do not photograph PIN entry screens with real credentials.

## Acceptance Criteria

AC-UI-001: New operator following UF-01 completes one transaction without reading source code.

AC-UI-002: UF-02 identifies ODA failure cause within 3 commands.

## Test Coverage Notes

MAN-UI-001 maps to UF-01; MAN-UI-002 to UF-03.

## Open Questions

None critical.
