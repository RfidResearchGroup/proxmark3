# QA Checklist — EMV Terminal Emulator

## Build Checks

- [ ] `make -j PLATFORM=PM3GENERIC` fullimage succeeds
- [ ] `make -j PLATFORM=PM3GENERIC LED_ORDER=PM3EASY` succeeds (if supported via Makefile.platform)
- [ ] `make client/client` succeeds on Linux, macOS, Windows CI
- [ ] No new compiler warnings in `client/src/emv/terminal/`
- [ ] 256 KB profile documented and verified OR size report attached

## Lint / Static Checks

- [ ] Coverity / static analysis on new terminal sources
- [ ] No hardcoded test PINs in source
- [ ] Includes use repo conventions (`common.h`, `ui.h`)

## Unit Tests

- [ ] `emv test` passes (existing crypto)
- [ ] `emv test --terminal` passes (new)
- [ ] AUTO-SEC-001 PIN zeroization passes

## Integration Tests

- [ ] AUTO-INT-001 fixture replay passes
- [ ] Exec/terminal APDU parity (AUTO-CORE-010)

## Manual Smoke Tests (PM3Easy)

- [ ] MAN-CORE-001 terminal run qVSDC
- [ ] MAN-CORE-010 PIN success
- [ ] MAN-DEVICE-004 no smartcard wired rejection
- [ ] MAN-SEC-001 log redaction

## Security Review

- [ ] Session JSON default redaction verified
- [ ] PIN not in shell history docs (env var alternative documented)
- [ ] README states authorized lab use only

## Data Loss Review

- [ ] Partial session saved on abort with `-o`
- [ ] Field drops on all exit paths (success, error, button)

## Upgrade / Migration Review

- [ ] `emv exec` behavior unchanged without new flags
- [ ] `emv scan` JSON format unchanged
- [ ] Old `emv_defparams.json` still loads

## Logging / Diagnostics

- [ ] `--trace-phases` shows phase boundaries
- [ ] SW codes include human descriptions
- [ ] Errors reference REQ-ID in debug build (optional)

## Documentation Completeness

- [ ] `doc/planning/emv-terminal-emulator/README.md` current
- [ ] `doc/emv_notes.md` links terminal section
- [ ] IMPLEMENTATION-PLAN phases match merged code
- [ ] OPEN-QUESTIONS updated for resolved items

## Known Issue Triage

- [ ] All P0/P1 bugs filed with reproduction
- [ ] Deferred features listed in IMPLEMENTATION-PLAN Deferred Work
- [ ] Scheme-specific gaps documented

## Ship / No-Ship (MVP)

**Ship when:** all Manual Smoke + Unit + Build checks pass; Milestone 3 minimum (PIN) for user-requested MVP.

**No-ship if:** PIN appears in default logs; firmware size regression on 512 KB default; `emv exec` regression.
