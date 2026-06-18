# QA Checklist v2 — EMV Terminal Emulator

Use before tagging `emv-term-v2.x` releases.

---

## Documentation

- [ ] [FEATURE-CATALOG-v2.md](./FEATURE-CATALOG-v2.md) matches implemented commands
- [ ] All REQ-* in shipped specs marked implemented or deferred in CHANGELOG
- [ ] [TEST-CARD-MATRIX.md](./examples/TEST-CARD-MATRIX.md) updated with card serials used
- [ ] `doc/emv_notes.md` lists all v2 subcommands
- [ ] `commands.json` regenerated
- [ ] OPEN-QUESTIONS decision log updated for resolved OQ items

---

## Build

- [ ] `make -C client -j` clean build (Linux)
- [ ] `make -C client -j` on macOS (if maintainer available)
- [ ] No new `-Werror` violations in terminal modules
- [ ] PM3Easy 256 KB firmware size job green (REQ-TST-050)

---

## Automated Tests

- [ ] `./pm3 -- emv test --terminal` → Tests ( ok )
- [ ] `./pm3 -- emv terminal test --golden` → Golden: N/N OK
- [ ] `./tools/pm3_tests.sh client` includes golden + profile validate
- [ ] New unit tests for each merged PR touching terminal/

---

## P0 Feature Gates (emv-term-v2.0)

- [ ] **F-001** host-sim completes Interac TC01 online
- [ ] **F-011** ARQC verify logged OK/FAIL correctly
- [ ] **F-002** `--profile auto` selects correct scheme
- [ ] **F-016** mock APDU run without hardware
- [ ] **F-017** ≥4 golden fixtures pass
- [ ] **F-032** batch test in CI

---

## P1 Feature Gates (emv-term-v2.1)

- [ ] **F-003** online PIN TVR path
- [ ] **F-006** interactive PIN on Linux
- [ ] **F-007** amount/currency overrides
- [ ] **F-008** `--aid` / `--forceaid`
- [ ] **F-010** session print with TVR decode
- [ ] **F-028** default session redaction
- [ ] **F-029** PIN audit tests pass
- [ ] **F-004** script 72 path

---

## Security

- [ ] PIN never in session JSON (AUTO-SEC-002)
- [ ] APDU log redaction verified (MAN-V2-039)
- [ ] `--no-redact` prints warning
- [ ] Legal banner on first use (MAN-V2-123)
- [ ] No production acquirer URLs or live host defaults in repo

---

## Hardware Smoke (minimum)

- [ ] Contactless: one successful `run --profile auto -o s.json`
- [ ] Contactless: host-sim online completion
- [ ] Contact (if mod): Interac VERIFY PIN
- [ ] Wrong PIN path does not leak PIN in log
- [ ] `emv terminal compare` exec vs terminal ≤1 intentional diff documented

---

## Scheme Coverage

- [ ] Interac: TC01 online + TC02 decline
- [ ] Visa: qVSDC offline or ARQC
- [ ] MC: M/Chip ARQC or documented limitation

---

## Integration

- [ ] `emv terminal load` + `step` offline phases
- [ ] export-sim produces parseable JSON (if M13 shipped)
- [ ] Lua demo runs (if M13 shipped)

---

## Release Artifacts

- [ ] CHANGELOG v2 section complete
- [ ] Git tag `emv-term-v2.x` with release notes
- [ ] Example traces in fixtures anonymized (no real PAN)

---

## Sign-off

| Role | Name | Date | Tag |
|------|------|------|-----|
| Dev | | | |
| QA | | | |
| Hardware smoke | | | |
