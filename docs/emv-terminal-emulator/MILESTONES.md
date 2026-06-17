# Milestones

## Milestone 1: Runnable Skeleton

**Outcome:** `emv terminal` command group exists; docs published; client builds.

**Included:**

- Phase 0 tasks
- Documentation bundle in `docs/emv-terminal-emulator/`
- CI compile verification

**Excluded:**

- PIN, TAA, new behavior

**Acceptance criteria:**

- [ ] `make client/client` succeeds
- [ ] `emv terminal --help` lists subcommands

**Risks:** Makefile integration breaks Windows build — test all CI platforms.

---

## Milestone 2: First Complete Core Flow (Terminal MVP)

**Outcome:** `emv terminal run` matches `emv exec` through GEN AC1 with session JSON.

**Included:**

- Phase 1–2 implementation
- Session export
- qVSDC contactless on test card

**Excluded:**

- PIN verification
- AC2, online

**Acceptance criteria:**

- [ ] AC-CORE-001
- [ ] AC-DATA-002
- [ ] AUTO-CORE-010 exec parity test

**Risks:** Refactor breaks `emv scan` — run regression on scan/exec.

---

## Milestone 3: PIN and Cardholder Verification

**Outcome:** Offline PIN VERIFY works; CVM list processed.

**Included:**

- Phase 3
- Security redaction
- `emv terminal pin`

**Excluded:**

- Online PIN to host
- Enciphered PIN optional if schedule tight — **minimum plain PIN required**

**Acceptance criteria:**

- [ ] AC-CORE-002, AC-CORE-003
- [ ] AC-SEC-001, AC-SEC-002
- [ ] MAN-CORE-010 PIN success/fail

**Risks:** Enciphered PIN RSA edge cases — allow phase deliverable with plain PIN first.

---

## Milestone 4: Full Offline Terminal

**Outcome:** TAA-driven decisions; AC2; decline path correct.

**Included:**

- Phase 4–5
- Terminal profile TACs
- `emv terminal step` for all offline phases

**Excluded:**

- Online ARPC

**Acceptance criteria:**

- [ ] AC-CORE-004
- [ ] MAN-CORE-015 decline on ODA failure + TAC deny

**Risks:** Scheme-specific TAC defaults wrong — document per-AID overrides.

---

## Milestone 5: Online Lab Path

**Outcome:** ARQC → manual ARPC → scripts → completion for test cards.

**Included:**

- Phase 6
- `emv terminal online`

**Excluded:**

- Real acquirer

**Acceptance criteria:**

- [ ] MAN-CORE-020 online lab completion
- [ ] Issuer script transmit on test card

**Risks:** Test card ARPC data unavailable — use published EMVCo examples.

---

## Milestone 6: Testable Beta (PM3Easy)

**Outcome:** PM3Easy owner can flash and run terminal with QA checklist green.

**Included:**

- Phase 7–8
- 256 KB validation doc
- `doc/emv_notes.md` update
- Automated test expansion

**Excluded:**

- Full scheme certification
- All AID/kernel variants

**Acceptance criteria:**

- [ ] QA-CHECKLIST.md MVP section complete
- [ ] MAN-DEVICE-001 flash size
- [ ] UF-01 walkthrough verified on PM3Easy

**Risks:** 256 KB image too large — publish skip profile.

---

## Milestone 7: Release Candidate

**Outcome:** v1.0 tag; stable CLI; known issues documented.

**Included:**

- Bug fixes from beta
- Performance tuning (field ON, retries)
- Optional firmware WTX assist if proven necessary

**Excluded:**

- v2 features (Lua API, GUI)

**Acceptance criteria:**

- [ ] No P0 bugs open
- [ ] CHANGELOG.md 1.0.0 entry
- [ ] Coverity clean on touched files

**Risks:** Hardware variance across PM3Easy clones — document antenna placement tips.
