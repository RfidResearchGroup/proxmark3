# Upstream Merge Plan — EMV Terminal Emulator

This document describes how to land the EMV terminal emulator as **one contribution** to the upstream Proxmark3 Iceman repository.

**Upstream PR:** [RfidResearchGroup/proxmark3#3385](https://github.com/RfidResearchGroup/proxmark3/pull/3385) (`andrew867:master`)

---

## Current status (2026-06-17)

All waves through **Wave F** are merged on `andrew867/proxmark3` `master` and included in upstream PR #3385. Hardware-validated on Visa qVSDC/MSD, Mastercard credit/debit (incl. Maestro PPSE fallback), and Interac contactless cards.

| Wave | Milestone | Highlights |
|------|-----------|------------|
| MVP | M1–M6 | Full phase pipeline, session export, profiles |
| A | M7–M9 | Host-sim, scheme profiles, golden CI |
| B | M10–M12 | CVM/PIN, session UX, ODA/risk |
| C | M13 | Lua, TCP acquirer, sim export, reader compare |
| D | M14 | PCAP, replay, timing, legal banner |
| **E** | Post-MVP | Contactless auto-field, search polling, CVM/probe diagnostics, terminal TLV defaults |
| **F** | Crypto lab | `emv terminal crypto` playground, `--summary` digest, `--quick` AFL, AID fallback, `compare` |

---

## Development PR stack (this fork — historical)

| PR | Branch | Milestone |
|----|--------|-----------|
| #1 | `cursor/emv-terminal-emulator-specs-d143` | Docs + v2 specs |
| #3–#5 | Wave B–D branches | M10–M14 |
| #6–#8 | Field activation, terminal fixes, crypto digest | Waves E–F |

Stacked fork PRs are superseded by upstream #3385.

---

## Recommended upstream pull request

**Superseded:** monolithic PR #3385 should be replaced by **four smaller PRs** — see [UPSTREAM-PR-SPLIT-PLAN.md](./UPSTREAM-PR-SPLIT-PLAN.md) (maintainer request: docs → resources → smaller code).

| Field | Value |
|-------|--------|
| **Title** | `feat(emv): add EMV terminal emulator (lab research tool)` |
| **URL** | https://github.com/RfidResearchGroup/proxmark3/pull/3385 |
| **Head** | `andrew867:master` |
| **Base** | upstream `master` |
| **Status** | Close after split PRs 1–4 are open |

### PR description update (Wave E + F)

When refreshing the upstream PR body, add these sections after Wave D:

**Wave E — Contactless reliability & diagnostics:** `EMVPrepareContactlessEx`, wait-for-card polling, search/PPSE improvements, `emv terminal step` segfault fix, CVM TLV sync, `cvm`/`probe` commands, terminal default fixes (`9F1A`/`5F2A`, runtime date/time, random `9F37`).

**Wave F — Crypto playground & card lab:** `emv terminal crypto` (`run`, `digest`, `compare`, `genac`, `vary`, …), `--summary` human-readable card digest, `--quick` AFL, `--aid` forced selection, PPSE AID auto-fallback, Visa qVSDC/MSD + MC GEN AC reliability, export JSON with `Track2`/`CryptoPath`/`PPSEAppCount`.

**Command tree v3:** add `cvm`, `probe`, and `crypto` subtree (see `emv_term_crypto_cmd.c`).

**Testing:** `terminal_crypto_test` — BCD, CDOL UN, export, digest, compare (offline).

**Hardware smoke test:**

```bash
emv terminal crypto run -s --quick -o card.json
emv terminal crypto run -s -o card.json
emv terminal crypto run -s --aid A0000000042203
emv terminal crypto compare -a mc.json -b visa.json
emv terminal run -s
```

Full suggested PR body (all waves): copy from maintainer notes or regenerate from sections in this file + original Wave A–D tables in PR #3385.

---

## Pre-merge checklist

- [x] `CC=gcc make -C client` clean build
- [x] `./pm3 --offline -c 'emv test'` passes
- [x] `./pm3 --offline -c 'emv terminal test --golden'` — 6/6 OK
- [x] Legal banner + README disclaimer reviewed
- [x] No real PAN/keys in fixtures or examples
- [ ] Root `CHANGELOG.md` entry (unreleased section updated)
- [ ] Upstream PR description refreshed with Wave E/F (manual — maintainer token)

---

## After upstream merge

Close stacked fork PRs (superseded by upstream PR #3385).  
Tag locally if desired: `emv-term-v2.3` per [MILESTONES-v2.md](./MILESTONES-v2.md).
