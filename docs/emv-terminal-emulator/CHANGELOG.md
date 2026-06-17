# Changelog — EMV Terminal Emulator Documentation

All notable changes to the EMV terminal emulator **documentation and implementation tracking** in this directory.

## Unreleased

### Added — Wave F (crypto playground & card lab)

- **`emv terminal crypto`** — `run`, `digest`, `compare`, `genac`/`genac2`, `vary`, `challenge`, `intauth`, `checksum`, `export`
- **`--summary`** — human-readable card digest (scheme, AIP, crypto path, AFL map, DOLs, MSD block, next-step hints)
- **`--quick`** — quick AFL (skip deep SFIs; stop when CDOL1+CDOL2 found)
- **`--aid`** — force PPSE/application AID; auto PPSE fallback when priority-01 lacks CDOL1
- Visa qVSDC GPO AC hoisting + TTQ re-GPO; MC GEN AC `6700` Le-retry, auto CDA, `9F7C` CDOL support
- Export JSON: `Track2`, `AFL`, `CryptoPath`, `PPSEAppCount`, `AIDFallbackUsed`, `Runs[]`
- Tests: `terminal_crypto_test` digest + compare (offline)
- Docs: `SPEC-crypto-playground.md`, `TEST-PLAN-crypto-playground.md`

### Added — Wave E (contactless reliability & diagnostics)

- **`EMVPrepareContactlessEx`** — auto HF field + wait-for-card across search/GPO/GEN AC and terminal phases
- **`emv search`** — PPSE-first, polling, UID on connect, improved error hints
- **`emv terminal cvm`** — CVM list / terminal capability diagnostics without VERIFY
- **`emv terminal probe`** — GET DATA sweep; `--records` AFL tag summary
- Terminal TLV defaults fix (`9F1A`/`5F2A`); bundled `emv_terminal_profile.json` auto-load
- `emv terminal step` cliparser index segfault fix

### Added — Wave D (M14) implementation

- **Legal banner** — first-run warning; ack file `~/.proxmark3/emv_terminal_ack`; `EMV_TERMINAL_I_ACK=1` for CI
- **PCAP export** — `--pcap-out`, `--pcap-meta`; linktype 265; [doc/emv_pcap_format.md](../../doc/emv_pcap_format.md)
- **Replay** — `emv terminal replay` with `--from-phase` / `--to-phase`
- **Phase timing** — `--timing-report`, `Phases[].duration_ms` in session JSON
- **Capabilities** — `emv terminal capabilities`
- Unit tests: `terminal_pcap_test.c`, `terminal_replay_test.c`

### Added — Wave C (M13) implementation

- `emv terminal export-sim`, `run --export-sim`
- TCP mock acquirer: `emv terminal host listen`, `run --host-tcp`
- Lua bindings (`emv_terminal_*` globals), `client/luascripts/emv_terminal_demo.lua`
- `emv reader --terminal-session`, `--terminal-compare`; contact ATR + MSD path
- `terminal_sim_export_test.c`

### Added — Wave B (M10–M12) implementation

- CVM/PIN: secure zeroize, online PIN stash, amount rules, Interac flash skip
- Session UX: scripts 71/72, `session print|merge|export`, redaction, `--full-tlv`
- ODA/risk: `--exception-file`, `--capk-extra`, CDA verify tracking
- Tests: `terminal_cvm_test.c`, `terminal_exception_test.c`

### Added — Wave A (M7–M9) implementation

- Host simulator: ARQC verify, ARPC CVN18, `emv terminal host-sim`
- Scheme profiles: `--profile auto|interac|visa|mc`
- Golden CI: `emv terminal test --golden`, fixtures under `client/src/emv/test/fixtures/`
- Mock APDU transport: `--mock-apdu-file`

### Added — Operator & upstream documentation

- **OPERATOR-GUIDE.md** — lab workflows, command reference, troubleshooting
- **UPSTREAM-MERGE.md** — stacked PR merge order and single upstream PR title
- README.md rewritten — legal disclaimer front and center, v2 status table

### Added (v2 planning bundle — prior)

- FEATURE-CATALOG-v2.md, IMPLEMENTATION-PLAN-v2.md, MILESTONES-v2.md
- TEST-PLAN-v2-manual.md, TEST-PLAN-v2-automated.md, QA-CHECKLIST-v2.md
- SPEC-v2-*.md (10 files), examples/, golden fixture layout

### Changed

- README.md — from planning-only to shipped v2 status; links to operator guide
- doc/emv_notes.md — expanded `emv terminal` command tree (Wave D)

---

## 1.0.0 (MVP — M1–M6)

- Terminal phases 2, 4–8 in client (`emv terminal` full pipeline)
- CVM, TAA, CAA, online lab stub, session JSON, `load`, `profile validate`

## 0.9.0 (docs)

- Initial planning bundle: SPEC-*, IMPLEMENTATION-PLAN, TEST-PLAN, scheme reference
