# EMV Terminal Emulator

> ## ⚠️ FOR RESEARCH AND LAB USE ONLY — NO WARRANTY — PROVIDED AS-IS
>
> The EMV terminal emulator is a **research and education tool**. It is **not** a certified payment terminal, **not** PCI PTS compliant, and **not** suitable for production payment processing.
>
> **You must:**
> - Use only **authorized EMV test cards** or cards you own and may legally test
> - **Not** use this tool to bypass, defraud, or intercept live payment systems
> - Comply with **applicable laws** in your jurisdiction
>
> **No warranty:** Proxmark3 contributors provide this software **as-is** with **no warranty** of any kind, express or implied, including fitness for a particular purpose or non-infringement. Use at your own risk.
>
> **Security & privacy:** [SPEC-security-privacy.md](./SPEC-security-privacy.md) — PIN zeroization, session redaction, threat model  
> **Operator procedures:** [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md) — commands, workflows, CI testing  
> **Upstream merge:** [UPSTREAM-MERGE.md](./UPSTREAM-MERGE.md) — how to land one PR upstream

---

## Plain-English Summary

The Proxmark3 Iceman client includes an **EMV payment terminal emulator** (`emv terminal`) for **PM3GENERIC** builds, with **PM3Easy** as the primary target hardware. The PM3 acts as the terminal (reader side): application selection, record reads, offline authentication, cardholder verification (PIN), Terminal Action Analysis, Generate AC, and optional online completion via a lab host simulator.

Card-side emulation (`emv scan` / `emv sim`) exists separately; this module completes the **terminal-side** flow in client C code under `client/src/emv/terminal/`.

---

## Current Status (v2 — Waves A–D)

| Area | Status |
|------|--------|
| Phase engine (`run` / `step`) | **Shipped** |
| Host simulator (ARQC/ARPC, CVN18) | **Shipped** (Wave A) |
| Scheme profiles (`--profile auto\|interac\|visa\|mc`) | **Shipped** (Wave A) |
| Golden CI (`emv terminal test --golden`) | **Shipped** — 6/6 fixtures, no USB |
| CVM / PIN / session UX / redaction | **Shipped** (Wave B) |
| ODA extras, exception file, scripts 71/72 | **Shipped** (Wave B) |
| emv sim export, TCP host, Lua API, reader trace | **Shipped** (Wave C) |
| Legal banner, PCAP, replay, timing, capabilities | **Shipped** (Wave D) |
| Firmware terminal assist | **Not implemented** |
| PM3Easy 256 KB firmware fit | **Not validated** |

---

## Quick Start

```bash
# Build (gcc recommended)
make -C client CC=gcc

# Capabilities (no device)
./pm3 --offline -c 'emv terminal capabilities'

# Full contactless run (lab test card)
./pm3 -- emv terminal run -satj -o /tmp/session.json --qvsdc --profile auto

# Regression (no USB)
./pm3 --offline -c 'emv test'
./pm3 --offline -c 'emv terminal test --golden'
```

See **[OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md)** for PIN handling, host-sim, mock replay, PCAP, and troubleshooting.

---

## Who This Is For

- Proxmark3 developers and maintainers
- PM3Easy owners testing contactless EMV in a **lab**
- Security researchers studying EMV protocol behavior (**authorized test cards only**)

---

## What This System Does

1. **Load terminal profile** — JSON terminal parameters and scheme profiles
2. **Present / read card** — PPSE/AID, GPO, AFL over HF 14a or smartcard contact
3. **Authenticate card** — SDA, DDA, fDDA, CDA via existing `emvcore.c`
4. **Verify cardholder** — offline / enciphered PIN, online PIN stub
5. **TAA + Generate AC** — ARQC / TC / AAC decision and cryptogram
6. **Optional online** — host simulator, TCP mock acquirer, manual ARPC
7. **Export session** — JSON trace, PCAP, sim patch, merge with scan

---

## Major Components

| Component | Location | Role |
|-----------|----------|------|
| Terminal phase engine | `client/src/emv/terminal/` | EMV Book 3 phase orchestration |
| EMV core | `client/src/emv/emvcore.c`, `dol.c`, crypto | APDU, ODA, DOL |
| CLI | `client/src/emv/terminal/emv_term_cmd.c` | `emv terminal` command tree |
| ISO7816 transport | `client/src/iso7816/` | Contactless + smartcard |
| Golden fixtures | `client/src/emv/test/fixtures/` | CI regression |
| Lua demo | `client/luascripts/emv_terminal_demo.lua` | Script API smoke test |

---

## Documentation Map

```text
docs/emv-terminal-emulator/
├── README.md                 ← you are here (legal + overview)
├── OPERATOR-GUIDE.md         ← day-to-day commands and workflows
├── UPSTREAM-MERGE.md         ← single upstream PR merge plan
├── CHANGELOG.md              ← feature/doc change history
├── SPEC-security-privacy.md  ← PIN, redaction, legal use (REQUIRED READING)
├── FEATURE-CATALOG-v2.md     ← F-001–F-040 index
├── IMPLEMENTATION-PLAN-v2.md ← M7–M14 build order
├── MILESTONES-v2.md          ← release gates
├── TEST-PLAN-v2-*.md         ← manual + automated tests
├── QA-CHECKLIST-v2.md
├── SPEC-v2-*.md              ← technical specs (10 files)
└── examples/                 ← profiles, keys templates (lab only)
```

Related:

- [doc/emv_notes.md](../../doc/emv_notes.md) — all EMV commands
- [doc/emv_pcap_format.md](../../doc/emv_pcap_format.md) — Wireshark PCAP linktype 265

---

## v2 Program Reference

| Wave | Milestones | Theme |
|------|------------|-------|
| A | M7–M9 | Host-sim, scheme profiles, golden CI |
| B | M10–M12 | CVM/PIN, session UX, ODA/risk |
| C | M13 | sim bridge, TCP host, Lua, reader |
| D | M14 | banner, PCAP, replay, timing |

**Deferred:** firmware WTX assist (F-027) — only if contactless timing fails on hardware.

---

## Known Gaps

- No EMVCo kernel certification (lab/research tool only)
- Contact chip (`-w`) requires smartcard hardware mod
- PM3Easy flash budget not formally signed off in CI

---

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) and root [CHANGELOG.md](../../CHANGELOG.md) (unreleased section).
