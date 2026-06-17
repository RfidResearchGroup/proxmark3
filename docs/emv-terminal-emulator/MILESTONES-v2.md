# Milestones v2 — EMV Terminal Emulator Enhancements

## Overview

Milestones M7–M14 extend the terminal emulator from **MVP (M1–M6)** to a **lab-grade, CI-backed, multi-scheme** platform. Each milestone has entry criteria, exit criteria, and a demo script.

---

## M7 — Host Simulator (P0)

**Delivers:** F-001, F-011, F-038

| Gate | Criterion |
|------|-----------|
| Entry | M6 complete; `phase_online.c` accepts `--arpc` |
| Exit | `emv terminal host-sim --session s.json` completes Interac TC01 online without manual ARPC |
| Demo | `./pm3 -- emv terminal run -j --profile interac --host-sim -o s.json` → `approved_online` |

**Acceptance tests:** AUTO-V2-001–015, MAN-V2-001–010

---

## M8 — Scheme Profiles (P0)

**Delivers:** F-002, F-015, F-024, F-036, F-040, F-034

| Gate | Criterion |
|------|-----------|
| Entry | M7 or parallel if host-sim not needed for profile load |
| Exit | `--profile auto` correct for Interac, Visa, MC test AIDs |
| Demo | Same card, three profiles → different TAA outcomes where TVR differs |

**Acceptance tests:** AUTO-V2-016–025, AUTO-V2-084–088, AUTO-V2-129–133, MAN-V2-011–020

---

## M9 — CI Mock + Golden (P0)

**Delivers:** F-016, F-017, F-009, F-032, F-018

| Gate | Criterion |
|------|-----------|
| Entry | Recorded APDU trace from one `emv scan` |
| Exit | `emv terminal test --golden` passes in CI without device |
| Demo | GitHub Actions job green; local `./pm3 -- emv terminal test --golden` |

**Acceptance tests:** AUTO-V2-053–160, MAN-V2-079–086

---

## M10 — Advanced CVM (P1)

**Delivers:** F-003, F-006, F-029, F-040

| Gate | Criterion |
|------|-----------|
| Entry | M8 profiles (CVM policy per scheme) |
| Exit | Online PIN defers to host-sim; interactive PIN works on Linux |
| Demo | `./pm3 -- emv terminal run --profile interac` prompts for PIN |

**Acceptance tests:** AUTO-V2-026–030, AUTO-V2-041–045, MAN-V2-021–040

---

## M11 — Scripts + Session UX (P1)

**Delivers:** F-004, F-005, F-010, F-028, F-037

| Gate | Criterion |
|------|-----------|
| Entry | M7 online path stable |
| Exit | Tag 72 processed; session print readable; redacted export default |
| Demo | `emv terminal session print s.json` shows decoded TVR bits |

**Acceptance tests:** AUTO-V2-031–040, AUTO-V2-059–062, MAN-V2-026–055

---

## M12 — ODA + Risk (P1–P2)

**Delivers:** F-012, F-013, F-014, F-026

| Gate | Criterion |
|------|-----------|
| Entry | Existing ODA phase green on Visa VSDC card |
| Exit | fDDA qVSDC path logs SDAD verify; exception file denies PAN |
| Demo | `--exception-file bad_pans.txt` → AAC at TAA |

**Acceptance tests:** AUTO-V2-071–083, MAN-V2-061–073

---

## M13 — Integration (P2)

**Delivers:** F-019, F-020, F-021, F-022, F-023, F-025

| Gate | Criterion |
|------|-----------|
| Entry | M11 session export stable |
| Exit | Lua script runs terminal; TCP host accepts connection |
| Demo | `script run emv_terminal_demo.lua` + `nc localhost 8583` |

**Acceptance tests:** AUTO-V2-109–128, MAN-V2-087–113

---

## M14 — Trace + Polish (P2–P3)

**Delivers:** F-030, F-031, F-033, F-035, F-039

| Gate | Criterion |
|------|-----------|
| Entry | M9 mock replay infrastructure |
| Exit | pcap opens in Wireshark; legal banner once per install |
| Demo | `--pcap-out /tmp/emv.pcap` during terminal run |

**Acceptance tests:** AUTO-V2-150–176, MAN-V2-123–136

---

## Release Tags (proposed)

| Tag | Milestones | Theme |
|-----|------------|-------|
| `emv-term-v2.0` | M7 + M8 + M9 | Real online + CI |
| `emv-term-v2.1` | M10 + M11 | CVM + session UX |
| `emv-term-v2.2` | M12 + M13 | ODA + integration |
| `emv-term-v2.3` | M14 | Trace + polish |

---

## Hardware Test Matrix (minimum before each tag)

| Tag | Cards / setup |
|-----|----------------|
| v2.0 | Interac TC01 contact; Visa qVSDC CL; PM3GENERIC build |
| v2.1 | Interac TC02 wrong PIN; enciphered PIN card if available |
| v2.2 | MC M/Chip CL; SMARTCARD mod contact Interac |
| v2.3 | Replay trace only (no new card required) |

See [TEST-PLAN-v2-manual.md](./TEST-PLAN-v2-manual.md) for full matrix.
