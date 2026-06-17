# Feature Catalog v2 — EMV Terminal Emulator (Post-MVP)

## Purpose

Master index of **every implementable enhancement** for the PM3 EMV terminal emulator after Milestones 1–6 (Phases 0–8). Each row links to a detailed spec, manual test IDs, and automated test IDs.

**Excluded from v2 scope (defer):**

| ID | Feature | Reason |
|----|---------|--------|
| F-027 | Firmware WTX / timing assist (`armsrc/emvterm.c`) | Requires measured timing failure on hardware; not client-only |
| — | EMVCo kernel certification | Out of product scope (lab/research tool) |
| — | Live acquirer / production HSM | Legal and scope boundary |

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| **P0** | Unblocks credible online + multi-scheme lab work |
| **P1** | High daily value for developers and CI |
| **P2** | Polish, integration, advanced research |
| **P3** | Nice-to-have / stretch |

---

## Feature Index

| ID | Feature | Priority | Spec | Manual tests | Auto tests | Depends on |
|----|---------|----------|------|--------------|------------|------------|
| F-001 | Local host simulator (`emv terminal host-sim`) | P0 | [SPEC-v2-host-online.md](./SPEC-v2-host-online.md) | MAN-V2-001–010 | AUTO-V2-001–015 | Phases 0–8 |
| F-002 | Scheme profile packs (`--profile interac\|visa\|mc`) | P0 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-011–020 | AUTO-V2-016–025 | F-001 |
| F-003 | Online PIN CVM (code `02`) + host deferral | P0 | [SPEC-v2-host-online.md](./SPEC-v2-host-online.md) | MAN-V2-021–025 | AUTO-V2-026–030 | F-001 |
| F-004 | Issuer script tag `72` (post-AC2) | P1 | [SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md) | MAN-V2-026–030 | AUTO-V2-031–035 | Phase 6 online |
| F-005 | Session ↔ scan merge + `--full-tlv` | P1 | [SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md) | MAN-V2-031–035 | AUTO-V2-036–040 | `emv scan` JSON |
| F-006 | Interactive PIN (no-echo, all platforms) | P1 | [SPEC-v2-cvm-pin.md](./SPEC-v2-cvm-pin.md) | MAN-V2-036–040 | AUTO-V2-041–045 | Phase 3 CVM |
| F-007 | CLI txn overrides (`--amount`, `--currency`, `--date`, `--type`) | P1 | [SPEC-v2-cli-ux.md](./SPEC-v2-cli-ux.md) | MAN-V2-041–045 | AUTO-V2-046–050 | Profile JSON |
| F-008 | `--forceaid` / `--aid` on all terminal commands | P1 | [SPEC-v2-cli-ux.md](./SPEC-v2-cli-ux.md) | MAN-V2-046–048 | AUTO-V2-051–052 | Phase 0 init |
| F-009 | APDU parity diff (`emv terminal compare`) | P1 | [SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md) | MAN-V2-049–052 | AUTO-V2-053–058 | `emv exec` |
| F-010 | Session pretty-print (`emv terminal session print`) | P1 | [SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md) | MAN-V2-053–055 | AUTO-V2-059–062 | Session JSON |
| F-011 | Cryptographic ARQC verification (log pass/fail) | P0 | [SPEC-v2-host-online.md](./SPEC-v2-host-online.md) | MAN-V2-056–060 | AUTO-V2-063–070 | F-001 |
| F-012 | CAPK / key management (`--capk-extra`, profile CAPKs) | P1 | [SPEC-v2-oda-crypto.md](./SPEC-v2-oda-crypto.md) | MAN-V2-061–065 | AUTO-V2-071–075 | ODA phase |
| F-013 | fDDA / qVSDC contactless ODA path | P1 | [SPEC-v2-oda-crypto.md](./SPEC-v2-oda-crypto.md) | MAN-V2-066–070 | AUTO-V2-076–080 | Phase ODA |
| F-014 | Exception file stub (`--exception-file`) | P2 | [SPEC-v2-restrictions-risk.md](./SPEC-v2-restrictions-risk.md) | MAN-V2-071–073 | AUTO-V2-081–083 | Phase restrict |
| F-015 | Contactless kernel hints (TTQ, CTQ, kernel ID) | P1 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-074–078 | AUTO-V2-084–088 | F-002 |
| F-016 | APDU mock/replay (`--mock-apdu-file`) | P0 | [SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md) | MAN-V2-079–082 | AUTO-V2-089–095 | Iso7816 layer |
| F-017 | Golden session fixtures + regression suite | P0 | [SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md) | MAN-V2-083–085 | AUTO-V2-096–105 | F-016 |
| F-018 | PM3Easy 256 KB firmware CI validation job | P1 | [SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md) | MAN-V2-086 | AUTO-V2-106–108 | CI pipeline |
| F-019 | `emv sim` ↔ terminal session bridge | P1 | [SPEC-v2-integration.md](./SPEC-v2-integration.md) | MAN-V2-087–090 | AUTO-V2-109–112 | `emv sim`, F-005 |
| F-020 | Lua / script API for terminal | P2 | [SPEC-v2-integration.md](./SPEC-v2-integration.md) | MAN-V2-091–093 | AUTO-V2-113–115 | Lua bindings |
| F-021 | `emv reader` / terminal alignment mode | P2 | [SPEC-v2-integration.md](./SPEC-v2-integration.md) | MAN-V2-094–096 | AUTO-V2-116–118 | `emv reader` |
| F-022 | Smartcard contact path hardening | P2 | [SPEC-v2-integration.md](./SPEC-v2-integration.md) | MAN-V2-097–100 | AUTO-V2-119–121 | SMARTCARD mod |
| F-023 | TCP mock acquirer (`emv terminal host --listen`) | P1 | [SPEC-v2-host-online.md](./SPEC-v2-host-online.md) | MAN-V2-101–105 | AUTO-V2-122–128 | F-001 |
| F-024 | Kernel selection dispatcher (C-2 / C-3 simplified) | P1 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-106–110 | AUTO-V2-129–133 | F-002 |
| F-025 | MSD / PayPass legacy terminal path | P2 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-111–113 | AUTO-V2-134–136 | Phase CAA |
| F-026 | Terminal-side CDA / SDAD verification | P2 | [SPEC-v2-oda-crypto.md](./SPEC-v2-oda-crypto.md) | MAN-V2-114–116 | AUTO-V2-137–140 | Phase CAA |
| F-028 | Session redaction defaults (`--redact-crypto`) | P1 | [SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md) | MAN-V2-117–119 | AUTO-V2-141–144 | Session export |
| F-029 | PIN zeroization + APDU log audit | P1 | [SPEC-v2-cvm-pin.md](./SPEC-v2-cvm-pin.md) | MAN-V2-120–122 | AUTO-V2-145–148 | Phase CVM |
| F-030 | Legal / authorized-use banner | P2 | [SPEC-v2-cli-ux.md](./SPEC-v2-cli-ux.md) | MAN-V2-123 | AUTO-V2-149 | CLI |
| F-031 | APDU pcap / Wireshark export | P2 | [SPEC-v2-trace-replay.md](./SPEC-v2-trace-replay.md) | MAN-V2-124–125 | AUTO-V2-150–152 | `-a` logging |
| F-032 | Batch regression (`emv terminal test --golden`) | P1 | [SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md) | MAN-V2-126 | AUTO-V2-153–160 | F-017 |
| F-033 | Transaction replay lab (`emv terminal replay`) | P2 | [SPEC-v2-trace-replay.md](./SPEC-v2-trace-replay.md) | MAN-V2-127–130 | AUTO-V2-161–165 | F-016, F-005 |
| F-034 | Scheme test-card matrix + lab checklist | P2 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-131–135 | — | Docs only |
| F-035 | Phase timing report (`--timing-report`) | P3 | [SPEC-v2-trace-replay.md](./SPEC-v2-trace-replay.md) | MAN-V2-136 | AUTO-V2-166 | Phase engine |
| F-036 | Auto-detect scheme from AID (`--profile auto`) | P1 | [SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md) | MAN-V2-137–139 | AUTO-V2-167–169 | F-002 |
| F-037 | Multi-record issuer script template `86` chaining | P1 | [SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md) | MAN-V2-140–142 | AUTO-V2-170–172 | F-004 |
| F-038 | CDOL2 / online data host injection | P1 | [SPEC-v2-host-online.md](./SPEC-v2-host-online.md) | MAN-V2-143–145 | AUTO-V2-173–175 | F-001 |
| F-039 | `emv terminal capabilities` discovery command | P2 | [SPEC-v2-cli-ux.md](./SPEC-v2-cli-ux.md) | MAN-V2-146 | AUTO-V2-176 | Device mods |
| F-040 | Contactless Flash PIN skip matrix (Interac TC01–04) | P1 | [SPEC-v2-cvm-pin.md](./SPEC-v2-cvm-pin.md) | MAN-V2-147–150 | AUTO-V2-177–180 | F-002 |

---

## Recommended Implementation Waves

```text
Wave A (P0) — Real online + CI foundation
  F-001, F-011, F-016, F-017, F-002, F-032

Wave B (P1) — Scheme depth + operator UX
  F-003, F-007, F-008, F-009, F-010, F-012, F-013, F-015, F-023, F-024, F-028, F-029, F-036, F-038, F-040

Wave C (P1–P2) — Data + scripts + integration
  F-004, F-005, F-006, F-018, F-019, F-037

Wave D (P2) — Research + polish
  F-014, F-020, F-021, F-022, F-025, F-026, F-030, F-031, F-033, F-034, F-035, F-039
```

See [IMPLEMENTATION-PLAN-v2.md](./IMPLEMENTATION-PLAN-v2.md) for phased task breakdown and [MILESTONES-v2.md](./MILESTONES-v2.md) for delivery gates.

---

## Requirement ID Namespace

| Prefix | Domain |
|--------|--------|
| `REQ-HOST-*` | Host simulator, ARQC/ARPC, TCP acquirer |
| `REQ-SCH-*` | Scheme profiles, kernels, MSD |
| `REQ-CVM-*` | PIN, CVM advanced |
| `REQ-DAT-*` | Session, scan merge, redaction |
| `REQ-CLI-*` | CLI UX, overrides, banner |
| `REQ-ODA-*` | ODA, CAPK, CDA, fDDA |
| `REQ-RISK-*` | Exception file, TRM extensions |
| `REQ-TST-*` | Testing, mock, golden, CI |
| `REQ-INT-*` | Lua, sim bridge, reader, contact |
| `REQ-TRC-*` | Trace, pcap, replay, timing |

---

## Document Map (v2 bundle)

```text
docs/emv-terminal-emulator/
├── FEATURE-CATALOG-v2.md          ← you are here
├── IMPLEMENTATION-PLAN-v2.md
├── MILESTONES-v2.md
├── TEST-PLAN-v2-manual.md
├── TEST-PLAN-v2-automated.md
├── QA-CHECKLIST-v2.md
├── SPEC-v2-host-online.md
├── SPEC-v2-scheme-kernels.md
├── SPEC-v2-cvm-pin.md
├── SPEC-v2-scripts-data.md
├── SPEC-v2-cli-ux.md
├── SPEC-v2-oda-crypto.md
├── SPEC-v2-restrictions-risk.md
├── SPEC-v2-testing-ci.md
├── SPEC-v2-integration.md
└── SPEC-v2-trace-replay.md
```
