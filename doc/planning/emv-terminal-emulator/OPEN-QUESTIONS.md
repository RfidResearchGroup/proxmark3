# Open Questions

| ID | Question | Area | Impact | Needed By | Status |
|----|----------|------|--------|-----------|--------|
| OQ-001 | Allocate `CMD_HF_EMV_TERMINAL_ASSIST` (0x0387?) in `pm3_cmd.h`? | Firmware | Low | If WTX needed | Open — defer F-027 |
| OQ-002 | Merge terminal session JSON with `emv scan` format or keep separate? | Data | Medium | v2 | **Resolved** — separate + `session merge` ([SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md)) |
| OQ-003 | Kernel selection (C-2/C-3) vs AID profiles? | Architecture | High | v2 | **Resolved** — dispatcher + profiles ([SPEC-v2-scheme-kernels.md](./SPEC-v2-scheme-kernels.md)) |
| OQ-004 | Redact ARQC/IAD in session traces by default? | Security | Medium | v2 | **Resolved** — default redact ([SPEC-v2-scripts-data.md](./SPEC-v2-scripts-data.md)) |
| OQ-005 | Default transaction type: MSD, qVSDC, or profile-driven? | Product | Medium | v2 | **Resolved** — profile-driven, default qVSDC in visa profile |
| OQ-006 | Standalone mode `HF_EMVTERM`? | Firmware | Low | Post v2 | Open — defer |
| OQ-007 | lumag/emv-tools PIN snippets vs clean-room? | Implementation | Medium | M10 | Open — evaluate license at implementation |
| OQ-008 | Amex/JCB in v2? | Scope | Medium | v2.2+ | Open — Visa+MC+Interac first |
| OQ-009 | Interactive PIN on Windows no-echo? | UX | Medium | M10 | Open — test per platform at implementation |
| OQ-010 | `--mock-apdu-file` for CI? | Testing | Low | v2 | **Resolved** ([SPEC-v2-testing-ci.md](./SPEC-v2-testing-ci.md)) |
| OQ-011 | Auto-detect profile from AID? | UX | Medium | v2 | **Resolved** — `--profile auto` + explicit |
| OQ-012 | capk.txt merge vs `--capk-extra`? | Data | Low | v2 | **Resolved** — both ([SPEC-v2-oda-crypto.md](./SPEC-v2-oda-crypto.md)) |
| OQ-013 | Full ARPC compute vs manual `--arpc`? | Crypto | High | v2 | **Resolved** — host-sim + manual override |

## Decision Log

| ID | Decision | Date | Notes |
|----|----------|------|-------|
| — | Client-heavy architecture for PM3Easy | 2026-06-16 | ARCHITECTURE.md |
| — | ntufar/EMV: architecture port only | 2026-06-16 | No C++ import |
| — | v2 feature catalog + specs + test plans | 2026-06-16 | FEATURE-CATALOG-v2.md |
| — | Firmware WTX deferred until measured need | 2026-06-16 | F-027 excluded from v2 |
| OQ-002 | Session merge command, not single format | 2026-06-16 | REQ-DAT-020 |
| OQ-003 | Simplified kernel enum + JSON profiles | 2026-06-16 | Not full EMVCo Entry Point |
| OQ-013 | host-sim primary; XOR stub deprecated | 2026-06-16 | SPEC-v2-host-online |
