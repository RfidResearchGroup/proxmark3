# Product Overview — EMV Terminal Emulator for PM3Easy

## Plain-English Product Definition

The EMV Terminal Emulator turns a Proxmark3 (PM3Easy / PM3GENERIC) into a **software-defined payment terminal** for laboratory and research use. When a contactless EMV card is presented to the PM3 antenna, the client runs the terminal-side EMV transaction: application selection, data authentication, cardholder verification, risk checks, and cryptogram generation — the same steps a POS terminal performs before sending an authorization request to a bank.

This is **not** a certified payment terminal and must not be used to process real consumer payments.

## Target Users

| User | Need |
|------|------|
| PM3Easy owner | Run EMV terminal flows on hardware they already have |
| RFID/EMV researcher | Observe and script full transaction phases with trace logs |
| Firmware/client contributor | Clear specs to extend `client/src/emv/` without breaking flash budgets |
| Test lab operator | Repeatable sessions against EMVCo / scheme test cards |

## Problem Statement

Proxmark3 Iceman already implements **card-side** EMV operations well (`emv scan`, `emv exec`, ODA, partial qVSDC). Gaps documented in [doc/emv_notes.md](../../doc/emv_notes.md) block a credible terminal emulator:

- PIN verification not implemented
- External authenticate, AC2, ARQC/ARPC, issuer scripts not implemented
- No unified terminal session with phase outcomes
- Firmware `emvsim.c` targets relay/card emulation, not terminal logic

Researchers currently stitch together manual commands or external tools (e.g. ntufar/EMV on PC with a different reader). This project integrates terminal behavior into the PM3 workflow.

## Non-Goals

- PCI PTS certification or deployment as a live merchant terminal
- Processing real bank cards for actual charges
- EMVCo L2 kernel certification
- Replacing `emv sim` / `HF_EMVPNG` card emulation modes
- Running full C++ ntufar/EMV inside ARM firmware
- Supporting Proxmark3 Ultimate / iCopy-X in v1 (PM3GENERIC + PM3Easy first)

## Success Criteria

| ID | Criterion |
|----|-----------|
| SC-01 | Operator completes contactless terminal flow on PM3Easy: select → GPO → read records → ODA → GEN AC1 with structured result |
| SC-02 | Offline PIN VERIFY succeeds on supported test card; TVR/CVMR reflect outcome |
| SC-03 | Terminal session exports JSON trace mappable to requirements REQ-CORE-* |
| SC-04 | PM3GENERIC fullimage builds without exceeding 512 KB; 256 KB profile documented with `SKIP_*` if needed |
| SC-05 | Automated crypto/phase tests pass in CI (`emv test` extended) |
| SC-06 | Documentation enables a new contributor to implement Phase 2 without re-architecting |

## Operating Assumptions

- Users possess **authorized test cards** or their own cards in a private lab
- PM3Easy runs PM3GENERIC firmware over USB from a host running the Iceman client
- Terminal logic runs on the **host client**; firmware provides HF 14a and optional smartcard I/O
- Test keys (CA / issuer) come from public EMV test packs or card personalization docs
- Online authorization uses a **stub host** or manual ARPC entry, not a production acquirer

## What Makes This Different From a Simple Demo

| Simple demo | This product |
|-------------|--------------|
| Single `emv exec` one-shot | Stateful session with explicit phases, resumability, audit trace |
| Skip PIN / CVM | Implements CVM list processing with VERIFY and enciphered PIN |
| Partial GEN AC only | TAA-driven AC type, CDOL1/CDOL2, AC2 where card requires |
| Card dump only | Terminal decisions (approve / decline / online) with TVR/TAC logic |
| RDV4-only standalone | PM3Easy-first, client-heavy, flash-aware |

## Staged Version Scope

### v0.1 — Terminal MVP (Milestone 2)

- `emv terminal run` command
- Reuses `EMVSearch`, `EMVSelect`, `EMVGPO`, `EMVReadRecord`, `trDDA`/`trSDA`, first `EMVAC`
- Session JSON export
- Contactless only

### v0.2 — Cardholder Verification (Milestone 3)

- Offline PIN VERIFY (plain)
- Enciphered PIN to ICC (when ICC PIN key present)
- CVM list walker, CVM Results (9F34), TVR updates (95)

### v0.3 — Full Offline Terminal (Milestone 4)

- Processing restrictions, floor limit, random selection
- TAC/IAC-driven Terminal Action Analysis
- AC2 / second GEN AC
- External authenticate hook (test cards)

### v0.4 — Online Lab Path (Milestone 5)

- ARQC display, manual or scripted ARPC injection
- Issuer script transmit (71/72) for test cards
- Optional `emv terminal host` mock

### v1.0 — PM3Easy Production Profile (Milestone 6)

- 256 KB firmware validation
- Operator docs, QA checklist green
- Visa qVSDC + Mastercard M/Chip contactless happy paths on reference test cards

## Reference Material

- Existing PM3 EMV: `client/src/emv/`, [doc/emv_notes.md](../../doc/emv_notes.md)
- Phase model reference: [ntufar/EMV](https://github.com/ntufar/EMV) (`EMV_Library/`, `docs/architecture.md`)
- EMVCo Book 3 Application Specification (transaction processing)
