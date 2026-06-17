# SPEC: Core Loop — EMV Terminal Transaction Phases

## Purpose

Define the terminal-side EMV transaction loop the PM3 client shall execute when acting as a payment terminal toward a presented EMV card.

## Scope

- Contactless (ISO14443-4) on PM3Easy — **primary**
- Contact (ISO7816 via smartcard slot) — **secondary**, requires SMARTCARD mod
- Visa MSD, qVSDC; Mastercard M/Chip contactless — **v1 target schemes**
- Phases from Application Initialization through first/second Generate AC
- Integration with existing `emvcore.c` functions

## Non-Goals

- Kernel-specific entry point (EP) full EMVCo L2 stack in v1
- MSD magnetic-stripe-only mode as terminal (legacy; low priority)
- Production host authorization (ISO8583 to live acquirer)
- Card emulation (`emv sim`, `emvsim.c`)

## User / Actor Stories

| Actor | Story |
|-------|-------|
| Lab operator | Run one command to execute a full terminal transaction and get approve/decline/online outcome |
| Developer | Step through phases individually to debug ODA or CVM on a test card |
| Researcher | Export phase trace JSON comparable to ntufar/EMV phase boundaries |
| Maintainer | Map each phase to EMV Book 3 section for compliance discussions |

## Functional Requirements

### Application Initialization

REQ-CORE-001: The terminal shall activate the RF field (contactless) or reset the smartcard interface (contact) before application selection.

REQ-CORE-002: The terminal shall attempt PPSE selection (`2PAY.SYS.DDF01`) on contactless; on failure it shall fall back to AID list search per `EMVSearch` behavior.

REQ-CORE-003: The terminal shall select a payment application (AID) and store FCI template data in the session card TLV tree.

REQ-CORE-004: The terminal shall build PDOL from terminal parameters and card PDOL tag (9F38), then execute GET PROCESSING OPTIONS.

REQ-CORE-005: The terminal shall read all AFL entries (SFI/record) and merge record TLVs into the card tree.

### Offline Data Authentication

REQ-CORE-010: The terminal shall determine ODA method from AIP (82) and perform SDA when indicated, using existing `trSDA`.

REQ-CORE-011: The terminal shall perform DDA or fDDA when indicated, using `EMVGenerateChallenge`, `EMVInternalAuthenticate`, and `trDDA`.

REQ-CORE-012: The terminal shall perform CDA verification path when transaction type CDA is selected and card supports it, using `trCDA`.

REQ-CORE-013: The terminal shall record ODA result in session context and set TVR bits per EMV rules when ODA fails.

### Processing Restrictions

REQ-CORE-020: The terminal shall verify application effective and expiration dates against transaction date (9A).

REQ-CORE-021: The terminal shall check application usage control (9F07) against terminal type and transaction type (9C).

REQ-CORE-022: The terminal shall compare application version number (card 9F08) to terminal version (9F09) and set TVR if incompatible.

### Cardholder Verification

REQ-CORE-030: The terminal shall parse CVM list (8E) and select the next applicable CVM rule for the transaction amount and terminal capabilities.

REQ-CORE-031: The terminal shall execute VERIFY (00 20) for offline plaintext PIN when CVM rule requires it.

REQ-CORE-032: The terminal shall build enciphered PIN block using ICC PIN encipherment public key (9F2D/9F2E/9F2F) when CVM rule requires enciphered offline PIN.

REQ-CORE-033: The terminal shall update CVM Results (9F34) and TVR PIN-related bits after each CVM attempt.

REQ-CORE-034: The terminal shall support operator PIN entry via CLI prompt or `--pin` argument for non-interactive tests.

REQ-CORE-035: Online PIN shall be marked as "simulated" in v0.2 — set TVR bit and include placeholder PIN block in CDOL; full HSM path deferred.

### Terminal Risk Management

REQ-CORE-040: The terminal shall compare amount authorized (9F02) to terminal floor limit (9F1B) and set TVR if exceeded.

REQ-CORE-041: The terminal shall implement random transaction selection per EMV Book 3 when configured in terminal profile.

REQ-CORE-042: Exception file checking shall be stubbed (always pass) unless operator supplies `--exception-file` path in v0.3.

### Terminal Action Analysis

REQ-CORE-050: The terminal shall combine TVR, TAC/IAC (issuer/card action codes), and AIP to determine requested cryptogram type: AAC, ARQC, or TC.

REQ-CORE-051: The terminal shall build CDOL1 related data from terminal and card TLV sources using existing `dol.c`.

REQ-CORE-052: The terminal shall send GENERATE AC with P1 referencing requested cryptogram type.

### Card Action Analysis

REQ-CORE-060: The terminal shall parse GENERATE AC response: CID, ATC, AC, IAD, SDAD (if CDA).

REQ-CORE-061: When card returns ARQC and terminal requested TC, the terminal shall apply second GEN AC flow (CDOL2) if CDOL2 (8D) present — v0.3.

REQ-CORE-062: The terminal shall map final cryptogram type to session outcome: `approved_offline`, `declined`, `online_required`.

### Completion

REQ-CORE-070: The terminal shall produce a human-readable summary: AID, PAN (masked), amount, cryptogram type, SW codes, phase errors.

REQ-CORE-071: The terminal shall write session trace JSON when `-o` path provided.

REQ-CORE-072: The terminal shall drop the RF field on completion or fatal error.

## State and Data

See [SPEC-data-model.md](./SPEC-data-model.md) for `emv_term_ctx_t` fields.

Phase-local inputs/outputs:

| Phase | Reads | Writes |
|-------|-------|--------|
| Init | terminal PDOL, card AID | AFL, AIP, records |
| ODA | AIP, CA keys, records | ODA status, ICC key recovered |
| Restrict | 5F24, 5F25, 9F07, 9A | TVR restriction bits |
| CVM | 8E, 9F33, amount | 9F34, TVR CVM bits |
| TRM | 9F02, 9F1B, profile | TVR risk bits |
| TAA | TVR, TAC*, IAC* | requested AC type, CDOL1 |
| CAA | CDOL1 | AC, ATC, CID, decision |

## Main Flows

### Flow A — Happy path offline approve (TC)

1. Init → ODA pass → Restrict pass → CVM pass or not required → TRM pass → TAA requests TC → GEN AC returns TC → outcome `approved_offline`.

### Flow B — Online required (ARQC)

1. Same through TAA → ARQC returned → outcome `online_required` → optional online phase (v0.4).

### Flow C — Decline (AAC)

1. ODA fail + TAC denies → TAA requests AAC → GEN AC returns AAC → outcome `declined`.

## Edge Cases

- Card returns SW 6985 (conditions not satisfied) on GPO → abort with clear message; common on wrong PDOL
- Empty CVM list → skip CVM, set CVMR per EMV default
- PIN try counter 63Cx → record tries remaining; stop CVM list if blocked
- qVSDC fDDA only path — skip full DDA challenge if TTQ and card indicate fDDA
- Multi-AID: operator `--aid` forces selection; else highest priority from PPSE

## Failure Handling

- **Hard fail:** USB error, card timeout, malformed AFL → stop session, save partial trace
- **Soft fail:** ODA optional per terminal `--oda-required false` → continue with TVR bit set
- **CVM fail:** try next CVM in list if rules allow; else decline path

## Security / Privacy Notes

- PIN entry must not echo to log; use existing client secure prompt pattern
- Mask PAN in summary (first 6 / last 4 only)
- Session JSON excludes PIN block and full track 2 by default (`--include-sensitive` disabled)

## Acceptance Criteria

AC-CORE-001: Given a qVSDC test card and default profile, when `emv terminal run -j` executes, then session reaches GEN AC and records ARQC or TC with phase trace ≥ 7 entries.

AC-CORE-002: Given a card requiring offline PIN and correct PIN entered, when VERIFY executes, then SW=9000 and CVMR indicates successful offline PIN.

AC-CORE-003: Given wrong offline PIN, when VERIFY returns 63Cx, then session records failed CVM and continues or declines per CVM list.

AC-CORE-004: Given ODA failure and TAC denial configured, when TAA runs, then requested cryptogram is AAC and outcome is `declined`.

AC-CORE-005: Given `-w wired` on device without SMARTCARD, when terminal run starts, then command exits with `PM3_EDEVNOTSUPP` before field activation.

## Test Coverage Notes

- Manual: MAN-CORE-001 through MAN-CORE-020
- Automated: AUTO-CORE-001 through AUTO-CORE-040 (phase unit tests with APDU fixtures)

## Open Questions

See OQ-003 (kernel selection), OQ-005 (CDA default on PM3Easy) in [OPEN-QUESTIONS.md](./OPEN-QUESTIONS.md).
