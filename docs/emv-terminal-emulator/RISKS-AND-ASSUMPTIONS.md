# Risks and Assumptions

## Assumptions

| ID | Assumption | If wrong |
|----|------------|----------|
| A-01 | PM3Easy has 512 KB flash | Need aggressive SKIP_* or drop standalone |
| A-02 | Client-only terminal meets timing for contactless | Need firmware WTX assist |
| A-03 | Test cards cover qVSDC + offline PIN | Manual testing blocked |
| A-04 | Existing emvcore ODA is sufficient for terminal | Extra crypto work in phase_oda |
| A-05 | Operators use lab cards only | Legal/reputation risk — document clearly |
| A-06 | ntufar/EMV phase model maps cleanly to C | Some C++ patterns need simplification |

## Risk: Refactoring `CmdEMVExec` breaks existing workflows

**Category:** Technical  
**Likelihood:** Medium  
**Impact:** High  
**Description:** Extracting shared code from monolithic exec/scan may introduce regressions for `emv exec`, `emv scan`, Lua scripts.  
**Mitigation:** Incremental extract; AUTO-CORE-010 parity test; keep exec as thin wrapper.  
**Detection:** CI `pm3_tests.sh`, manual MAN-CORE-005.

## Risk: PM3Easy 256 KB firmware too small for default image

**Category:** Technical  
**Likelihood:** Medium  
**Impact:** Medium  
**Description:** Growing armsrc may exceed 262144 bytes on 256 KB Easy units.  
**Mitigation:** Terminal stays client-side; document SKIP profile; MAN-DEVICE-001.  
**Detection:** `PLATFORM_SIZE=256` build in CI.

## Risk: Enciphered PIN implementation complexity

**Category:** Technical  
**Likelihood:** High  
**Impact:** Medium  
**Description:** ICC PIN key recovery and RSA formatting errors cause false CVM failures.  
**Mitigation:** Deliver plain PIN first (M3); enciphered in M3 stretch; use lumag/emv-tools reference.  
**Detection:** AUTO-CORE-031, test cards with known keys.

## Risk: Scheme-specific behavior differences (Visa vs MC)

**Category:** Product  
**Likelihood:** High  
**Impact:** Medium  
**Description:** Single TAA profile may fail on one scheme's test cards.  
**Mitigation:** Per-AID profiles in JSON; document scheme-specific TTQ/TAC defaults.  
**Detection:** Manual tests on both scheme cards.

## Risk: Misuse for fraudulent transactions

**Category:** Security / Legal  
**Likelihood:** Low  
**Impact:** High  
**Description:** Tool could be misused outside lab context.  
**Mitigation:** Clear docs; no live host integration; masked exports; educational framing.  
**Detection:** N/A — policy and communication.

## Risk: ntufar/EMV license incompatibility

**Category:** Dependency  
**Likelihood:** Low  
**Impact:** Medium  
**Description:** Direct code copy may have license issues; repo appears mixed/proprietary hints.  
**Mitigation:** **Port architecture only**, do not copy C++ source; use EMVCo spec + existing PM3 emv code.  
**Detection:** Legal review before any ntufar code paste.

## Risk: Contactless timing / WTX failures

**Category:** Operational  
**Likelihood:** Medium  
**Impact:** Medium  
**Description:** Slow cards timeout during multi-record AFL read.  
**Mitigation:** `--retry`; optional `emvterm.c` WTX assist; operator card positioning docs.  
**Detection:** MAN-DEVICE-002, field reports.

## Risk: Missing CA public keys

**Category:** Operational  
**Likelihood:** Medium  
**Impact:** Low  
**Description:** ODA fails on cards signed by unknown CAs.  
**Mitigation:** `--no-oda-required` for lab; expand CA key pack in resources.  
**Detection:** ODA phase logs, MAN-CORE-004.

## Risk: SMARTCARD mod confusion

**Category:** User  
**Likelihood:** Medium  
**Impact:** Low  
**Description:** Users expect contact EMV on stock PM3Easy without mod.  
**Mitigation:** Clear `-w` capability check and SPEC-device messaging.  
**Detection:** MAN-DEVICE-004.

## Risk: Scope creep toward full EMVCo kernel

**Category:** Product  
**Likelihood:** High  
**Impact:** High  
**Description:** "Full terminal emulator" could imply certified kernel — unbounded effort.  
**Mitigation:** Staged milestones; explicit non-goals; v1 = Book 3 phase orchestration not L2 kernel.  
**Detection:** Milestone reviews against OPEN-QUESTIONS.

## Risk: Documentation drift from implementation

**Category:** Operational  
**Likelihood:** Medium  
**Impact:** Low  
**Description:** Specs written before code may diverge.  
**Mitigation:** Update CHANGELOG and specs each milestone; REQ-IDs in code comments.  
**Detection:** QA documentation checklist.
