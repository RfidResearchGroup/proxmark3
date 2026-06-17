# Implementation Plan — EMV Terminal Emulator

## Assumptions

1. PM3Easy runs PM3GENERIC 512 KB firmware unless operator opts into 256 KB profile.
2. Terminal logic lives in the **client**; firmware unchanged for MVP.
3. Existing `CmdEMVExec` logic is the best starting point — refactor, don't rewrite from scratch.
4. ntufar/EMV provides **phase architecture reference**; implementation stays C, matching Iceman style.
5. Test cards available for Visa qVSDC and at least one offline-PIN card.
6. No live acquirer integration in v1.

## Repo / Project Structure (target)

```text
client/src/emv/
├── terminal/                    # NEW
│   ├── emv_term_ctx.c/h
│   ├── emv_terminal.c/h         # orchestrator
│   ├── phase_init.c
│   ├── phase_oda.c
│   ├── phase_restrict.c
│   ├── phase_cvm.c              # PIN VERIFY
│   ├── phase_trm.c
│   ├── phase_taa.c
│   ├── phase_caa.c
│   ├── phase_online.c
│   ├── phase_complete.c
│   └── emv_term_session.c       # JSON export
├── cmdemv.c                     # add terminal subcommands
├── emvcore.c                    # shared helpers extracted from exec
└── ...

client/resources/
├── emv_defparams.json           # existing
└── emv_terminal_profile.json  # NEW

client/src/emv/test/
├── terminal_phase_test.c        # NEW
└── pin_verify_test.c            # NEW

docs/emv-terminal-emulator/      # this bundle

armsrc/
└── emvterm.c                    # OPTIONAL later
```

## Phase 0: Project Skeleton

**Goal:** Buildable scaffolding, no behavior change.

**Tasks:**

- Create `client/src/emv/terminal/` with empty phase stubs returning `PM3_ENOTIMPL`
- Add `emv terminal run --help` to command table
- Add `emv_terminal_profile.json` with TAC/CVM defaults
- Wire `client/Makefile` sources
- Add `docs/emv-terminal-emulator/` link in root README

**Completion criteria:**

- Client compiles on Linux CI
- `emv terminal run` prints "not yet implemented" or delegates to exec stub

**Files:** `cmdemv.c`, `Makefile`, `emv_terminal.c`, profile JSON

## Phase 1: Core Data Model + Refactor Exec

**Goal:** Shared session context; extract exec loop into callable API.

**Tasks:**

- Implement `emv_term_ctx_t` init/free
- Extract `emv_transaction_init()` from `CmdEMVExec` body (~lines 1484–1700 in `cmdemv.c`)
- Extract `emv_transaction_genac1()` from exec
- Implement session JSON export (minimal: phases + outcome)
- `emv terminal run` calls extracted API — **same behavior as `emv exec`** initially

**Dependencies:** Phase 0

**Completion criteria:**

- AC-API-001, AC-DATA-002 for minimal session
- `emv exec` and `emv terminal run` produce equivalent APDU sequences (AUTO-CORE-010)

## Phase 2: Phase Engine + Explicit Outcomes

**Goal:** Named phases with trace; clear terminal outcome enum.

**Tasks:**

- Implement phase orchestrator loop in `emv_terminal.c`
- Implement `phase_init`, `phase_oda` wrapping existing functions
- Add `--trace-phases` logging
- Map GEN AC result to `approved_offline` / `online_required` / `declined`
- Implement `emv terminal step init|oda`

**Dependencies:** Phase 1

**Completion criteria:**

- AC-CORE-001 on qVSDC test card
- Phase trace ≥ 7 events in session JSON

## Phase 3: PIN / Cardholder Verification

**Goal:** Minimum user request — PIN verification.

**Tasks:**

- Implement CVM list parser in `phase_cvm.c`
- Implement VERIFY APDU builder (plain PIN format 2)
- Implement enciphered PIN using ICC PIN key + RSA (mbedtls)
- CLI: `--pin`, `emv terminal pin`, interactive prompt
- Update TVR (95) and CVM Results (9F34)
- Security: PIN zeroization, log redaction

**Reference:** ntufar/EMV `CardholderVerification.*`; lumag/emv-tools VERIFY patterns

**Dependencies:** Phase 2

**Completion criteria:**

- AC-CORE-002, AC-CORE-003, AC-SEC-001

## Phase 4: Restrictions + TRM + TAA

**Goal:** Terminal decisions beyond first GEN AC.

**Tasks:**

- `phase_restrict.c` — date/AUC/version checks
- `phase_trm.c` — floor limit, random selection from profile
- `phase_taa.c` — TAC/IAC tables from profile; request AAC/ARQC/TC
- Integrate CDOL1 build already in `dol.c`

**Dependencies:** Phase 3

**Completion criteria:**

- AC-CORE-004 ODA fail → AAC decline path
- Floor limit exceeded sets TVR and influences TAA

## Phase 5: CAA + AC2 + External Auth

**Goal:** Complete offline terminal path.

**Tasks:**

- Expand `phase_caa.c` — parse CID, handle ARQC vs TC mismatch
- CDOL2 second GEN AC when required
- External authenticate command for test cards (optional path)
- `emv terminal step caa`

**Dependencies:** Phase 4

**Completion criteria:**

- AC-CORE-001 with second GEN AC on applicable test card
- Matches ntufar phase sequence through Card Action Analysis

## Phase 6: Online Lab Stub

**Goal:** Close the loop after ARQC for test cards with ARPC.

**Tasks:**

- `phase_online.c` — manual ARPC entry, `--arpc` flag
- Issuer script 71/72 transmit
- `emv terminal online` command

**Dependencies:** Phase 5

**Completion criteria:**

- Test card with known ARPC completes to `approved_online` in lab

## Phase 7: PM3Easy Hardening + QA

**Goal:** Release-quality docs and CI for PM3GENERIC.

**Tasks:**

- 256 KB flash size validation script
- Extend `tools/pm3_tests.sh` with terminal tests (mock APDU mode)
- Update `doc/emv_notes.md` with terminal section
- Complete QA checklist

**Dependencies:** Phase 5 minimum; Phase 6 optional

**Completion criteria:**

- QA-CHECKLIST.md all MVP items checked
- MAN-CORE-* pass on PM3Easy hardware

## Phase 8: Packaging / Deployment

**Goal:** Operator-ready defaults for PM3Easy.

**Tasks:**

- Ship example profile: copy `docs/emv-terminal-emulator/examples/emv_terminal_profile.json` to `client/resources/` (alongside `emv_defparams.json`)
- Document `Makefile.platform` example for PM3Easy in `doc/md/Use_of_Proxmark/`
- Optional: Lua script wrapper for automated regression

**Completion criteria:**

- New PM3Easy user follows README quick start successfully

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | C only in client | Match existing emv module |
| ntufar/EMV | Port phases, not code | C++, different runtime |
| Firmware | Client-only MVP | Flash budget |
| Kernel model | Single orchestrator + scheme tweaks | Full L2 kernels too heavy for PM3 |
| Backward compat | Keep `emv exec` | Existing scripts/users |

## Migration / Refactor Notes

- Move shared code from `CmdEMVExec` and `CmdEMVScan` incrementally; avoid big-bang delete
- Add `--terminal` to exec only if needed for deprecation path — prefer separate command group

## What to Stub First

1. `phase_online.c` — return `PM3_ENOTIMPL` until Phase 6
2. Exception file — always pass
3. Online PIN — TVR bit only

## What Not to Build Yet

- EMVCo certified kernel
- Live ISO8583 host
- Firmware terminal crypto
- GUI integration
- American Express / JCB scheme-specific kernels until Visa/MC stable

## Deferred Work

See [MILESTONES.md](./MILESTONES.md) Milestone 6+ and [OPEN-QUESTIONS.md](./OPEN-QUESTIONS.md).

## ntufar/EMV Mapping

| ntufar module | PM3 module |
|---------------|------------|
| `ApplicationInitialization` | `phase_init.c` |
| `OfflineDataAuthentication` | `phase_oda.c` + `emvcore.c` |
| `ProcessingRestrictions` | `phase_restrict.c` |
| `CardholderVerification` | `phase_cvm.c` |
| `TerminalRiskManagement` | `phase_trm.c` |
| `TerminalActionAnalysis` | `phase_taa.c` |
| `CardActionAnalysis` | `phase_caa.c` |
| `OnLineProcessing` | `phase_online.c` |
| `Completion` | `phase_complete.c` |
| `EMV_Context` | `emv_term_ctx_t` |
| `SCRControl` | `iso7816core.c` |
| `UIControl` | CLI prompt / cliparser |
| `CryptoControl` | `crypto.c`, `emv_pki.c` |
