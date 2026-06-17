# SPEC v2: Testing, Mock APDU, Golden Fixtures, CI, Parity

## Scope

Features **F-009**, **F-016**, **F-017**, **F-018**, **F-032**

---

## APDU Mock / Replay — REQ-TST-001–019

### REQ-TST-001

Flag `--mock-apdu-file <path>` on `emv terminal run|step|replay`.

### REQ-TST-002

Trace format v1 (JSON array):

```json
{
  "version": 1,
  "channel": "contactless",
  "aid": "A0000002771010",
  "steps": [
    { "name": "SELECT", "capdu": "00A40400...", "rapdu": "6F2A...", "sw": "9000" },
    { "name": "GPO", "capdu": "80A80000...", "rapdu": "7781...", "sw": "9000" }
  ]
}
```

### REQ-TST-003

Mock layer hooks `Iso7816ExchangeEx` (or EMV wrapper) to match CAPDU prefix and return RAPDU; unmatched → `PM3_ERFTRANS`.

### REQ-TST-004

Optional `--mock-strict` fails on extra unexpected APDUs.

### REQ-TST-005

Record mode: `--record-apdu-file out.json` on live run captures trace for fixture generation.

---

## Golden Session Fixtures — REQ-TST-020–034

### REQ-TST-020

Directory layout:

```text
client/src/emv/test/fixtures/
├── README.md
├── interac_tc01_arqc/
│   ├── mock_apdu.json
│   ├── terminal_profile.json
│   ├── session_expected.json
│   └── README.md
├── visa_qvsdc_tc/
└── taa_denial_expired/
    └── card_tlv.json          # load-only, no APDU
```

### REQ-TST-021

Each fixture README documents: source card, date captured, expected outcome, anonymization steps.

### REQ-TST-022

`session_expected.json` fields compared: `Outcome`, `Phases[].name`, `Phases[].result`, `Cryptogram.Type` (not full AC if redacted).

### REQ-TST-023

Synthetic fixtures allowed for TAA/CVM-only tests (no real PAN).

---

## Batch Regression — REQ-TST-030–039

### REQ-TST-030

`emv terminal test [--golden] [--fixture <name>]` runs all or one fixture.

### REQ-TST-031

Exit code 0 iff all pass; print summary `Golden: 12/12 OK`.

### REQ-TST-032

Integrate into `emv test --terminal` and `tools/pm3_tests.sh`.

### REQ-TST-033

Host-only tests run without PM3 USB connected.

---

## APDU Parity Compare — REQ-TST-040–049

### REQ-TST-040

`emv terminal compare --exec <trace.json> --terminal <trace.json>` diffs CAPDU sequences.

### REQ-TST-041

Ignore whitespace; optional ignore SELECT if `--ignore-select`.

### REQ-TST-042

Output unified diff format; exit 1 on mismatch.

### REQ-TST-043

Generate exec trace: `emv exec -sat --qvsdc --record-apdu exec.json` (implement record on exec too for parity).

### REQ-TST-044

MAN-CORE-005 parity: through GEN AC1, sequences match for same card/profile.

---

## PM3Easy 256 KB CI — REQ-TST-050–054

### REQ-TST-050

CI job `firmware-size-pm3easy`:

```bash
make -C arms clean && PLATFORM=PM3GENERIC PLATFORM_SIZE=256 make -C arms
# Assert arms/*.elf < 262144 bytes (or documented limit)
```

### REQ-TST-051

Document result in QA checklist; terminal remains client-side — job validates no firmware bloat from related arms changes.

### REQ-TST-052

Optional: `PM3EASY=1` client build smoke.

---

## Unit Test File Map

| File | Covers |
|------|--------|
| `terminal_host_test.c` | ARQC/ARPC vectors |
| `terminal_mock_apdu_test.c` | Mock matcher |
| `terminal_golden_test.c` | Fixture runner |
| `terminal_taa_test.c` | Existing TAA |
| `pin_verify_test.c` | PIN block |

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-TST-001 | interac_tc01 fixture | `test --golden` | Pass |
| AC-TST-002 | Modified outcome | test | Fail with diff |
| AC-TST-003 | mock_apdu.json | `run --mock` | No USB |
| AC-TST-004 | exec + terminal traces | compare | Match |
| AC-TST-005 | CI job | push | Size report artifact |

---

## CI Integration Snippet

```bash
# tools/pm3_tests.sh (addition)
if ! CheckExecute "emv terminal golden" \
    "$CLIENTBIN -c 'emv terminal test --golden'" "Golden:.*OK"; then break; fi
if ! CheckExecute "emv terminal profile interac" \
    "$CLIENTBIN -c 'emv terminal profile validate client/resources/scheme_profiles/interac.json'" \
    "Profile valid"; then break; fi
```
