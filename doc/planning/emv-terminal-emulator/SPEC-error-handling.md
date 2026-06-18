# SPEC: Error Handling

## Purpose

Classify failures, recovery actions, and operator-visible messages across terminal phases.

## Scope

Client terminal engine and transport errors

## Non-Goals

Acquirer host protocol error catalog (v0.4 stub only)

## Error Categories

| Code prefix | Category | Example |
|-------------|----------|---------|
| `EMV_E_IO` | Transport | USB timeout, card removed |
| `EMV_E_SW` | Card SW | 6985, 6984, 63C0 |
| `EMV_E_TLV` | Parse | Missing 9F38, bad AFL |
| `EMV_E_ODA` | Authentication | DDA verify fail |
| `EMV_E_CVM` | Cardholder verify | PIN blocked |
| `EMV_E_POLICY` | Terminal policy | ODA required but failed |
| `EMV_E_PROFILE` | Config | Invalid JSON profile |

## Functional Requirements

REQ-ERR-001: Every phase shall return `int` status; non-success propagates to session `Outcome=aborted` unless phase policy allows continue.

REQ-ERR-002: SW errors shall include human string from `GetAPDUCodeDescription`.

REQ-ERR-003: Partial session shall save on abort when `-o` specified.

REQ-ERR-004: Field shall drop on fatal abort (`DropFieldEx`).

REQ-ERR-005: Retryable errors (transient RF) may retry once per APDU when `--retry` set.

REQ-ERR-006: ODA failure: if `--no-oda-required`, set TVR and continue; else if TAC denies, proceed to decline path not abort.

REQ-ERR-007: CVM failure: walk CVM list; abort only when no remaining applicable CVM and decline required.

## Common SW Handling

| SW | Phase | Action |
|----|-------|--------|
| 9000 | any | Success |
| 6985 | GPO | Abort — wrong PDOL / conditions |
| 6984 | SELECT | Try next AID |
| 6283 | SELECT | Application blocked — log, try next |
| 63Cx | VERIFY | Record tries, next CVM or fail |
| 6983 | VERIFY | PIN blocked — CVM failure |

## Operator Messages (examples)

Good:

```text
[!] ODA: fDDA failed — ICC certificate expired (5F24)
[+] Hint: retry with --no-oda-required for lab continue, or update CA key pack
```

Bad:

```text
Error in crypto
```

## Acceptance Criteria

AC-ERR-001: GPO SW 6985 produces message referencing PDOL / 9F38.

AC-ERR-002: USB disconnect mid-session saves partial JSON when `-o` set.

## Test Coverage Notes

AUTO-ERR-001: SW mapping table tests  
MAN-ERR-001: Card removed during READ RECORD

## Open Questions

None.
