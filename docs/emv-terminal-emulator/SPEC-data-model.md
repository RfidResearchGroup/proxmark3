# SPEC: Data Model

## Purpose

Define persistent and in-memory data structures for the EMV terminal emulator: session context, JSON schemas, and TLV ownership rules.

## Scope

- Client-side structures only (firmware uses existing command payloads)
- Compatibility with existing `emv scan` JSON where possible
- Terminal profile and session export formats

## Non-Goals

- Database or cloud sync
- EMV certificate provisioning system
- Full EMVCo data dictionary duplicate (reference `emv_tags.c`)

## User / Actor Stories

| Actor | Story |
|-------|-------|
| Operator | Load terminal country/currency/limits from JSON file |
| Developer | Inspect session JSON after a run to see each phase I/O |
| Tester | Feed recorded APDU fixtures into phase tests |

## Functional Requirements

### Session Context

REQ-DATA-001: The system shall define `emv_term_ctx_t` as the single session root object.

REQ-DATA-002: The context shall own two TLV trees: `terminal` (terminal-side tags) and `card` (card-side tags).

REQ-DATA-003: The context shall store `Iso7816CommandChannel channel` (contactless default).

REQ-DATA-004: The context shall store `TransactionType_t tr_type` aligned with existing enum in `emvcore.h`.

REQ-DATA-005: The context shall maintain ordered `phase_events[]` with phase id, timestamp, result code, optional SW.

### Terminal Profile JSON

REQ-DATA-010: The system shall support `client/resources/emv_terminal_profile.json` extending `emv_defparams.json`. Example shipped at `docs/emv-terminal-emulator/examples/emv_terminal_profile.json`.

REQ-DATA-011: Profile shall include: floor limit (9F1B), terminal capabilities (9F33), additional capabilities (9F40), terminal type (9F35), TAC default/denial/online (DF8120–DF8122), country (9F1A), currency (5F2A).

REQ-DATA-012: Profile shall support per-AID overrides keyed by AID hex string.

REQ-DATA-013: Loading shall use existing `ParamLoadFromJson` / `JsonLoadBufAsHex` patterns.

### Session Export JSON

REQ-DATA-020: Session export shall include metadata: `Created`, `Platform`, `Command`, `Outcome`, `TransactionType`.

REQ-DATA-021: Session export shall include `Phases[]` array: `{ "id", "name", "result", "sw", "notes" }`.

REQ-DATA-022: Session export shall include masked PAN path `Card.PAN` when available from track 2 or PAN tag.

REQ-DATA-023: Session export shall embed TLV snapshot references (not full duplicate of scan format unless `--full-tlv`).

REQ-DATA-024: Session export shall be compatible for downstream tools: optional `merge` into scan JSON for `emv sim` card replay research.

### Card Load (from prior scan)

REQ-DATA-030: `emv terminal load <file.json>` shall import card TLV subset from prior `emv scan` output for **offline replay testing** (no live card).

REQ-DATA-031: Load shall reject files missing minimum tags: AID, AIP, ATC-capable records for GEN AC testing.

### PIN Data

REQ-DATA-040: PIN shall exist only in volatile memory; max 8 digits BCD; zeroized after VERIFY.

REQ-DATA-041: Enciphered PIN block shall be built in a stack buffer; not written to session JSON.

## State and Data

### `emv_term_ctx_t` (indicative C structure)

```c
typedef enum {
    EMV_PHASE_INIT = 0,
    EMV_PHASE_ODA,
    EMV_PHASE_RESTRICT,
    EMV_PHASE_CVM,
    EMV_PHASE_TRM,
    EMV_PHASE_TAA,
    EMV_PHASE_CAA,
    EMV_PHASE_ONLINE,
    EMV_PHASE_COMPLETE,
} emv_term_phase_t;

typedef enum {
    EMV_OUTCOME_UNKNOWN = 0,
    EMV_OUTCOME_APPROVED_OFFLINE,
    EMV_OUTCOME_DECLINED,
    EMV_OUTCOME_ONLINE_REQUIRED,
    EMV_OUTCOME_ABORTED,
} emv_term_outcome_t;

typedef struct {
    emv_term_phase_t id;
    int result;           // PM3_* code
    uint16_t sw;
    uint64_t ts_ms;
    char note[128];
} emv_phase_event_t;

typedef struct {
    struct tlvdb *terminal;
    struct tlvdb *card;
    Iso7816CommandChannel channel;
    TransactionType_t tr_type;
    emv_term_outcome_t outcome;
    emv_term_phase_t current_phase;
    emv_phase_event_t *events;
    size_t event_count;
    size_t event_cap;
    // ODA summary
    bool oda_performed;
    bool oda_success;
    // CVM summary
    uint8_t cvm_results[3];  // 9F34
} emv_term_ctx_t;
```

### Session JSON schema (excerpt)

```json
{
  "File": { "Created": "proxmark3 emv terminal", "Version": "1" },
  "Terminal": { "Profile": "default", "Channel": "contactless" },
  "Outcome": "online_required",
  "Phases": [
    { "id": 0, "name": "init", "result": 0, "sw": "9000" }
  ],
  "Card": {
    "AID": "A0000000031010",
    "PAN": "411111******1111"
  },
  "Cryptogram": {
    "Type": "ARQC",
    "ATC": "0001",
    "AC": "..."
  }
}
```

## Main Flows

1. **Init context** — `emv_term_ctx_init()` allocates trees, loads profile JSON into `terminal`.
2. **Live card** — phases populate `card` via APDU responses.
3. **Export** — `emv_term_session_save_json(ctx, path)`.
4. **Teardown** — `emv_term_ctx_free()` frees TLV trees, events, zeroizes PIN buffers.

## Edge Cases

- Profile tag wrong length → reject load with tag name in error
- Merge session into scan JSON with conflicting ATC → warn and require `--force`
- jansson path limits on Windows — use `FILE_PATH_SIZE` like existing commands

## Failure Handling

- JSON parse errors reference line number (existing `json_load_file` pattern)
- Missing required terminal tag → use EMV default from `ParamLoadDefaults` in `cmdemv.c` with warning

## Security / Privacy Notes

- Default export redacts: PIN, track 2 equivalent, issuer authentication data
- `--include-sensitive` requires explicit flag and prints warning banner

## Acceptance Criteria

AC-DATA-001: Given valid profile JSON, when loaded into context, then terminal tree contains 9F02, 9F1A, 5F2A, 9F33.

AC-DATA-002: Given completed session, when exported, then JSON validates and contains Phases array length equals executed phase count.

AC-DATA-003: Given PIN used in session, when export default, then no field contains PIN or enciphered PIN block.

## Test Coverage Notes

- AUTO-DATA-001: profile load round-trip
- AUTO-DATA-002: session JSON schema validation
- AUTO-DATA-003: PAN masking function

## Open Questions

OQ-002: Single merged JSON schema for scan + terminal session vs separate files — see [OPEN-QUESTIONS.md](./OPEN-QUESTIONS.md).
