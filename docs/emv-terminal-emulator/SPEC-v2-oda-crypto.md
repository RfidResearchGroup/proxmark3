# SPEC v2: ODA, CAPK, fDDA, Terminal CDA

## Scope

Features **F-012**, **F-013**, **F-026**

---

## CAPK Management — REQ-ODA-001–014

### REQ-ODA-001

CLI `--capk-extra <file>` shall parse supplemental CAPK entries (same format as `capk.txt`) and merge into runtime CAPK table before ODA.

### REQ-ODA-002

Profile JSON field `CAPKExtra: "capk_interac_extra.txt"` auto-loads with scheme profile.

### REQ-ODA-003

Interac RID `A000000277` indices 03, 07 shall ship in default or extra file ([SPEC-cryptography-keys.md](./SPEC-cryptography-keys.md)).

### REQ-ODA-004

On unknown CA index (`8F`), log warning and set TVR "ICC data missing" if ODA required.

### REQ-ODA-005

`emv terminal profile validate` shall optionally check referenced CAPK files exist.

---

## fDDA / qVSDC Contactless — REQ-ODA-020–029

### REQ-ODA-020

For qVSDC contactless with AIP fDDA bit, `phase_oda` shall:

1. Ensure UN (`9F37`) present (from TRM)
2. Execute INTERNAL AUTHENTICATE / fDDA path per existing `trDDA` / qVSDC variant
3. Verify SDAD in GPO response (`9F4B`) when present

### REQ-ODA-021

Set `ctx->oda_performed` and `ctx->oda_success` accordingly; TAA reads result.

### REQ-ODA-022

Profile `visa_qvsdc.json` field `ODARequired: false` for MSD-only lab cards.

### REQ-ODA-023

Log: `fDDA: SDAD verify OK` or `FAIL`.

---

## Terminal-Side CDA Verification — REQ-ODA-030–039

### REQ-ODA-030

When transaction type `TT_CDA` and AC1 response includes `9F4B`, terminal shall verify SDAD after GEN AC using existing `trCDA()` logic.

### REQ-ODA-031

On CDA verify failure, set TVR "CDA failed" and force AAC at TAA if not already decided.

### REQ-ODA-032

AC2 CDA path same verification on second GEN AC.

### REQ-ODA-033

Session records `Cryptogram.CDAVerify: ok|fail|skipped`.

---

## ODA Input List — REQ-ODA-040–044

### REQ-ODA-040

When loading from scan JSON, rebuild tag `21` ODA input list from Records offline flags if missing.

### REQ-ODA-041

Offline replay (`load` + `step oda`) shall perform ODA without live READ RECORD.

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-ODA-001 | Extra CAPK file with Interac 07 | ODA | DDA succeeds on test card |
| AC-ODA-002 | qVSDC fDDA card | `run --qvsdc` | fDDA log OK |
| AC-ODA-003 | CDA txn bad SDAD | genac | TVR CDA fail |
| AC-ODA-004 | Scan load + step oda | mock | ODA uses tag 21 |

---

## Files

| File | Change |
|------|--------|
| `phase_oda.c` | fDDA branch |
| `phase_caa.c` | CDA verify |
| `emv_term_load.c` | ODA list rebuild |
| `emv_pk` / capk loader | extra file merge |
