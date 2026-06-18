# SPEC v2: Scheme Profiles, Kernels, MSD, Test Matrix

## Scope

Features **F-002**, **F-015**, **F-024**, **F-025**, **F-034**, **F-036**, **F-040**

---

## Scheme Profile Packs

### REQ-SCH-001

The system shall ship profile JSON files under `client/resources/scheme_profiles/`:

| File | Scheme | AID prefix |
|------|--------|------------|
| `interac.json` | Interac Flash + contact | `A000000277` |
| `visa_qvsdc.json` | Visa qVSDC / VSDC | `A000000003`, `A000000004` |
| `mc_mchip.json` | Mastercard M/Chip | `A000000004`, `A000000005` |

### REQ-SCH-002

CLI flag `--profile <name>` where `<name>` ∈ `interac`, `visa`, `mc`, `default`, `auto`.

### REQ-SCH-003

`--profile auto` shall map selected AID to profile using `examples/terminal_aid_candidates.json` rules (longest prefix match).

### REQ-SCH-004

Profile load shall merge into terminal TLV tree **before** GPO PDOL build:

- Terminal Action Codes (`DF8120`–`DF8122` or scheme-specific)
- Floor limit (`9F1B`), capabilities (`9F33`, `9F40`)
- TTQ (`9F66`), CTQ defaults where applicable
- Default transaction type hint

### REQ-SCH-005

Profile shall include metadata:

```json
{
  "Name": "interac",
  "Version": "1",
  "AIDs": ["A0000002771010"],
  "ContactlessKernel": "C-1",
  "HostKeysFile": "interac_test_keys.json",
  "CVM": { "FlashSkipVerify": true, "DefaultOfflinePIN": false }
}
```

---

## Kernel Selection (Simplified) — REQ-SCH-010–019

### REQ-SCH-010

Before TAA, dispatcher shall set internal kernel enum: `KERNEL_VISA_QVSDC`, `KERNEL_MC_MCHIP`, `KERNEL_INTERAC`, `KERNEL_GENERIC`.

### REQ-SCH-011

Dispatcher input: AID, channel (contact/contactless), profile override.

### REQ-SCH-012

Visa qVSDC contactless: skip full CDOL1 GEN AC when AC in GPO and profile says `ACFromGPO=true`.

### REQ-SCH-013

MC M/Chip: ensure `GET CHALLENGE` before GEN AC1 when AIP indicates.

### REQ-SCH-014

Interac contactless Flash: apply CVM skip matrix (REQ-SCH-040).

### REQ-SCH-015

Log selected kernel: `Kernel: interac-c1 (contactless)`.

---

## Contactless Kernel Hints — REQ-SCH-020–029

### REQ-SCH-020

Terminal shall set TTQ (`9F66`) from profile unless card/operator overrides.

### REQ-SCH-021

Visa: TTQ byte 1 bit 8 — offline PIN supported flag per profile.

### REQ-SCH-022

MC: set `9F6D` / contactless TAC tags when present in profile (Interac uses `9F6D`/`9F6B`).

### REQ-SCH-023

Kernel ID (`9F2A`) shall be logged when present in PPSE/FCI; not required for v2 behavior.

---

## Interac Flash CVM Matrix — REQ-SCH-040–044

### REQ-SCH-040

For Interac contactless + profile `interac`, CVM phase shall skip offline VERIFY when CVM list entry is offline PIN and card indicates Flash (per TC01–TC04 lab doc).

### REQ-SCH-041

Set CVM Results (`9F34`) to reflect skipped/bypassed with documented byte values for each TC case.

### REQ-SCH-042

Contact path shall **not** skip VERIFY for same card profile.

---

## MSD / PayPass Legacy — REQ-SCH-050–054

### REQ-SCH-050

When AIP indicates MSD (`0x8000`) and transaction type MSD, `phase_caa` shall approve offline with Track 2 validation logged.

### REQ-SCH-051

Extract and validate Track 2 equivalent data (`57`) — expiry, service code logged.

### REQ-SCH-052

Outcome `approved_offline` with note `MSD path — no cryptogram`.

### REQ-SCH-053

Document deprecation warning in output.

---

## Test Card Matrix (Lab Checklist) — REQ-SCH-060

Document-only requirement for operators; file `client/resources/TEST-CARD-MATRIX.md`:

| Card | AID | Profile | Contact | CL | PIN | Expected outcome |
|------|-----|---------|---------|----|----|------------------|
| Interac TC01 | A0000002771010 | interac | VERIFY 1111 | Flash skip | 1111 | ARQC → online OK |
| Interac TC02 | same | interac | wrong PIN | — | 2222 | AAC |
| Visa qVSDC test | A0000000031010 | visa | VSDC | qVSDC | varies | TC or ARQC |
| MC test | A0000000043060 | mc | M/Chip | M/Chip | varies | ARQC |

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-SCH-001 | AID A0000002771010 | `--profile auto` | Loads interac.json |
| AC-SCH-002 | Interac CL TC01 | `run -j --profile interac` | No VERIFY APDU |
| AC-SCH-003 | Visa qVSDC | `--profile visa` | TTQ from profile |
| AC-SCH-004 | MSD AIP card | `run` MSD | Track2 path, no GEN AC |
| AC-SCH-005 | MC card | `--profile mc` | GET CHALLENGE if required |

---

## Files

| Path | Purpose |
|------|---------|
| `client/resources/scheme_profiles/*.json` | Profile packs |
| `client/src/emv/terminal/scheme/*.c` | Per-scheme hooks |
| `examples/TEST-CARD-MATRIX.md` | Lab checklist |
