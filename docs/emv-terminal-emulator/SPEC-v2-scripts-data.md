# SPEC v2: Issuer Scripts, Session Data, Redaction, Viewer

## Scope

Features **F-004**, **F-005**, **F-010**, **F-028**, **F-037**

---

## Issuer Script Processing — REQ-DAT-001–019

### REQ-DAT-001

Module `phase_scripts.c` shall process issuer script templates tag `71` (before final GEN AC) and tag `72` (after final GEN AC).

### REQ-DAT-002

Each `86` command template inside script: build C-APDU from bytes after tag header; send via `EMVExchange`.

### REQ-DAT-003

Stop on first non-9000 SW; set TVR:

| Script | TVR byte | Bit |
|--------|----------|-----|
| 71 fail | 4 | 0x40 — before final GEN AC |
| 72 fail | 4 | 0x20 — after final GEN AC |

### REQ-DAT-004

On any script sent, set TSI byte 1 bit 0x04 (script processing performed).

### REQ-DAT-005

Tag `72` shall run in `phase_complete` or end of `phase_online` after AC2 success.

### REQ-DAT-006

Multiple `86` in one script: process sequentially (REQ F-037).

### REQ-DAT-007

Do not log script payloads that match PIN change pattern (`24`/`25` INS) in clear — redact as `[SCRIPT REDACTED]`.

---

## Session ↔ Scan Merge — REQ-DAT-020–029

### REQ-DAT-020

`emv terminal session merge <scan.json> <session.json> -o out.json` shall produce combined document:

- `File`, `Card` from scan
- `Terminal`, `Phases`, `Outcome`, `Cryptogram` from session
- Optional `Transaction` overlay

### REQ-DAT-021

`emv terminal load` shall accept `--merge-session` to apply phase outcomes onto loaded card tree.

### REQ-DAT-022

Export flag `--full-tlv` on `run`/`step` shall embed `Card.TLV` snapshot (subset: tags touched during transaction).

### REQ-DAT-023

Merged file shall validate minimum fields for `emv sim` research import (document mapping in SPEC-data-model.md addendum).

### REQ-DAT-024

Reject merge if AID in scan ≠ AID in session.

---

## Session Viewer — REQ-DAT-030–039

### REQ-DAT-030

Subcommand `emv terminal session print <file>` human output:

```
Outcome: approved_online
AID: A0000002771010
PAN: ************1234
Phases:
  init       OK
  oda        OK (DDA)
  cvm        OK  CVMR=010002
  taa        OK  requested=ARQC
  caa        OK  AC1=ARQC ATC=0042
  online     OK  EXTERNAL AUTH OK  AC2=TC
TVR: 0000008000  [byte3 b8=Amount exceeds floor limit]
TSI: E800
Cryptogram: ARQC ... → TC ...
```

### REQ-DAT-031

Decode TVR/TSI bits using tables in [SPEC-advanced-terminal-features.md](./SPEC-advanced-terminal-features.md).

### REQ-DAT-032

Optional `--json` emits enriched session with decoded bit names.

---

## Session Redaction — REQ-DAT-040–049

### REQ-DAT-040

Default session export shall **redact**:

| Field | Redaction |
|-------|-----------|
| `Cryptogram.AC` | First 4 bytes + `...` |
| `Card.PAN` | Already masked |
| Track 2 `57` | Masked |
| IAD `9F10` | Omitted unless `--no-redact` |

### REQ-DAT-041

Flag `--no-redact` exports full hex for local lab only; print warning.

### REQ-DAT-042

Environment `EMV_TERMINAL_FULL_SESSION=1` equivalent to `--no-redact`.

### REQ-DAT-043

Redaction module `emv_term_redact.c` shared by save and merge.

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-DAT-001 | Script 71 with bad SW | online | TVR script fail bit |
| AC-DAT-002 | Script 72 after AC2 | complete | TSI script bit |
| AC-DAT-003 | scan + session same AID | merge | Valid out.json |
| AC-DAT-004 | Default save | export | AC truncated |
| AC-DAT-005 | session print | CLI | TVR bits labeled |

---

## Files

| File | Purpose |
|------|---------|
| `phase_scripts.c/h` | Script 71/72 |
| `emv_term_session_view.c/h` | print |
| `emv_term_redact.c/h` | redaction |
| `emv_term_session.c` | merge, full-tlv |
