# SPEC v2: Host Simulator, ARQC/ARPC, TCP Acquirer, Online PIN

## Scope

Features **F-001**, **F-003**, **F-011**, **F-023**, **F-038**

## Purpose

Replace the XOR lab stub with a **cryptographically correct local host** that verifies ARQC and computes ARPC for authorized test cards. Enable online PIN deferral and optional TCP acquirer for automated rigs.

## Non-Goals

- Live ISO 8583 to production acquirer
- HSM integration
- PIN translation to real network

---

## Module: `emv_term_host.c`

### REQ-HOST-001

The system shall provide subcommand `emv terminal host-sim [options]` that loads a session JSON with ARQC outcome, verifies ARQC, computes ARPC, and invokes the existing online phase (EXTERNAL AUTH + AC2).

### REQ-HOST-002

The system shall load issuer/session keys from JSON path defaulting to `docs/emv-terminal-emulator/examples/interac_test_keys.json` or profile field `HostKeys`.

Key record schema:

```json
{
  "Scheme": "interac",
  "ACMasterKey": "0123456789ABCDEFFEDCBA9876543210",
  "ARPCMethod": "cvn18",
  "DefaultARPCRC": "8840",
  "PINKey": "optional-for-online-pin"
}
```

### REQ-HOST-003

For Interac test cards, ARPC-RC shall default to `8840` when not specified (contact path per Interac issuer simulator documentation).

### REQ-HOST-004

`emv terminal run` shall accept `--host-sim` flag equivalent to `--auto-online` with host key lookup (no manual `--arpc`).

### REQ-HOST-005

When host-sim ARQC verification fails, outcome shall be `declined` or `online_required` with log `ARQC verify: FAIL` and optional `--continue-on-bad-arqc` for research.

---

## ARQC Verification — REQ-HOST-010–019

### REQ-HOST-010

The host shall extract ARQC from tag `9F26`, ATC from `9F36`, and build input data per scheme CVN from CDOL1-equivalent tags present in session/card TLV.

### REQ-HOST-011

Interac / MC CVN18: verify ARQC using session key derived from AC master key and ATC (document algorithm reference in [SPEC-cryptography-keys.md](./SPEC-cryptography-keys.md)).

### REQ-HOST-012

Visa CVN10/CVN18: implement verify path for test keys when profile `visa_qvsdc` selected.

### REQ-HOST-013

On successful verify, log `ARQC verify: OK (scheme=<name> cvn=<n>)`.

### REQ-HOST-014

On failure, set TVR bit "Issuer authentication failed" if continuing to EXTERNAL AUTH with bad ARPC (lab override only).

---

## ARPC Generation — REQ-HOST-020–029

### REQ-HOST-020

ARPC shall be computed per scheme rules; tag `91` = ARPC || ARPC-RC when RC required.

### REQ-HOST-021

ARC tag `8A` shall come from `--arc`, host-sim config, or default `3030` (approve ASCII) / `0000` (approve BCD) per profile.

### REQ-HOST-022

Decline path: ARC `05` or `3035` → AC2 requests AAC ref control.

### REQ-HOST-023

Manual `--arpc` shall override computed ARPC (backward compatible with Phase 6 stub).

---

## Online PIN (CVM 02) — REQ-HOST-030–039

### REQ-HOST-030

When CVM list selects online PIN (`02`), terminal shall format ISO 9564 format 0/1/2 block per scheme profile and store in volatile host-bridge buffer.

### REQ-HOST-031

Terminal shall set TVR "Online PIN entered" when PIN collected; shall **not** send PIN over TCP in v2 unless `--host-sim-unsafe-pin` (documented lab-only).

### REQ-HOST-032

Host-sim shall accept PIN block in session for CDOL2 inclusion when issuer test script requires it.

### REQ-HOST-033

`--cvm-skip-online` behavior unchanged; online PIN stub sets TVR only.

---

## CDOL2 Host Data Injection — REQ-HOST-040–044

### REQ-HOST-040

Host-sim shall inject tags required for CDOL2 not present on card: `8A`, `91`, issuer script `71` from simulated host response file.

### REQ-HOST-041

Support `--host-response <json>` with fields: `ARC`, `ARPC`, `ARPCRC`, `Script71`, `Script72`.

---

## TCP Mock Acquirer — REQ-HOST-050–059

### REQ-HOST-050

Subcommand `emv terminal host --listen [<port>]` default port `8583` on `127.0.0.1`.

### REQ-HOST-051

Protocol v1 (JSON lines, newline-delimited):

**Request (terminal → host):**

```json
{"type":"auth","arqc":"...","atc":"...","amount":"...","pan_masked":"************1234","aid":"A0000002771010"}
```

**Response (host → terminal):**

```json
{"type":"auth_resp","arc":"3030","arpc":"...","arpc_rc":"8840","script71":""}
```

### REQ-HOST-052

Terminal online phase shall use TCP host when `--host-tcp localhost:8583` set.

### REQ-HOST-053

TCP host shall use same crypto as local host-sim (shared `emv_term_arqc.c`).

### REQ-HOST-054

Connection timeout 5s; retry 0 (fail fast in lab).

---

## CLI Summary

| Command / flag | Description |
|--------------|-------------|
| `emv terminal host-sim` | One-shot host on session |
| `emv terminal host --listen 8583` | Daemon mock acquirer |
| `--host-sim` | Enable on `run` |
| `--host-keys <file>` | Key material |
| `--host-response <file>` | Canned ARC/ARPC/scripts |
| `--host-tcp host:port` | TCP acquirer |
| `--continue-on-bad-arqc` | Research override |

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-HOST-001 | Interac TC01 session with ARQC | `host-sim` | EXTERNAL AUTH SW 9000, AC2 TC, `approved_online` |
| AC-HOST-002 | Wrong AC master key in config | `host-sim` | ARQC verify FAIL logged |
| AC-HOST-003 | `--arpc` hex provided | `online` | Computed ARPC skipped |
| AC-HOST-004 | TCP host returns decline ARC | `run --host-tcp` | AC2 AAC |
| AC-HOST-005 | CVM 02 + `--pin 1234` + host-sim | `run` | TVR online PIN bit set |

---

## Files to Create/Modify

| File | Change |
|------|--------|
| `emv_term_host.c/h` | Host orchestration |
| `emv_term_arqc.c/h` | Verify + ARPC |
| `phase_online.c` | Call host |
| `phase_cvm.c` | Online PIN branch |
| `emv_term_cmd.c` | New subcommands |

---

## References

- [SPEC-cryptography-keys.md](./SPEC-cryptography-keys.md)
- [examples/interac_test_keys.json](./examples/interac_test_keys.json)
- EMV Book 3 — EXTERNAL AUTHENTICATE, ARPC
