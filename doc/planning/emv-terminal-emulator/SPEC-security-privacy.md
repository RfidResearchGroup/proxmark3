# SPEC: Security and Privacy

> **FOR RESEARCH AND LAB USE ONLY — NO WARRANTY — PROVIDED AS-IS**  
> Operators must read [README.md](./README.md) and [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md) before use.

## Purpose

Define how the terminal emulator handles sensitive data and legal/ethical boundaries.

## Scope

PIN, PAN, cryptograms, keys, logging, authorized use

## Non-Goals

PCI PTS POI certification requirements checklist (full)

## Functional Requirements

REQ-SEC-001: The system shall zeroize PIN buffers immediately after VERIFY completes or on error path.

REQ-SEC-002: Session JSON export shall mask PAN (BIN + last 4) unless `--include-sensitive` explicitly set.

REQ-SEC-003: APDU logging shall not print PIN VERIFY command data field in default mode.

REQ-SEC-004: Documentation shall state: **for authorized security research and EMV test cards only**.

REQ-SEC-005: Online PIN path shall not send PIN to any network endpoint in v1; stub only.

REQ-SEC-006: Terminal profile shall not store issuer master keys or live acquirer credentials.

REQ-SEC-007: `--include-sensitive` shall print one-time warning banner about lab use.

REQ-SEC-008: Enciphered PIN construction shall use card ICC PIN key from live card response, not stored keys.

## Threat Model (abbreviated)

| Asset | Threat | Mitigation |
|-------|--------|------------|
| PIN | Shell history / logs | Env var PIN, no default log of VERIFY body |
| PAN / track | Session file leak | Masking, access control on files |
| ARQC | Replay at merchant | Tool is terminal not card; educate on misuse |
| CA private keys | N/A | Terminal holds public CA keys only |

## Legal / Ethical Use

Operators must:

- Only test cards they own or have written authorization to test
- Not use emulator to bypass payment systems in production environments
- Comply with local laws regarding payment card research

## Acceptance Criteria

AC-SEC-001: After PIN entry, heap/stack buffer scan in debug build shows zeroized PIN (unit test).

AC-SEC-002: Default session JSON never contains `"99"` PIN data tag.

## Test Coverage Notes

AUTO-SEC-001: PIN zeroization test  
AUTO-SEC-002: PAN mask test  
MAN-SEC-001: Verify APDU log redaction with `-a`

## Open Questions

OQ-004: Redaction policy for cryptogram in shared traces — see OPEN-QUESTIONS.md
