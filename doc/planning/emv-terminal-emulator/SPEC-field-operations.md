# SPEC: Field Operations

## Purpose

Lab setup, test cards, and operational procedures for EMV terminal testing on PM3Easy.

## Test Environment

| Item | Requirement |
|------|-------------|
| Hardware | PM3Easy (or PM3GENERIC clone), USB cable |
| Host | Linux/macOS/Windows with built Iceman client |
| Cards | EMVCo / scheme test cards or personal debit/credit in private lab |
| RF | Quiet 13.56 MHz environment; no parallel HF readers |

## Setup Steps

1. Configure `Makefile.platform` (see [SPEC-device-behavior.md](./SPEC-device-behavior.md))
2. `make -j && make client/client && ./pm3-flash-fullimage`
3. Verify: `hw status`, `hf 14a info` with card present
4. Copy `client/resources/emv_terminal_profile.json` if customized

## Reset Steps

- `emv list -c` — clear APDU history
- Remove card, `hf 14a fieldoff`
- Delete partial session JSON files

## Test Card Categories

| Category | Use |
|----------|-----|
| qVSDC Visa test | Primary contactless happy path |
| M/Chip test | Mastercard contactless |
| Offline PIN card | CVM VERIFY testing |
| ODA failure card | TVR / TAA decline testing |

Specific card IDs depend on issuer test packs available to operator — not bundled in repo.

## Operator Workflows

See [SPEC-user-flows.md](./SPEC-user-flows.md).

## Safety

- Do not test in live retail terminals
- Label lab PM3 clearly as research device

## Acceptance Criteria

AC-FIELD-001: Documented setup produces successful `hf 14a info` on test card before terminal run.

## Test Coverage Notes

Referenced by MAN-* setup sections in [TEST-PLAN-manual.md](./TEST-PLAN-manual.md)
