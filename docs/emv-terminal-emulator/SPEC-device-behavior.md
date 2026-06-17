# SPEC: Device Behavior — PM3Easy / PM3GENERIC

## Purpose

Hardware constraints and runtime behavior for EMV terminal emulation on generic Proxmark3 platforms, **PM3Easy primary**.

## Scope

PM3GENERIC firmware, PM3Easy LED order, 256 KB / 512 KB flash variants, HF 14a antenna

## Non-Goals

RDV4 BT addon, external flash dependency for terminal MVP

## Platform Matrix

| Platform | Flash | Terminal MVP | Notes |
|----------|-------|--------------|-------|
| PM3Easy 512 KB | Default fullimage | Client-only terminal | Recommended |
| PM3Easy 256 KB | Tight | Client-only; may need `STANDALONE=` + `SKIP_*` | Validate in M6 |
| PM3GENERIC + SMARTCARD | 512 KB | Contact EMV via `-w` | Requires hardware mod |
| PM3 RDV4 | 512 KB+ | Same client commands | Not primary target |

## Functional Requirements

REQ-DEVICE-001: Terminal MVP shall not require firmware changes on PM3Easy 512 KB builds.

REQ-DEVICE-002: Build documentation shall specify `Makefile.platform`:

```make
PLATFORM=PM3GENERIC
LED_ORDER=PM3EASY
```

REQ-DEVICE-003: 256 KB profile shall document minimum skips if fullimage exceeds 262144 bytes:

```make
PLATFORM=PM3GENERIC
PLATFORM_SIZE=256
LED_ORDER=PM3EASY
STANDALONE=
SKIP_HITAG=1
SKIP_FELICA=1
```

REQ-DEVICE-004: EMV terminal contactless shall use existing HF 14a field; operator holds card on antenna during session.

REQ-DEVICE-005: LED feedback (optional v1): use existing `LED_A` blink on phase complete — not required for MVP.

REQ-DEVICE-006: Button abort: existing pm3 button handling during long operations shall abort terminal run (same as `emv reader`).

REQ-DEVICE-007: Device capability check: refuse `-w wired` when `IfPm3Smartcard()` false.

## RF / Timing

REQ-DEVICE-010: Terminal shall keep field ON between phase APDUs (`LeaveFieldON=true`) unless operator `--drop-between-phases` for debug.

REQ-DEVICE-011: WTX handling relies on existing iso14443-4 stack; if timeouts occur on slow cards, optional firmware assist deferred.

## Memory (device)

Existing BigBuf limits apply (~270 byte ISO7816 frame). Terminal engine on host has no device RAM impact for MVP.

## Acceptance Criteria

AC-DEVICE-001: PM3Easy 512 KB fullimage builds with default standalone without EMV terminal firmware additions.

AC-DEVICE-002: `hw status` on PM3Easy reports capabilities matching contactless terminal run.

## Test Coverage Notes

MAN-DEVICE-001: Build flash size check with PLATFORM_SIZE=256  
MAN-DEVICE-002: Field ON stability through 20+ APDU transaction

## Open Questions

OQ-006: Dedicated standalone mode `HF_EMVTERM` for field-only terminal — likely unnecessary; see OPEN-QUESTIONS.md
