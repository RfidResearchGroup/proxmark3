# SPEC v2: CLI UX, Overrides, Legal Banner, Capabilities

## Scope

Features **F-007**, **F-008**, **F-030**, **F-039**

---

## Transaction Parameter Overrides — REQ-CLI-001–014

### REQ-CLI-001

Flags on `run`, `step` (init), and `load` (with profile):

| Flag | Tag | Format |
|------|-----|--------|
| `--amount <n>` | 9F02 | Decimal cents → 6-byte BCD |
| `--currency <code>` | 5F2A | ISO 4217 numeric (e.g. 124 CAD) |
| `--country <code>` | 9F1A | ISO 3166 numeric |
| `--date YYMMDD` | 9A | BCD 3 bytes |
| `--time HHMMSS` | 9F21 | BCD 3 bytes (if in profile) |
| `--type <hex\|name>` | 9C | 00=purchase, 01=cash, etc. |

### REQ-CLI-002

Invalid BCD input shall return `PM3_EINVARG` with example in error message.

### REQ-CLI-003

Overrides apply after profile load; override wins.

### REQ-CLI-004

Log applied overrides at INFO when `--trace-phases`.

---

## AID Selection — REQ-CLI-020–024

### REQ-CLI-020

`--aid <hex>` on `emv terminal run|step init` forces selection of that AID (skip PPSE selection logic).

### REQ-CLI-021

`--forceaid` equivalent to `emv exec --forceaid` — search AID list.

### REQ-CLI-022

Mutually exclusive: if both `--aid` and PPSE succeed, `--aid` wins.

### REQ-CLI-023

Session export records `Terminal.ForcedAID: true`.

---

## Legal / Authorized Use Banner — REQ-CLI-030–034

### REQ-CLI-030

First `emv terminal run|step|online|host-sim` per user config dir shall print:

```
[!] EMV terminal emulator — authorized test cards and lab use only.
    See docs/emv-terminal-emulator/SPEC-security-privacy.md
```

### REQ-CLI-031

Acknowledgment stored in `~/.proxmark3/emv_terminal_ack` (timestamp) or skip if `EMV_TERMINAL_I_ACK=1`.

### REQ-CLI-032

Banner suppressed in `--mock-apdu-file` CI mode.

---

## Capabilities Discovery — REQ-CLI-040–044

### REQ-CLI-040

`emv terminal capabilities` prints:

- Device: PM3GENERIC / PM3Easy detection if available
- 14a: yes/no
- Smartcard mod: yes/no
- Recommended: `emv terminal run -j --profile auto`
- Firmware flash size if query supported

### REQ-CLI-041

Always available (no device required for static capability list from build flags).

---

## Extended Command Tree (v2)

```text
emv terminal
├── run
├── step
├── online
├── host-sim          # NEW
├── host              # NEW (--listen)
├── pin
├── profile
├── load
├── session           # NEW
│   ├── print
│   └── merge
├── compare           # NEW (see SPEC-v2-testing-ci)
├── test              # NEW (--golden)
├── replay            # NEW (see SPEC-v2-trace-replay)
└── capabilities      # NEW
```

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-CLI-001 | `--amount 100` | init | 9F02 = 000000000100 |
| AC-CLI-002 | `--aid A0000000031010` | run | That AID selected |
| AC-CLI-003 | First run | no ack file | Banner shown |
| AC-CLI-004 | Second run | ack exists | No banner |
| AC-CLI-005 | `capabilities` | no PM3 | Static list printed |
