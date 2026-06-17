# SPEC: API — CLI and Device Interface

## Purpose

Define user-facing commands, arguments, and USB/firmware hooks for the EMV terminal emulator.

## Scope

- New and extended `emv` subcommands in `client/src/emv/cmdemv.c`
- Reuse existing ISO7816 transport; no breaking changes to current `emv exec` / `emv scan`
- Optional future firmware opcode for terminal assist

## Non-Goals

- Graphical UI or Proxmark3 GUI integration in v1
- Lua scripting API (may follow existing `script run` patterns later)
- Public stable C API for third-party libraries

## User / Actor Stories

| Actor | Story |
|-------|-------|
| Operator | Run `emv terminal run` with familiar flags like existing `emv exec` |
| CI | Invoke non-interactive terminal run with `--pin` and fixed UN |
| Developer | Use `emv terminal step init` to debug one phase |

## Functional Requirements

### Command Tree

REQ-API-001: The system shall add subcommand group `emv terminal` with subcommands: `run`, `step`, `load`, `profile`, `pin`.

REQ-API-002: Existing commands (`emv exec`, `emv scan`, `emv reader`, `emv sim`) shall remain unchanged in behavior for backward compatibility.

REQ-API-003: `emv terminal run` shall accept superset of `emv exec` transaction flags: `--qvsdc`, `--qvsdccda`, `--vsdc`, `-j`, `-w`, `-a`, `-t`.

### `emv terminal run`

REQ-API-010: Syntax: `emv terminal run [options]` — executes full terminal phase loop.

REQ-API-011: Options:
- `-j, --jload` — load `emv_terminal_profile.json` (fallback `emv_defparams.json`)
- `-o, --output <file>` — session JSON path
- `--amount <cents>` — override 9F02 (6-byte BCD)
- `--pin <digits>` — non-interactive offline PIN (lab only)
- `--aid <hex>` — force AID selection
- `--forceaid` — skip PPSE, search AID list (same as exec)
- `--oda-required` / `--no-oda-required` — policy flag
- `--stop-after <phase>` — debug: stop after named phase
- `--trace-phases` — log phase boundaries to stdout

REQ-API-012: Return codes: `PM3_SUCCESS` on completed session (any outcome); `PM3_E*` on transport/parse abort.

REQ-API-013: Human output shall include outcome line: `[+] Terminal outcome: online_required (ARQC)`.

### `emv terminal step`

REQ-API-020: Syntax: `emv terminal step <phase> [options]` — run single phase against current session state.

REQ-API-021: Phases: `init`, `oda`, `restrict`, `cvm`, `trm`, `taa`, `caa`, `online`, `complete`.

REQ-API-022: Requires `--session <file>` for state carry-over except `init` which creates new session file.

### `emv terminal pin`

REQ-API-030: Syntax: `emv terminal pin [--offline <pin>] [--enciphered]` — standalone VERIFY for debugging after `init` phase session exists.

REQ-API-031: Interactive mode prompts on stdin when `--offline` omitted (password-style no echo if terminal supports).

### `emv terminal profile`

REQ-API-040: Syntax: `emv terminal profile print|validate [file]` — dump or validate terminal profile JSON.

### `emv terminal load`

REQ-API-050: Syntax: `emv terminal load <scan.json>` — import card data for offline phase testing without live card.

### Extensions to existing commands

REQ-API-060: `emv exec` shall call shared `emv_terminal_phases()` internally when `--terminal` flag added (optional compatibility shim).

REQ-API-061: `emv test` shall add terminal phase self-tests entry point.

### Device / USB

REQ-API-070: MVP shall use existing commands only: `CMD_HF_ISO14443A_*`, smartcard via `CMD_SMARTCARD_*` — no new opcodes required.

REQ-API-071: Optional firmware opcode `CMD_HF_EMV_TERMINAL_ASSIST` (0x0387 proposed) reserved for future WTX/pipeline — not required for MVP.

REQ-API-072: `IfPm3Iso14443` gate shall apply to all terminal contactless commands; `IfPm3Smartcard` for `-w wired`.

## State and Data

Command handlers receive `emv_term_cli_opts_t` parsed by cliparser, build `emv_term_ctx_t`, invoke engine, serialize output.

Session file path stored in context for `step` subcommands.

## Main Flows

```text
emv terminal run -j -o /tmp/s.json --amount 500 --qvsdc
  → parse args
  → emv_term_ctx_init + profile load
  → emv_terminal_run(ctx)
  → emv_term_session_save_json
  → print summary
```

## Edge Cases

- `--pin` with wrong length → reject before field on
- `--session` missing for `step cvm` → error with hint to run `step init` first
- Concurrent commands while field active → existing DropField behavior

## Failure Handling

Use `PrintAndLogEx(ERR, ...)` with actionable hints referencing EMV tag names.

Map ISO7816 SW to strings via existing `GetAPDUCodeDescription`.

## Security / Privacy Notes

- `--pin` on command line exposes PIN in shell history — document use of env var `EMV_TEST_PIN` as alternative for CI

## Acceptance Criteria

AC-API-001: `emv terminal run --help` lists all options with examples.

AC-API-002: `emv terminal profile validate` returns non-zero on malformed profile.

AC-API-003: `emv terminal run` on PM3 without 14a support fails with device capability message before USB timeout.

## Test Coverage Notes

- AUTO-API-001: cliparser arg validation
- AUTO-API-002: help text snapshot
- MAN-API-001: full CLI smoke on connected PM3Easy

## Open Questions

OQ-001: Opcode allocation for firmware assist — coordinate with `pm3_cmd.h` maintainers.
