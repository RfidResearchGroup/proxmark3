# SPEC v2: Integration — sim, Lua, Reader, Contact

## Scope

Features **F-019**, **F-020**, **F-021**, **F-022**

---

## emv sim Bridge — REQ-INT-001–014

### REQ-INT-001

`emv terminal export-sim <session.json> -o <patch.json>` extracts card-side updates:

- ATC increment value used
- Last AC (9F26) if TC/AAC
- CVR/CVMR if changed
- Application cryptogram history for replay research

### REQ-INT-002

Output compatible with `emv sim` JSON merge (document field mapping in SPEC-data-model addendum).

### REQ-INT-003

`emv terminal run --export-sim patch.json` auto-export after complete.

### REQ-INT-004

Warning in output: replay research only; modern terminals reject replayed ARQC.

---

## Lua Script API — REQ-INT-020–029

### REQ-INT-020

Expose to Lua (follow existing `cmdlua` patterns):

```lua
emv_terminal_run(opts)   -- table: profile, amount, pin, output
emv_terminal_step(phase, opts)
emv_terminal_session_load(path)
emv_terminal_session_save(path)
```

### REQ-INT-021

Return table: `{ rc=0, outcome="approved_online", session_path="/tmp/s.json" }`.

### REQ-INT-022

Ship example `scripts/emv_terminal_demo.lua` in repo.

### REQ-INT-023

PIN never returned to Lua table.

---

## emv reader Alignment — REQ-INT-030–034

### REQ-INT-030

`emv reader --terminal-session <file>` passive sniff plus write observed APDUs to session phase log (read-only card analysis).

### REQ-INT-031

Optional `--terminal-compare` diff reader APDUs vs what terminal would send (educational).

### REQ-INT-032

Non-goal: full kernel in reader mode — log only in v2.

---

## Smartcard Contact Hardening — REQ-INT-040–049

### REQ-INT-040

On `-w` / `--wired` without smartcard mod: exit `PM3_EDEVNOTSUPP` before USB timeout (existing; verify message clarity).

### REQ-INT-041

Print ATR on contact init when `-a` enabled.

### REQ-INT-042

Profile hint: `interac contact TC01` documents CVM list `440301030203` in error when VERIFY fails.

### REQ-INT-043

Session field `Terminal.ATR` when contact used.

### REQ-INT-044

Document wiring in [SPEC-field-operations.md](./SPEC-field-operations.md) cross-link.

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-INT-001 | Completed session | export-sim | Valid patch.json |
| AC-INT-002 | demo.lua | script run | Outcome printed |
| AC-INT-003 | No smartcard mod | run -w | Immediate error |
| AC-INT-004 | Contact card | run -w -a | ATR in log |

---

## Files

| File | Purpose |
|------|---------|
| `emv_term_sim_export.c/h` | sim bridge |
| `lua/emv_terminal.lua` bindings | Lua |
| `scripts/emv_terminal_demo.lua` | example |
