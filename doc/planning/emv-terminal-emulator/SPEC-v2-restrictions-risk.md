# SPEC v2: Restrictions, Exception File, TRM Extensions

## Scope

Feature **F-014**

---

## Exception File — REQ-RISK-001–014

### REQ-RISK-001

CLI `--exception-file <path>` on `run` and `step restrict`.

### REQ-RISK-002

File format (text, one entry per line):

```
# SHA-256 of PAN (hex), or masked PAN prefix
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Alternative v2 line format: `panhash:<hex>` or `pan:<12-19 digits>` (hashed internally).

### REQ-RISK-003

Before TAA (in `phase_restrict` or dedicated check), if PAN (`5A` or from track 2) matches entry:

- Set TVR byte 1 bit 0x10 (card on exception file)
- Log `PAN on exception file`

### REQ-RISK-004

Default behavior without file: exception check **pass** (stub open file).

### REQ-RISK-005

TAA denial TAC should trigger AAC when exception bit set (verify with test fixture).

### REQ-RISK-006

Exception file path recorded in session `Terminal.ExceptionFile`.

---

## TRM Extensions (optional v2.2)

### REQ-RISK-010

Profile field `RandomTransactionSelect` enables random floor exceed simulation (1–99% per EMV Book 3).

### REQ-RISK-011

Log selected random threshold when triggered.

---

## Sample File

See `examples/exception_file_sample.txt`:

```text
# Lab exception file — PAN SHA-256
# Generate: echo -n "4111111111111111" | sha256sum
a1b2c3d4...
```

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-RISK-001 | PAN in exception file | restrict → taa → caa | AAC |
| AC-RISK-002 | No exception file | run | No exception TVR bit |
| AC-RISK-003 | Bad hash line | load file | Warning, line skipped |

---

## Files

| File | Purpose |
|------|---------|
| `phase_restrict.c` | Exception lookup |
| `emv_term_exception.c/h` | Hash file loader |
