# TEST-PLAN: Card timing benchmarks

## Automated (offline, `make client/check`)

### AC-TIME-001: CVM no prompt without PIN

- Fixture: CVM list `1F 00` only, AIP with CVM bit set, no `--pin`.
- `phase_cvm_run` → `PM3_SUCCESS`, `cvm_results[0] == 0x1F`.
- **Regression for:** `emv terminal run -s -j` on qVSDC / no-CVM cards must not call `getpass`.

### AC-TIME-002: AIP skips CVM

- AIP `8000` (no cardholder verification bit), CVM list with offline PIN rule.
- `phase_cvm_run` → success without VERIFY, no PIN.

### AC-TIME-003: Contactless offline PIN skipped

- Channel contactless, CVM list `01 00` then `1F 00`, terminal supports offline PIN.
- Walk skips `01`, succeeds on `1F` without PIN prompt.

### AC-TIME-004: Terminal caps precedence (existing)

- `test_terminal_caps_from_terminal_tree` — offline PIN skipped when 9F33 lacks support.

### AC-TIME-005: Online PIN stash (existing)

- `test_online_pin_stash` — online CVM stashes block when `--pin` provided.

### AC-TIME-006: EMV test suite

- `emv test` includes `exec_terminal_cvm_test`.

---

## Manual: RNG stream bench (hardware)

### AC-TIME-M01: Default 30 s bench

```bash
emv terminal crypto rng -s --bench
```

**Expect:**

- Progress every ~5 s (`blocks/s`, ok/fail counts).
- Summary: vendor, AID, path, throughput, latency percentiles.
- No stdout hex spam.

### AC-TIME-M02: JSON export

```bash
emv terminal crypto rng -s --bench --seconds 45 -o /tmp/visa-bench.json
```

**Expect:** JSON with `Card` + `Bench` sections; valid parse.

### AC-TIME-M03: Card comparison matrix

Run on lab wallet (see `examples/TEST-CARD-MATRIX.md`):

| Card | Notes |
|------|-------|
| CIBC Visa | qVSDC, expect higher `blocks_per_sec` |
| RBC Visa | qVSDC, compare p50 to CIBC |
| BMO MC | M/Chip, expect lower throughput |
| Koho prepaid MC | M/Chip |
| BMO Interac | CDOL1 path, try `-d tc` if ARQC declines |

Record `BlocksPerSec`, `CycleMsP50`, `CryptoPath` in spreadsheet.

### AC-TIME-M04: Early stop

- Start bench, press Enter before 30 s.
- Elapsed time &lt; configured seconds; partial stats still printed.

---

## Manual: Terminal run phase timing (hardware)

### AC-TIME-M10: Full run timing report

```bash
emv terminal run -s -j --qvsdc --timing-report -o /tmp/run-cibc.json
```

**Expect:**

- Console: `Timing: Total: … ms (init=…, cvm=…, …)`.
- Session JSON: each `PhaseEvents[]` entry has `duration_ms`.

### AC-TIME-M11: No PIN prompt on contactless Visa

```bash
emv terminal run -s -j --qvsdc --timing-report
```

**Without** `--pin` on qVSDC Visa:

- Must **not** show `Enter offline PIN:`.
- CVM phase completes (skip or no-CVM).

### AC-TIME-M12: PIN still works when required

Contact card with offline PIN CVM:

```bash
emv terminal run -s -j -w --pin 1234 --timing-report
```

**Expect:** VERIFY attempted, timing includes `cvm` &gt; 0.

### AC-TIME-M13: Stop-after isolates phase

```bash
emv terminal run -s -j --stop-after init --timing-report -o /tmp/init-only.json
emv terminal run -s -j --stop-after caa --timing-report -o /tmp/to-caa.json
```

Compare `init` duration vs cumulative time to `caa`.

---

## Manual: Cross-command comparison

### AC-TIME-M20: RNG bench vs terminal `caa`

On same card, same session:

1. `emv terminal crypto rng -s --bench --seconds 30`
2. `emv terminal run -s -j --qvsdc --timing-report`

Document:

- RNG `cycle_ms_p50` ≈ order-of-magnitude with sum of init + caa portions (not exact — different fast-path).

---

## Regression

- `emv terminal run` outcome unchanged for cards that need `--pin` on contact.
- `emv terminal cvm -s --run --offline <pin>` unchanged.
- `--stream` RNG unaffected.

---

## Future automated (when `emv terminal bench` lands)

### AC-TIME-F01: Mock APDU timing replay

- Fixture with recorded phase durations; JSON export golden file compare.

### AC-TIME-F02: Multi-card CI

- Not feasible on hardware CI; keep manual matrix in `examples/TEST-CARD-MATRIX.md`.
