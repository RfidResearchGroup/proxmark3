# SPEC: Card timing benchmarks (terminal + crypto RNG)

## Purpose

Measure **how fast a payment card responds** under repeatable lab conditions so operators can compare:

- Issuer / bank (CIBC vs RBC Visa, BMO MC, Koho prepaid, Interac)
- Chip family / form factor (contactless vs contact, qVSDC vs M/Chip)
- Operation type (field cycle, init, CVM, GEN AC, full terminal run)

This is **research / lab timing only** — not a certification or performance SLA.

---

## Layers

| Layer | Command | Granularity | Status |
|-------|---------|-------------|--------|
| **RNG stream cycle** | `emv terminal crypto rng -s --bench` | One field reselect + init + GEN AC + hash output | **Implemented** |
| **Terminal phase** | `emv terminal run -j --timing-report -o session.json` | Per-phase `duration_ms` in session events | **Implemented** |
| **Unified compare** | `emv terminal bench` (future) | Multi-mode report + JSON schema v2 | Planned |
| **APDU sub-step** | `--apdu` + pcap / mock replay | Individual CAPDU/RAPDU | Future |

---

## REQ-TIME-001: RNG stream bench

Command:

```text
emv terminal crypto rng -s --bench [--seconds <n>] [-o <file.json>]
```

### Behavior

- Hold card on antenna for `seconds` (default **30**).
- Each **cycle** = contactless reselect + transaction init (fast path when cached) + one RNG sample (GEN AC or qVSDC GPO path).
- Suppress entropy output; print human summary + optional JSON.

### Metrics (successful cycles)

| Metric | Description |
|--------|-------------|
| `blocks_per_sec` | Successful cycles / elapsed wall time |
| `bytes_per_sec` | `blocks_per_sec × out_bytes` (default 8) |
| `cycle_ms_min/avg/p50/p95/max` | Full cycle latency |
| `cycles_ok` / `cycles_fail` | GEN AC / init failures |
| `fast_init_cycles` / `full_init_cycles` | Warm vs cold init mix |

### Card fingerprint (JSON `Card` object)

- `AID`, `Vendor`, `CryptoPath`, `AIP`
- `ApplicationLabel`, `PANLast4` (when track2 present)

---

## REQ-TIME-002: Terminal run phase timing

Command:

```text
emv terminal run -s -j --timing-report -o /tmp/session.json [--stop-after <phase>]
```

### Behavior

- `emv_terminal_step` records `duration_ms` per phase when `--timing-report` is set.
- Session JSON `PhaseEvents[]` includes `duration_ms` per phase id.
- Console summary: `Timing: Total: N ms (init=…, cvm=…, caa=…)`.

### Phases measured

| Phase | Typical work |
|-------|----------------|
| `init` | SELECT, GPO, READ RECORD (AFL) |
| `oda` | SDA/DDA/CDA data retrieval |
| `restrict` | Exception file, velocity checks |
| `cvm` | CVM list walk, VERIFY if applicable |
| `trm` | Terminal risk management |
| `taa` | Terminal action analysis |
| `caa` | GENERATE AC (first cryptogram) |
| `online` | Host / ARQC stub |
| `complete` | Second GEN AC, script, cleanup |

### Comparison workflow

Run the same amount/profile on each card:

```bash
emv terminal run -s -j --timing-report -o bench/cibc-visa.json --qvsdc
emv terminal run -s -j --timing-report -o bench/rbc-visa.json --qvsdc
emv terminal run -s -j --timing-report -o bench/bmo-mc.json --qvsdc
```

Extract `PhaseEvents[].duration_ms` from JSON or use printed summary.

---

## REQ-TIME-003: Comparison schema (JSON)

RNG bench export (`emv terminal crypto rng --bench -o`) uses:

```json
{
  "File": { "Created": "proxmark3 emv terminal crypto rng bench", "Version": "1" },
  "Card": { "AID", "Vendor", "CryptoPath", "AIP", "ApplicationLabel", "PANLast4" },
  "Bench": {
    "DurationMs", "CyclesOk", "CyclesFail",
    "BlocksPerSec", "BytesPerSec",
    "CycleMsMin", "CycleMsAvg", "CycleMsP50", "CycleMsP95", "CycleMsMax",
    "FastInitCycles", "FullInitCycles"
  }
}
```

Future **terminal bench** export shall add `Phases: { "init": ms, "caa": ms, ... }` and `TotalMs`.

---

## REQ-TIME-004: Fairness rules

1. Same physical setup: antenna, card position, PM3 firmware build.
2. Same CLI profile: `-j`, same `--qvsdc` / `--amount`, same `--decision`.
3. Report **median (p50)** for noisy contactless links; use `--seconds 60` for RNG bench when comparing close cards.
4. Note **fast_init ratio** — first cycle is always slower (PPSE + AFL).
5. Do not compare RNG bench `blocks_per_sec` directly to terminal `caa` phase ms (different code paths).

---

## REQ-TIME-005: Future unified bench (planned)

Proposed command:

```text
emv terminal bench -s -j [--seconds 30] [--modes rng,run] [-o bench.json]
```

- `--modes rng` — existing crypto RNG bench
- `--modes run` — one full terminal run with phase timing
- `--modes all` — both back-to-back on same tap session

Out of scope for initial delivery; documented here for test-plan alignment.

---

## Related fixes

### REQ-CVM-040 (PIN prompt gating)

`emv terminal run` shall **not** interactively prompt for PIN when:

- AIP indicates cardholder verification not supported (AIP byte 1 bit 5 clear), or
- No applicable CVM rule requires offline VERIFY on this channel, or
- Contactless + offline PIN rule (VERIFY not supported over NFC in lab), or
- Enciphered offline PIN without `9F2D` on card.

Prompt only when a **contact** offline PIN rule is reached and `--pin` / `EMV_TEST_PIN` are absent.

---

## Files

| File | Role |
|------|------|
| `emv_term_crypto.c` | RNG `--bench` implementation |
| `emv_terminal.c` | Phase `duration_ms` collection |
| `emv_term_timing.c` | Timing summary print |
| `emv_term_session.c` | Session JSON phase events |
| `phase_cvm.c` | Lazy PIN prompt / skip unverifiable CVM |
