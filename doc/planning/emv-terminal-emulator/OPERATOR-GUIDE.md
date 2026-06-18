# EMV Terminal Emulator — Operator Guide

> **FOR RESEARCH AND LAB USE ONLY — NO WARRANTY — PROVIDED AS-IS**
>
> This tool is **not** a certified payment terminal. It does not implement PCI PTS POI requirements and must **not** be used on live payment networks, at merchants, or against cards you do not own or lack written authorization to test.
>
> See [SPEC-security-privacy.md](./SPEC-security-privacy.md) for PIN handling, redaction, and threat model.

---

## What you need

| Item | Notes |
|------|--------|
| Proxmark3 client | Built with `make client` (gcc recommended) |
| PM3 device | Optional for mock/golden tests; required for live cards |
| Test cards | EMV lab / personal test cards only |
| Terminal profile | `client/resources/emv_terminal_profile.json` or scheme profile (`--profile auto`) |

Check hardware support (no device required):

```bash
./pm3 --offline -c 'emv terminal capabilities'
```

---

## First run — legal acknowledgment

The first time you run a live terminal command (`run`, `step`, `online`, `host-sim`), the client prints an authorized-use banner and writes a timestamp to:

```text
~/.proxmark3/emv_terminal_ack
```

To skip the banner in automation (CI only):

```bash
export EMV_TERMINAL_I_ACK=1
```

Mock and golden tests suppress the banner automatically (`--mock-apdu-file`, `emv terminal test --golden`).

---

## Common workflows

### 1. Full contactless transaction (live card)

```bash
./pm3 -- emv terminal run -satj -o /tmp/session.json --qvsdc --profile auto
```

Flags:

- `-s` — activate field and select card
- `-a` — show APDUs (PIN data redacted by default)
- `-t` — TLV decode
- `-j` — load terminal profile JSON
- `-o` — write session JSON

### 2. Scheme-specific (Interac example)

```bash
./pm3 -- emv terminal run -j --profile interac --host-sim -o /tmp/session.json
```

### 3. Step-by-step debugging

```bash
./pm3 -- emv terminal step init -satj -o /tmp/session.json
./pm3 -- emv terminal step cvm --session /tmp/session.json --pin 1234 -o /tmp/session.json
./pm3 -- emv terminal step caa --session /tmp/session.json -o /tmp/session.json
./pm3 -- emv terminal online --session /tmp/session.json --host-sim -o /tmp/session.json
```

### 4. Offline testing from scan JSON

```bash
./pm3 -- emv scan -at card.json
./pm3 -- emv terminal load card.json -o card_session.json
./pm3 -- emv terminal step taa --session card_session.json -o out.json
```

### 5. Mock APDU replay (no USB)

```bash
./pm3 --offline -c 'emv terminal run --mock-apdu-file fixtures/foo/mock_apdu.json -j -o /tmp/s.json'
./pm3 --offline -c 'emv terminal replay fixtures/foo/mock_apdu.json --from-phase cvm --to-phase caa -o /tmp/s.json'
```

### 6. Host simulator (online completion)

```bash
# One-shot on existing session with ARQC
./pm3 -- emv terminal host-sim --session /tmp/session.json

# TCP mock acquirer (separate terminal)
./pm3 --offline -c 'emv terminal host listen 8583'
./pm3 -- emv terminal run -j --host-tcp 127.0.0.1:8583 -o /tmp/session.json
```

### 7. Session inspection and export

```bash
./pm3 --offline -c 'emv terminal session print /tmp/session.json'
./pm3 --offline -c 'emv terminal session merge scan.json session.json -o merged.json'
./pm3 --offline -c 'emv terminal export-sim session.json -o patch.json'
```

### 8. Trace and timing

```bash
./pm3 -- emv terminal run -satj --pcap-out /tmp/emv.pcap --timing-report -o /tmp/session.json
```

PCAP format: [doc/emv_pcap_format.md](../../doc/emv_pcap_format.md) (Wireshark linktype 265).

---

## PIN handling

| Method | Command / env |
|--------|----------------|
| CLI flag | `--pin 1234` (avoid in shared shell history) |
| Environment | `EMV_TEST_PIN=1234` (preferred for scripts) |
| Interactive | `emv terminal pin --prompt` |
| Skip online PIN CVM | `--cvm-skip-online` (sets TVR bit only) |

PIN buffers are zeroized after use. Session JSON does not include raw PIN by default.

---

## Session JSON and redaction

Default export **masks** PAN and **truncates** cryptograms. For lab-only full export:

```bash
./pm3 -- emv terminal run ... --no-redact --full-tlv -o session_full.json
# or
export EMV_TERMINAL_FULL_SESSION=1
```

Never commit unredacted session files with real card data to git.

---

## Regression testing (no hardware)

```bash
./pm3 --offline -c 'emv test'                      # unit tests incl. terminal crypto
./pm3 --offline -c 'emv terminal test --golden'    # 6/6 golden fixtures
./pm3 --offline -c 'emv terminal test --fixture taa_denial_expired'
```

Fixtures live in `client/src/emv/test/fixtures/`. See [fixtures README](../../client/src/emv/test/fixtures/README.md).

---

## Command reference (v2)

```text
emv terminal
├── run              Full phase loop
├── step             Single phase
├── online           Complete online after ARQC
├── pin              Standalone VERIFY PIN
├── profile          print | validate
├── load             Import card TLV from scan JSON
├── session          print | merge | export
├── host             listen (TCP) | sim (one-shot)
├── host-sim         Alias for host sim one-shot
├── export-sim       Card patch for emv sim research
├── test             --golden | --fixture <name>
├── replay           Mock APDU replay with phase range
└── capabilities     Device / build capability list
```

Full CLI flags: `emv terminal help` and [SPEC-v2-cli-ux.md](./SPEC-v2-cli-ux.md).

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `No 14a tag spotted` | Card position, `-s` select, try `-w` for contact |
| `SMARTCARD support` error | Contact path needs smartcard mod; use contactless or mock |
| CVM / PIN failure | Wrong PIN, use test card docs; try `emv terminal pin --offline` |
| ARQC online stuck | Pass `--host-sim`, `--host-tcp`, or `--arpc` |
| Golden test fail | Run from repo root; `CC=gcc make -C client` |

---

## Related documentation

- [README.md](./README.md) — overview and document map
- [SPEC-security-privacy.md](./SPEC-security-privacy.md) — security requirements
- [SPEC-v2-trace-replay.md](./SPEC-v2-trace-replay.md) — PCAP and replay
- [doc/emv_notes.md](../../doc/emv_notes.md) — all EMV commands
- [CHANGELOG.md](./CHANGELOG.md) — feature history
