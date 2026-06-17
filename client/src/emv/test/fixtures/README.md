# Golden Test Fixtures — EMV Terminal

Host-side regression fixtures for `emv terminal test --golden`.

## Layout

```text
fixtures/
├── README.md                    ← you are here
├── interac_tc01_arqc/           # Full mock APDU → ARQC → host-sim
├── interac_tc02_pin_fail/
├── taa_denial_expired/          # TLV-only, no APDU
├── visa_qvsdc_tc/
└── mc_arqc_online/
```

## Required files per fixture

| File | Purpose |
|------|---------|
| `README.md` | Card source, date, expected outcome, anonymization |
| `session_expected.json` | Baseline outcome + phases |
| `mock_apdu.json` | Optional — full APDU replay |
| `card_tlv.json` | Optional — preloaded card for load/step tests |
| `profile.json` | Optional — scheme override |

## Creating fixtures from hardware

```bash
# 1. Capture (lab card only — anonymize before commit)
./pm3 -- emv scan -at card_anonymized.json
./pm3 -- emv terminal run --record-apdu mock_apdu.json -o session_live.json ...

# 2. Copy to fixtures/<name>/
# 3. Trim session_live.json → session_expected.json (outcome + phases only)
# 4. Run: ./pm3 -- emv terminal test --fixture <name>
```

## Synthetic fixtures

TAA/CVM-only tests may use `card_tlv.json` built by hand — no real PAN.  
See `taa_denial_expired/` template in repo (add when implementing M9).

## CI

Fixtures run without USB. See [TEST-PLAN-v2-automated.md](../../docs/emv-terminal-emulator/TEST-PLAN-v2-automated.md).
