# Automated Test Plan — EMV Terminal Emulator

## Test Framework Assumptions

- Existing EMV tests in `client/src/emv/test/` (`cryptotest`, `cda_test`, `dda_test`, `sda_test`)
- Host-side unit tests compile with client (`make client/test` pattern if present) or dedicated test target
- CI: Ubuntu workflow runs `tools/pm3_tests.sh`
- Hardware-in-loop tests optional; prefer APDU fixtures for CI

## Unit Test Coverage

| ID | Requirement | Test name (proposed) | File |
|----|-------------|----------------------|------|
| AUTO-CORE-001 | REQ-CORE-004 PDOL build | `test_terminal_pdol_build` | `terminal_phase_test.c` |
| AUTO-CORE-010 | Exec parity | `test_terminal_exec_apdu_parity_fixture` | `terminal_phase_test.c` |
| AUTO-CORE-020 | REQ-CORE-050 TAA table | `test_terminal_taa_denial_on_tvr` | `terminal_phase_test.c` |
| AUTO-CORE-030 | REQ-CORE-031 VERIFY APDU | `test_cvm_verify_plain_apdu` | `pin_verify_test.c` |
| AUTO-CORE-031 | REQ-CORE-032 enc PIN block | `test_cvm_enciphered_pin_block` | `pin_verify_test.c` |
| AUTO-DATA-001 | REQ-DATA-011 profile load | `test_terminal_profile_load` | `terminal_phase_test.c` |
| AUTO-DATA-002 | REQ-DATA-020 session export | `test_terminal_session_json_schema` | `terminal_phase_test.c` |
| AUTO-DATA-003 | REQ-DATA-040 PAN mask | `test_terminal_pan_mask` | `terminal_phase_test.c` |
| AUTO-SEC-001 | REQ-SEC-001 PIN zeroize | `test_pin_buffer_zeroized` | `pin_verify_test.c` |
| AUTO-SEC-002 | REQ-SEC-002 no PIN in JSON | `test_session_no_pin_tag` | `pin_verify_test.c` |
| AUTO-ERR-001 | REQ-ERR-002 SW strings | `test_sw_description_known_codes` | `terminal_phase_test.c` |
| AUTO-API-001 | cliparser | `test_terminal_cli_amount_parse` | `terminal_phase_test.c` |

## Integration Test Coverage

| ID | Description | Method |
|----|-------------|--------|
| AUTO-INT-001 | Full phase loop with recorded APDU trace | Replay fixture from `emv scan` capture |
| AUTO-INT-002 | CVM list walk multiple rules | Synthetic TLV 8E fixture |
| AUTO-INT-003 | `emv terminal run` end-to-end mock | Mock `Iso7816ExchangeEx` |
| AUTO-ADV-001 | CVM list parser on 8E fixtures | `terminal_cvm_test.c` |
| AUTO-ADV-002 | TAA: TVR+TAC → AAC/ARQC/TC | `terminal_taa_test.c` |
| AUTO-CRYPT-001 | CAPK parse including Interac 03/07 | `emv_pk` + capk.txt |
| AUTO-CRYPT-002 | PIN ISO9564 format 2 builder | `pin_verify_test.c` |
| AUTO-SCH-001 | GetCardPSVendor Interac AID | `emvcore` unit test |

## End-to-End Coverage

| ID | Description | Environment |
|----|-------------|-------------|
| AUTO-E2E-001 | PM3 connected qVSDC run | Hardware optional nightly |
| AUTO-E2E-002 | PIN VERIFY on hardware | Manual gate / lab runner |

## Fixtures / Mocks

```text
client/src/emv/test/fixtures/
├── qvsdc_gpo_response.bin
├── cvm_list_offline_pin.tlv
├── terminal_profile_min.json
└── session_expected_mvp.json
```

Mock transport: wrap `Iso7816ExchangeEx` with `--mock-apdu-file` (implement in Phase 2).

## CI Notes

Add to `tools/pm3_tests.sh`:

```bash
# EMV terminal unit tests (host only)
if [ -x client/emv_terminal_test ]; then
  client/emv_terminal_test || exit 1
fi
```

Extend existing `emv test` command to run terminal tests:

```
emv test --terminal
```

## Requirement-to-Test Mapping (summary)

| REQ range | Auto tests |
|-----------|------------|
| REQ-CORE-001–072 | AUTO-CORE-*, AUTO-INT-* |
| REQ-DATA-* | AUTO-DATA-* |
| REQ-SEC-* | AUTO-SEC-* |
| REQ-API-* | AUTO-API-* |
| REQ-ERR-* | AUTO-ERR-* |
| REQ-FW-* | AUTO-FW-001 (size script) |

## Existing Tests to Keep Passing

- `emv test` — crypto_test, cda_test, dda_test, sda_test
- No regression in `tools/pm3_tests.sh --long` client portion
