# Automated Test Plan v2 — EMV Terminal Emulator

## Framework

- Host unit tests compile with client (`client/src/emv/test/`)
- Golden fixtures: `client/src/emv/test/fixtures/`
- CI: `tools/pm3_tests.sh` + optional GitHub Actions
- Mock transport: no USB required for ≥80% of v2 auto tests

Run commands:

```bash
./pm3 -- emv test --terminal
./pm3 -- emv terminal test --golden
./pm3 -- emv terminal test --fixture interac_tc01_arqc
```

---

## Unit Tests by Feature

### F-001 / F-011 Host Simulator (AUTO-V2-001–015, 063–070, 122–128)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-001 | `test_arqc_verify_interac_ok` | `terminal_host_test.c` | REQ-HOST-011 |
| AUTO-V2-002 | `test_arqc_verify_interac_fail` | `terminal_host_test.c` | REQ-HOST-005 |
| AUTO-V2-003 | `test_arpc_compute_cvn18` | `terminal_host_test.c` | REQ-HOST-020 |
| AUTO-V2-004 | `test_arpc_rc_interac_8840` | `terminal_host_test.c` | REQ-HOST-003 |
| AUTO-V2-005 | `test_host_keys_json_load` | `terminal_host_test.c` | REQ-HOST-002 |
| AUTO-V2-006 | `test_arc_approve_bcd` | `terminal_host_test.c` | REQ-HOST-021 |
| AUTO-V2-007 | `test_arc_decline` | `terminal_host_test.c` | REQ-HOST-022 |
| AUTO-V2-008 | `test_manual_arpc_override` | `terminal_host_test.c` | REQ-HOST-023 |
| AUTO-V2-009 | `test_host_response_json` | `terminal_host_test.c` | REQ-HOST-041 |
| AUTO-V2-010 | `test_cdol2_injection` | `terminal_host_test.c` | REQ-HOST-040 |
| AUTO-V2-063 | `test_arqc_visa_cvn10_vector` | `terminal_host_test.c` | REQ-HOST-012 |
| AUTO-V2-064 | `test_arqc_mc_vector` | `terminal_host_test.c` | REQ-HOST-011 |
| AUTO-V2-122 | `test_tcp_host_protocol_parse` | `terminal_host_test.c` | REQ-HOST-051 |
| AUTO-V2-123 | `test_tcp_auth_approve` | `terminal_host_test.c` | REQ-HOST-052 |

### F-002 / F-015 / F-024 / F-036 Scheme (AUTO-V2-016–025, 084–088, 129–133, 167–169)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-016 | `test_profile_interac_load` | `terminal_scheme_test.c` | REQ-SCH-001 |
| AUTO-V2-017 | `test_profile_visa_ttq` | `terminal_scheme_test.c` | REQ-SCH-020 |
| AUTO-V2-018 | `test_profile_auto_interac_aid` | `terminal_scheme_test.c` | REQ-SCH-003 |
| AUTO-V2-019 | `test_profile_auto_visa_aid` | `terminal_scheme_test.c` | REQ-SCH-003 |
| AUTO-V2-020 | `test_kernel_dispatch_mc` | `terminal_scheme_test.c` | REQ-SCH-013 |
| AUTO-V2-021 | `test_kernel_dispatch_visa_gpo_ac` | `terminal_scheme_test.c` | REQ-SCH-012 |
| AUTO-V2-022 | `test_interac_flash_cvm_skip` | `terminal_scheme_test.c` | REQ-SCH-040 |
| AUTO-V2-023 | `test_msd_aip_branch` | `terminal_scheme_test.c` | REQ-SCH-050 |
| AUTO-V2-084 | `test_ttq_merge_profile` | `terminal_scheme_test.c` | REQ-SCH-020 |
| AUTO-V2-129 | `test_kernel_enum_log` | `terminal_scheme_test.c` | REQ-SCH-015 |

### F-003 / F-006 / F-029 CVM (AUTO-V2-026–030, 041–045, 145–148, 177–180)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-026 | `test_online_pin_tvr_bit` | `pin_verify_test.c` | REQ-HOST-031 |
| AUTO-V2-027 | `test_online_pin_cdol_stash` | `pin_verify_test.c` | REQ-HOST-032 |
| AUTO-V2-028 | `test_cvm_fail_3f` | `terminal_cvm_test.c` | REQ-CVM-032 |
| AUTO-V2-029 | `test_cvm_amount_rule` | `terminal_cvm_test.c` | REQ-CVM-033 |
| AUTO-V2-041 | `test_pin_prompt_non_tty` | `terminal_pin_test.c` | REQ-CVM-002 |
| AUTO-V2-042 | `test_enciphered_pin_block` | `pin_verify_test.c` | REQ-CVM-012 |
| AUTO-V2-043 | `test_apdu_log_pin_redact` | `terminal_pin_test.c` | REQ-CVM-022 |
| AUTO-V2-145 | `test_pin_secure_zero` | `pin_verify_test.c` | REQ-CVM-020 |
| AUTO-V2-146 | `test_session_no_pin_field` | `pin_verify_test.c` | REQ-CVM-023 |

### F-004 / F-005 / F-010 / F-028 Data (AUTO-V2-031–040, 059–062, 141–144, 170–172)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-031 | `test_script71_success` | `terminal_scripts_test.c` | REQ-DAT-002 |
| AUTO-V2-032 | `test_script71_fail_tvr` | `terminal_scripts_test.c` | REQ-DAT-003 |
| AUTO-V2-033 | `test_script72_after_ac2` | `terminal_scripts_test.c` | REQ-DAT-005 |
| AUTO-V2-034 | `test_script_multi_86` | `terminal_scripts_test.c` | REQ-DAT-006 |
| AUTO-V2-036 | `test_session_merge_ok` | `terminal_session_test.c` | REQ-DAT-020 |
| AUTO-V2-037 | `test_session_merge_aid_mismatch` | `terminal_session_test.c` | REQ-DAT-024 |
| AUTO-V2-038 | `test_full_tlv_export` | `terminal_session_test.c` | REQ-DAT-022 |
| AUTO-V2-059 | `test_session_print_tvr_bits` | `terminal_session_test.c` | REQ-DAT-031 |
| AUTO-V2-141 | `test_redact_ac_default` | `terminal_session_test.c` | REQ-DAT-040 |
| AUTO-V2-142 | `test_redact_no_redact_flag` | `terminal_session_test.c` | REQ-DAT-041 |

### F-007 / F-008 / F-030 CLI (AUTO-V2-046–052, 149, 176)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-046 | `test_cli_amount_bcd` | `terminal_cli_test.c` | REQ-CLI-001 |
| AUTO-V2-047 | `test_cli_invalid_amount` | `terminal_cli_test.c` | REQ-CLI-002 |
| AUTO-V2-048 | `test_cli_date_override` | `terminal_cli_test.c` | REQ-CLI-001 |
| AUTO-V2-051 | `test_forced_aid_parse` | `terminal_cli_test.c` | REQ-CLI-020 |
| AUTO-V2-149 | `test_banner_ack_file` | `terminal_cli_test.c` | REQ-CLI-031 |

### F-012 / F-013 / F-026 ODA (AUTO-V2-071–080, 137–140)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-071 | `test_capk_extra_merge` | `terminal_oda_test.c` | REQ-ODA-001 |
| AUTO-V2-072 | `test_unknown_ca_index_tvr` | `terminal_oda_test.c` | REQ-ODA-004 |
| AUTO-V2-076 | `test_fdda_sdad_verify` | `terminal_oda_test.c` | REQ-ODA-023 |
| AUTO-V2-137 | `test_cda_verify_ac1` | `cda_test.c` extension | REQ-ODA-030 |
| AUTO-V2-138 | `test_oda_list_from_scan` | `terminal_oda_test.c` | REQ-ODA-040 |

### F-014 Risk (AUTO-V2-081–083)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-081 | `test_exception_file_hit` | `terminal_risk_test.c` | REQ-RISK-003 |
| AUTO-V2-082 | `test_exception_file_miss` | `terminal_risk_test.c` | REQ-RISK-004 |
| AUTO-V2-083 | `test_exception_bad_line` | `terminal_risk_test.c` | REQ-RISK-006 |

### F-009 / F-016 / F-017 / F-032 Testing (AUTO-V2-053–058, 089–105, 153–160)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-053 | `test_apdu_compare_equal` | `terminal_compare_test.c` | REQ-TST-040 |
| AUTO-V2-054 | `test_apdu_compare_diff` | `terminal_compare_test.c` | REQ-TST-042 |
| AUTO-V2-089 | `test_mock_apdu_match` | `terminal_mock_apdu_test.c` | REQ-TST-003 |
| AUTO-V2-090 | `test_mock_apdu_unmatched` | `terminal_mock_apdu_test.c` | REQ-TST-003 |
| AUTO-V2-091 | `test_mock_strict_extra` | `terminal_mock_apdu_test.c` | REQ-TST-004 |
| AUTO-V2-096 | `test_golden_interac_tc01` | `terminal_golden_test.c` | REQ-TST-022 |
| AUTO-V2-097 | `test_golden_taa_denial` | `terminal_golden_test.c` | REQ-TST-022 |
| AUTO-V2-098 | `test_golden_all` | `terminal_golden_test.c` | REQ-TST-030 |
| AUTO-V2-106 | `test_firmware_size_script` | shell CI | REQ-TST-050 |
| AUTO-V2-153 | `test_batch_runner_exit_code` | `terminal_golden_test.c` | REQ-TST-031 |

### F-019 / F-020 Integration (AUTO-V2-109–115)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-109 | `test_sim_export_schema` | `terminal_sim_test.c` | REQ-INT-001 |
| AUTO-V2-113 | `test_lua_terminal_run_smoke` | lua tests | REQ-INT-020 |

### F-031 / F-033 / F-035 Trace (AUTO-V2-150–152, 161–165, 166)

| ID | Test function | File | Validates |
|----|---------------|------|-----------|
| AUTO-V2-150 | `test_pcap_write_records` | `terminal_pcap_test.c` | REQ-TRC-002 |
| AUTO-V2-161 | `test_replay_outcome` | `terminal_replay_test.c` | REQ-TRC-020 |
| AUTO-V2-166 | `test_phase_timing_fields` | `terminal_session_test.c` | REQ-TRC-032 |

### Existing (retain)

| ID | Test | File |
|----|------|------|
| AUTO-ADV-002 | TAA denial | `terminal_taa_test.c` |
| AUTO-CORE-030 | VERIFY APDU | `pin_verify_test.c` |
| AUTO-SEC-001 | PIN zeroize | `pin_verify_test.c` |

---

## Golden Fixture Specification

Each fixture directory **must** contain:

| File | Required | Purpose |
|------|----------|---------|
| `README.md` | Yes | Provenance, expected outcome |
| `mock_apdu.json` | For full pipeline | APDU trace |
| `card_tlv.json` | For load-only tests | Preloaded card |
| `session_expected.json` | Yes | Assertion baseline |
| `profile.json` | Optional | Override scheme profile |

### Fixture catalog (initial)

| Name | Type | Outcome |
|------|------|---------|
| `interac_tc01_arqc` | mock APDU | online_required → approved_online |
| `interac_tc02_pin_fail` | mock APDU | declined |
| `taa_denial_expired` | TLV only | declined AAC |
| `visa_qvsdc_tc` | mock APDU | approved_offline |
| `mc_arqc_online` | mock APDU | online_required |
| `script71_fail` | mock + host | declined script TVR |

---

## CI Pipeline (proposed)

```yaml
# .github/workflows/emv-terminal-v2.yml
jobs:
  host-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make -C client -j
      - run: ./pm3 --offline -c 'emv test --terminal'
      - run: ./pm3 --offline -c 'emv terminal test --golden'
  firmware-size:
    runs-on: ubuntu-latest
    steps:
      - run: make -C arms PLATFORM=PM3GENERIC PLATFORM_SIZE=256
      - run: ./tools/check_firmware_size.sh 262144
```

---

## Coverage Targets

| Milestone | Unit tests | Golden fixtures | Mock E2E |
|-----------|------------|-----------------|----------|
| M7 | 15+ host crypto | 1 Interac | — |
| M8 | 10+ scheme | +2 scheme | — |
| M9 | 20+ mock/golden | 6 total | 4 full |
| M10–M14 | +30 cumulative | 10 total | 6 full |

**Goal:** ≥85% REQ-v2 IDs have at least one AUTO-V2 test before `emv-term-v2.0` tag.

---

## Mapping to pm3_tests.sh

```bash
# Host-only (no device)
CheckExecute "emv terminal golden" "$CLIENTBIN -c 'emv terminal test --golden'" "Golden:"
CheckExecute "emv test terminal" "$CLIENTBIN -c 'emv test --terminal'" "Tests ( ok"

# Device optional (nightly)
CheckExecute "emv terminal host-sim smoke" "$CLIENTBIN -c 'emv terminal run ...'" "approved_online"
```

---

## Negative Tests

| ID | Scenario | Expected |
|----|----------|----------|
| AUTO-NEG-001 | Empty mock file | PM3_ESOFT |
| AUTO-NEG-002 | Golden tampered outcome | Test fail with diff |
| AUTO-NEG-003 | Host keys missing | Clear error |
| AUTO-NEG-004 | Merge wrong AID | PM3_EINVARG |
| AUTO-NEG-005 | PCAP path not writable | PM3_ESOFT |
