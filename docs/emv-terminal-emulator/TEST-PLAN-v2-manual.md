# Manual Test Plan v2 — EMV Terminal Emulator

## Prerequisites

- PM3 with HF 14a; SMARTCARD mod for contact tests
- Test cards: Interac TC01–04 (or subset), Visa qVSDC, MC M/Chip (minimum one each)
- Terminal profiles and keys in `docs/emv-terminal-emulator/examples/`
- Client built with v2 features (see [MILESTONES-v2.md](./MILESTONES-v2.md))

## Legend

| Status | Meaning |
|--------|---------|
| Not Run | — |
| Pass | — |
| Fail | — |
| N/A | No hardware |

---

## M7 — Host Simulator (MAN-V2-001–010)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-001 | Host-sim approve | `run -j --profile interac --host-sim -o s.json` on TC01 CL | `approved_online`, EXTERNAL AUTH OK | Not Run |
| MAN-V2-002 | Host-sim ARQC log | Same with `-a` | `ARQC verify: OK` in log | Not Run |
| MAN-V2-003 | Bad key | `--host-keys` with wrong master key | Verify FAIL, no silent approve | Not Run |
| MAN-V2-004 | Manual ARPC override | `online --arpc <hex>` | Uses provided ARPC | Not Run |
| MAN-V2-005 | Decline ARC | `host-sim --arc 05` | AC2 AAC, declined | Not Run |
| MAN-V2-006 | Interac ARPC-RC | Contact TC01 | Tag 91 ends with 8840 | Not Run |
| MAN-V2-007 | Host-sim one-shot | `host-sim --session s.json` after ARQC run | Completes online | Not Run |
| MAN-V2-008 | Visa ARQC | Visa card + `--profile visa --host-sim` | Online complete or documented CVN gap | Not Run |
| MAN-V2-009 | Host response file | `--host-response approve.json` | ARC/ARPC from file | Not Run |
| MAN-V2-010 | Continue bad ARQC | `--continue-on-bad-arqc` | Logs FAIL, behavior documented | Not Run |

---

## M8 — Scheme Profiles (MAN-V2-011–020)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-011 | Profile interac | `run -j --profile interac` | Interac TACs used in TAA log | Not Run |
| MAN-V2-012 | Profile visa | `--profile visa` on Visa AID | TTQ from profile | Not Run |
| MAN-V2-013 | Profile mc | `--profile mc` on MC AID | GET CHALLENGE if required | Not Run |
| MAN-V2-014 | Profile auto Interac | `--profile auto` + Interac card | Loads interac | Not Run |
| MAN-V2-015 | Profile auto Visa | `--profile auto` + Visa | Loads visa | Not Run |
| MAN-V2-016 | Flash CVM skip | Interac CL TC01 | No VERIFY APDU | Not Run |
| MAN-V2-017 | Contact VERIFY | Interac contact TC01 `--pin 1111` | VERIFY SW 9000 | Not Run |
| MAN-V2-018 | Kernel log | `-a --trace-phases` | `Kernel: ...` line | Not Run |
| MAN-V2-019 | Profile validate all | `profile validate client/resources/scheme_profiles/*.json` | All valid | Not Run |
| MAN-V2-020 | Wrong profile | MC card + `--profile visa` | Degraded but no crash | Not Run |

---

## M10 — CVM / PIN (MAN-V2-021–040, 120–122, 147–150)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-021 | Online PIN TVR | Card with CVM 02, no host | TVR online PIN bit | Not Run |
| MAN-V2-022 | Online PIN + host | CVM 02 + host-sim | CDOL2 includes PIN-related tags if required | Not Run |
| MAN-V2-023 | Wrong offline PIN | TC02 `--pin 9999` | VERIFY fail, CVMR fail | Not Run |
| MAN-V2-024 | Enciphered PIN | Card supporting CVM 04 | VERIFY or documented skip | Not Run |
| MAN-V2-025 | CVM skip online flag | `--cvm-skip-online` | No PIN block sent | Not Run |
| MAN-V2-036 | Interactive PIN | `run` without `--pin` on PIN card | Prompt no echo | Not Run |
| MAN-V2-037 | EMV_TEST_PIN | `EMV_TEST_PIN=1111 run` | No prompt | Not Run |
| MAN-V2-038 | CI non-TTY | piped stdin | Clear error | Not Run |
| MAN-V2-039 | PIN in APDU log | `pin --offline 1234 -a` | REDACTED in log | Not Run |
| MAN-V2-040 | PIN not in session | save session | No pin field | Not Run |
| MAN-V2-120 | Zeroize audit | `emv test --pin-audit` | Pass | Not Run |
| MAN-V2-121 | After failed VERIFY | memory check via test | Buffers zero | Not Run |
| MAN-V2-122 | Session + pin cmd | pin then save | No leak | Not Run |
| MAN-V2-147 | TC01 Flash | CL Interac | Skip VERIFY | Not Run |
| MAN-V2-148 | TC03 PIN | contact `--pin 3333` | OK | Not Run |
| MAN-V2-149 | TC04 wrong | `--pin 0000` | Fail | Not Run |
| MAN-V2-150 | Profile matrix doc | Follow TEST-CARD-MATRIX.md | All rows checked | Not Run |

---

## M11 — Scripts / Session (MAN-V2-026–035, 053–055, 117–119)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-026 | Script 71 OK | Host response with valid script | SW 9000 each cmd | Not Run |
| MAN-V2-027 | Script 71 fail | Bad script in response | TVR bit before AC | Not Run |
| MAN-V2-028 | Script 72 OK | After AC2 | TSI script bit | Not Run |
| MAN-V2-029 | Script 72 fail | Inject fail script | TVR after AC bit | Not Run |
| MAN-V2-030 | Multi 86 | Chained commands | All sent in order | Not Run |
| MAN-V2-031 | Merge scan+session | `session merge scan.json s.json` | Valid out | Not Run |
| MAN-V2-032 | Merge AID mismatch | Different AIDs | Error | Not Run |
| MAN-V2-033 | Full TLV export | `run --full-tlv` | Card.TLV in JSON | Not Run |
| MAN-V2-034 | Load + merge session | `load --merge-session` | Phases restored | Not Run |
| MAN-V2-035 | emv sim import | merge → sim research | Documented path works | Not Run |
| MAN-V2-053 | Session print | `session print s.json` | Human readable | Not Run |
| MAN-V2-054 | TVR decode | print output | Bit labels | Not Run |
| MAN-V2-055 | Session print JSON | `--json` | Enriched output | Not Run |
| MAN-V2-117 | Default redact | save session | AC truncated | Not Run |
| MAN-V2-118 | --no-redact | full AC in file | Warning shown | Not Run |
| MAN-V2-119 | Redact track2 | export | 57 masked | Not Run |

---

## M9 — Testing / CI (MAN-V2-041–052, 079–086, 126)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-041 | Amount override | `--amount 500` | 9F02 correct in TLV | Not Run |
| MAN-V2-042 | Currency | `--currency 124` | 5F2A set | Not Run |
| MAN-V2-043 | Date | `--date 260616` | 9A set | Not Run |
| MAN-V2-044 | Txn type | `--type 01` | 9C cash | Not Run |
| MAN-V2-045 | Invalid amount | `--amount abc` | PM3_EINVARG | Not Run |
| MAN-V2-046 | Force AID | `--aid A0000000031010 --forceaid` | Selected AID | Not Run |
| MAN-V2-047 | Forceaid search | `--forceaid` no PPSE | Search list | Not Run |
| MAN-V2-048 | Session forced flag | export | ForcedAID true | Not Run |
| MAN-V2-049 | Record APDU | `run --record-apdu t.json` | Trace file | Not Run |
| MAN-V2-050 | Mock replay | `run --mock-apdu-file t.json` | No card needed | Not Run |
| MAN-V2-051 | Compare exec | `compare exec.json term.json` | Exit 0 same card | Not Run |
| MAN-V2-052 | Compare diff | Alter terminal trace | Exit 1 diff | Not Run |
| MAN-V2-079 | Golden all | `terminal test --golden` | 100% pass | Not Run |
| MAN-V2-080 | Single fixture | `test --fixture taa_denial` | Pass | Not Run |
| MAN-V2-081 | pm3_tests.sh | `./tools/pm3_tests.sh client` | Golden line pass | Not Run |
| MAN-V2-082 | Record from scan | scan + record | Valid mock | Not Run |
| MAN-V2-083 | Mock strict | unexpected APDU | Fail in strict mode | Not Run |
| MAN-V2-086 | PM3Easy size | CI artifact | Under limit | Not Run |
| MAN-V2-126 | Batch after change | run golden before PR | No regressions | Not Run |

---

## M12 — ODA / Risk (MAN-V2-061–073)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-061 | CAPK extra | `--capk-extra` with Interac key | ODA success | Not Run |
| MAN-V2-062 | Unknown CA index | Card with missing CAPK | TVR + warning | Not Run |
| MAN-V2-063 | fDDA qVSDC | Visa CL fDDA card | SDAD verify log | Not Run |
| MAN-V2-064 | CDA verify OK | `--qvsdccda` | CDAVerify ok in session | Not Run |
| MAN-V2-065 | CDA verify fail | tampered fixture | TVR CDA fail | Not Run |
| MAN-V2-066 | Load + ODA | load scan, step oda mock | ODA without live read | Not Run |
| MAN-V2-071 | Exception hit | PAN in exception file | AAC path | Not Run |
| MAN-V2-072 | Exception miss | Not in file | Normal path | Not Run |
| MAN-V2-073 | Bad exception line | corrupt file | Warning skip | Not Run |

---

## M13 — Integration (MAN-V2-087–113, 101–105)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-087 | export-sim | after run | patch.json | Not Run |
| MAN-V2-088 | sim merge | patch + sim | Documented workflow | Not Run |
| MAN-V2-091 | Lua demo | `script run emv_terminal_demo.lua` | Success | Not Run |
| MAN-V2-094 | reader session | `reader --terminal-session s.json` | APDU log | Not Run |
| MAN-V2-097 | No smartcard | `run -w` without mod | PM3_EDEVNOTSUPP | Not Run |
| MAN-V2-098 | Contact ATR | `run -w -a` | ATR logged | Not Run |
| MAN-V2-101 | TCP host listen | `host --listen 8583` | Listening | Not Run |
| MAN-V2-102 | TCP auth | `run --host-tcp` + host | Online OK | Not Run |
| MAN-V2-103 | TCP decline | host returns decline | AAC | Not Run |
| MAN-V2-111 | MSD path | MSD card | Track2 approve | Not Run |
| MAN-V2-112 | MSD warning | MSD log | Deprecation note | Not Run |

---

## M14 — Trace / Polish (MAN-V2-123–136)

| ID | Test | Steps | Expected | Status |
|----|------|-------|----------|--------|
| MAN-V2-123 | Legal banner | first run | Shown once | Not Run |
| MAN-V2-124 | PCAP export | `--pcap-out x.pcap` | Wireshark opens | Not Run |
| MAN-V2-125 | PCAP redact | with PIN | No PIN in pcap | Not Run |
| MAN-V2-127 | Replay full | `replay mock.json` | Expected outcome | Not Run |
| MAN-V2-128 | Replay from cvm | `--from-phase cvm` | Skips init | Not Run |
| MAN-V2-136 | Timing report | `--timing-report` | durations in JSON | Not Run |
| MAN-V2-146 | capabilities | `terminal capabilities` | Lists features | Not Run |

---

## Regression Smoke (run before every release tag)

1. `emv terminal test --golden`
2. `emv terminal profile validate` all scheme profiles
3. `emv test --terminal`
4. One live CL transaction with `--profile auto`
5. `emv terminal compare` exec vs terminal on same card
6. Session print + redaction spot check

---

## Requirement Traceability

| REQ prefix | Manual IDs |
|------------|------------|
| REQ-HOST-* | MAN-V2-001–010, 101–105 |
| REQ-SCH-* | MAN-V2-011–020, 111–113, 147–150 |
| REQ-CVM-* | MAN-V2-021–040, 120–122 |
| REQ-DAT-* | MAN-V2-026–035, 053–055, 117–119 |
| REQ-CLI-* | MAN-V2-041–048, 123, 146 |
| REQ-ODA-* | MAN-V2-061–066 |
| REQ-RISK-* | MAN-V2-071–073 |
| REQ-TST-* | MAN-V2-049–052, 079–086, 126 |
| REQ-INT-* | MAN-V2-087–098, 091–094 |
| REQ-TRC-* | MAN-V2-124–128, 136 |

See [TEST-PLAN-v2-automated.md](./TEST-PLAN-v2-automated.md) for CI coverage.
