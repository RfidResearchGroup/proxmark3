# SPEC v2: Trace, PCAP, Replay, Timing

## Scope

Features **F-031**, **F-033**, **F-035**

---

## PCAP / Wireshark Export — REQ-TRC-001–014

### REQ-TRC-001

Flag `--pcap-out <file.pcap>` on `run|step|replay`.

### REQ-TRC-002

Encapsulate ISO7816 APDUs as pseudo-linktype suitable for Wireshark USER0 / custom dissector, or SSL-less TCP loopback format documented in `doc/emv_pcap_format.md`.

### REQ-TRC-003

Each record: timestamp (us), direction (PMD→ICC / ICC→PMD), CAPDU/RAPDU bytes.

### REQ-TRC-004

PIN data replaced with zeros in pcap when redaction enabled.

### REQ-TRC-005

Optional companion `--pcap-meta session.json` links pcap to session phases.

---

## Transaction Replay — REQ-TRC-020–029

### REQ-TRC-020

`emv terminal replay <mock_apdu.json> [--from-phase <name>] [--to-phase <name>]` executes phase engine against recorded APDUs without live card.

### REQ-TRC-021

`--from-phase cvm` skips init/oda in replay (uses card TLV from fixture sidecar).

### REQ-TRC-022

Combine with `--host-sim` for full offline→online replay.

### REQ-TRC-023

Outcome written to `-o session.json`.

---

## Phase Timing Report — REQ-TRC-030–034

### REQ-TRC-030

Flag `--timing-report` adds to each phase event: `duration_ms`.

### REQ-TRC-031

Summary line: `Total: 842 ms (oda=120, cvm=45, caa=200, online=350)`.

### REQ-TRC-032

Stored in session JSON `Phases[].duration_ms`.

### REQ-TRC-033

Useful for comparing contactless timing before considering firmware WTX (F-027 excluded).

---

## Acceptance Criteria

| ID | Given | When | Then |
|----|-------|------|------|
| AC-TRC-001 | Live run | --pcap-out | File opens in Wireshark |
| AC-TRC-002 | mock fixture | replay | Same outcome as golden |
| AC-TRC-003 | --timing-report | run | duration_ms in JSON |

---

## Files

| File | Purpose |
|------|---------|
| `emv_term_pcap.c/h` | pcap writer |
| `emv_term_replay.c/h` | replay driver |
| `doc/emv_pcap_format.md` | dissector notes |
