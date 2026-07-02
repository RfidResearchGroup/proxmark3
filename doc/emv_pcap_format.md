# Proxmark3 EMV ISO7816 PCAP format

Link-layer type **265** (`EMV_PCAP_LINKTYPE`) for Wireshark USER0 / custom dissector import.

## Global header

Standard libpcap global header with `network = 265`.

## Per-packet payload

Each captured frame uses a pseudo-header compatible with the ISO14443 pcap convention.
`text2pcap -l 265` may be used for text conversion.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (`0x00`) |
| 1 | 1 | Direction: `0xFE` = PMD→ICC (CAPDU), `0xFF` = ICC→PMD (RAPDU+SW) |
| 2 | 2 | Payload length (big-endian, excludes pseudo-header) |
| 4 | N | APDU bytes |
| 4+N | 2 | Status word (ICC→PMD records only, appended after RAPDU body) |

Timestamps are stored in the standard pcap record header (`ts_sec`, `ts_usec`), relative to the first APDU in the session.

## PIN redaction

When session redaction is enabled (default), VERIFY PIN (`INS=0x20`), VERIFY PIN enciphered (`0x24`), and related PIN-bearing CAPDUs have their command data field zeroed before write.

## Companion metadata

`--pcap-meta session.json` writes `<pcap>.meta.json` linking the trace file to the terminal session export for phase correlation.

## Wireshark

Register a USER0 dissector on linktype 265, or use `tshark -r trace.pcap -V` with a Lua post-dissector. Phase boundaries are available in the companion session JSON `Phases[]` array.
