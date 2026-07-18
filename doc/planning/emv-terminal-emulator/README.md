# EMV terminal emulator (lab use)

> **FOR RESEARCH AND LAB USE ONLY — NO WARRANTY — PROVIDED AS-IS**
>
> This is **not** a certified payment terminal. Use only with authorized EMV test cards.

## How to use

See **[OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md)** for day-to-day commands, workflows, RDV4 3.3 V notes, and safety acknowledgments.

Also:

- Command overview: [doc/emv_notes.md](../../emv_notes.md) (`emv terminal` section)
- PCAP export notes: [doc/emv_pcap_format.md](../../emv_pcap_format.md)

```bash
./pm3 --offline -c 'emv terminal capabilities'
./pm3 --offline -c 'emv terminal help'
```
