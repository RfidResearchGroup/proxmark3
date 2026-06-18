# SPEC: Payment Schemes — AIDs, Kernels, and Terminal Profiles

## Purpose

Reference data for Visa, Mastercard, Plus, Cirrus, Interlink, Interac, and related EMV applications when building the PM3 terminal emulator. Use this to configure terminal candidate lists, per-scheme profiles, and test plans.

## Scope

- Application Identifiers (AIDs) and RIDs
- EMV contactless kernel mapping (EMVCo C-1…C-7)
- Lab/test card hints (public test pack data)
- Mapping to existing Proxmark3 code paths

## Non-Goals

- Live production acquirer routing tables
- Complete global AID database (see `client/resources/aidlist.json` for 3700+ entries)

---

## EMVCo Contactless Kernels

| Kernel | Scheme | RID prefix | PM3 `emv exec` mode |
|--------|--------|------------|---------------------|
| C-1 | Interac Flash | `A0 00 00 02 77` | qVSDC/MChip-style flow; Interac-specific tags (9F6B–9F6D CIACs, MTI limits) |
| C-2 | Mastercard contactless | `A0 00 00 00 04` | `--qvsdc` / M/Chip |
| C-3 | Visa contactless (qVSDC) | `A0 00 00 00 03` | `--qvsdc` |
| C-4 | American Express | `A0 00 00 00 25` | partial via generic EMV |
| C-5 | JCB | `A0 00 00 00 65` | partial |
| C-6 | Discover/Diners | `A0 00 00 01 52` | partial |
| C-7 | UnionPay | `A0 00 00 03 33` | partial |

Sources: EMVCo Entry Point spec; [SmartCardFYI kernel guide](https://smartcardfyi.com/tr/guide/emv-contactless-kernel/).

---

## Visa (RID `A000000003`)

### Core payment AIDs

| AID | Name | Typical use | Terminal notes |
|-----|------|-------------|----------------|
| `A0000000031010` | Visa Credit/Debit (Classic) | Global credit/debit | **Default Visa** — PPSE, qVSDC, VSDC |
| `A0000000032010` | Visa Electron | Debit / co-badge | POS must accept if Visa accepted (Visa US guide) |
| `A0000000032020` | V Pay | Europe debit | Same RID family |
| `A0000000033010` | Visa Interlink | US debit network | **Online PIN** at POS; needs online-capable terminal |
| `A0000000038010` | Plus | ATM / shared ATM network | **ATMs** must list with Visa + Electron; chip Plus-only cards exist |
| `A0000000980840` | Visa U.S. Common Debit | US regulated debit routing | US POS debit choice; partial AID `A000000098` |

### Select APDU example

```text
00 A4 04 00 07  A0 00 00 00 03 10 10  00
```

### Terminal profile hints

- Country `9F1A`: issuer market (e.g. `0840` US)
- Currency `5F2A`: `0840` USD
- TTQ `9F66`: qVSDC default `26 00 00 00` (see `emv_defparams.json`)
- Interlink: terminal must support online PIN (`9F33` / TTQ online PIN bit)

### Test CAPK indices (lab)

| Index | Key size | Notes |
|-------|----------|-------|
| `92`, `94`, `95` | 1408 / 1984 | Common in `client/resources/capk.txt` / lumag test keys |
| `08`, `09` | 1408 | Production-style expiry dates in file |

Source: [lumag/emv-tools visa-test.keys](https://github.com/lumag/emv-tools/blob/master/data/visa-test.keys); Worldpay EMV Network Keys Test PDF.

---

## Mastercard (RID `A000000004`)

### Core payment AIDs

| AID | Name | Typical use | Terminal notes |
|-----|------|-------------|----------------|
| `A0000000041010` | Mastercard Credit/Debit | Global | **Default MC** — M/Chip contactless |
| `A0000000043060` | Maestro | Debit | Common EU debit |
| `A0000000046000` | Cirrus | **ATM only** | ATM withdrawal network; not POS purchase app on most cards |
| `A0000000042203` | Mastercard U.S. Common Debit | US regulated debit | Partial `A000000004` + PIX `2203` |
| `A0000000049999` | PayPass legacy | Contactless | Older cards |

### Cirrus vs Maestro vs MC Credit

- **Cirrus (`…6000`)**: ATM interbank; terminal type ATM; often no CVM list for contactless Flash-style flows
- **Maestro (`…3060`)**: POS debit brand
- **MC Credit (`…1010`)**: Credit/charge

### Test CAPK indices (lab)

| Index | Key size | Notes |
|-------|----------|-------|
| `EF`, `F1` | 1984 / 1408 | Worldpay test doc; MC requires hash verification |
| `00`, `02`, `05`, `F3`–`F9` | various | In `client/resources/capk.txt` |

Source: [lumag/emv-tools mastercard-test.keys](https://github.com/lumag/emv-tools/blob/master/data/mastercard-test.keys).

---

## Plus and Interlink (Visa RID, different PIX)

These are **not separate RIDs** — they share `A000000003` with different PIX:

| Network | AID | Interface | CVM typical |
|---------|-----|-----------|-------------|
| Plus | `A0000000038010` | ATM (+ some co-badged cards) | Online PIN |
| Interlink | `A0000000033010` | POS debit | Online PIN required at POS |

**Terminal emulator implication:** when walking CVM list, online PIN (CVM code `02`) requires host stub or `--online-pin-stub`; offline VERIFY is insufficient for Interlink-only rules.

Visa US Acquirer Implementation Guide (Table 2-1, 2-2): ATMs need Visa + Electron + Plus; POS with Interlink need Visa + Interlink + US Common Debit.

---

## Interac (RID `A000000277`)

### Application

| Field | Value |
|-------|-------|
| **AID** | `A0000002771010` |
| **RID** | `A0 00 00 02 77` |
| **PIX** | `10 10` |
| **Kernel** | EMVCo C-1 (Interac Flash contactless) |
| **Country** | Canada (`5F28` / `9F1A` = `0124`) |
| **Currency** | CAD (`5F2A` = `0124`) |
| **PPSE** | Standard `2PAY.SYS.DDF01` |

### Select APDU

```text
00 A4 04 00 07  A0 00 00 02 77 10 10  00
```

### Interac-specific card tags (terminal must parse)

| Tag | Name | Relevance |
|-----|------|-----------|
| `9F6B` | CIAC — contactless decline | Interac Flash TAA inputs |
| `9F6D` | CIAC — contactless online | |
| `8F` | CA PKI | CAPK index on card |
| `9F52`–`9F57` | MTI limits | Merchant type indicator limits (test cards often `$50.01`) |
| `9F63` | Card Transaction Information | Interac Flash |
| `9F70` | Form Factor Indicator | Contactless form factor |
| `DF62` | Application Selection Flag [Canada] | `8080` on test cards |

### Test cards (Interac Flash Interoperability v2.1)

| Card | PAN (test) | PIN | CVM list (contact) | CAPK idx |
|------|------------|-----|-------------------|----------|
| TC01 | `0012010000000005` | `1111` | `44 03 01 03 02 03` enc→plain→online | CA `07` |
| TC02 | `0012030000000003` | `2222` | `04 03 01 03 02 03` | CA `03` |
| TC03 | `0012040000000002` | `3333` | `02 03 44 03 01 03` online first | CA `03` |
| TC04 | `0012050000000001` | `4444` | same as TC01 | CA `03` |

**Contactless Interac Flash:** test doc states **no CVM rules** on contactless — terminal skips PIN on Flash tap; contact interface requires PIN.

### Test issuer keys (AC / ARPC lab)

All Interac Flash test cards share (Section 3.2):

```text
AC Master Key:  0123456789ABCDEFFEDCBA9876543210
SMI (integrity): 0123456789ABCDEFFEDCBA9876543210
SMC (confidential): 0123456789ABCDEFFEDCBA9876543210
```

Use with host simulator for ARQC validation / ARPC generation on BIN `0012`.

### Test CAPKs (terminal must load)

| Index | Size | Exponent | Checksum (SHA-1) |
|-------|------|----------|------------------|
| `03` | 1408 | `010001` | `0FB60A1BCA38095F3CC578D2DEC95F7789840A343` |
| `07` | 1984 | `010001` | `44F2C13373A5068B63C9334E914DDE6AB70CE0F1` |

Added to `client/resources/capk.txt` in lumag/emv-tools line format. Full modulus in [Interac Flash test card PDF](https://b2ps.com/fileadmin/pdf/cardsetdocs/Interac_Flash_Interoperability_Test_Card_Set.pdf).

### ARPC lab (contact online)

Issuer simulator should return **ARPC-RC = `8840`** for contact (not `3030`) to avoid application block on test cards.

IAD format: `ARPC || ARPC-RC` (tag `91`).

Source: [Interac Corp Simulator Setup For Flash Test Cards](https://b2ps.com/fileadmin/fixed_link_brochures/Interac_Corp_Simulator_Setup_For_Flash_Test_Cards.pdf).

### Example terminal profile

See `examples/emv_terminal_profile_interac.json`.

---

## Recommended terminal candidate AID list (PM3Easy lab)

Priority order for `emv terminal run` / `EMVSearch` fallback list:

```json
[
  "A0000002771010",
  "A0000000031010",
  "A0000000032010",
  "A0000000041010",
  "A0000000043060",
  "A0000000033010",
  "A0000000038010",
  "A0000000046000",
  "A0000000980840",
  "A0000000042203"
]
```

Full file: `examples/terminal_aid_candidates.json`.

Existing search list: `client/src/emv/emvcore.c` `AIDlist[]` (already includes most entries; Interac reclassified as `CV_INTERAC`).

---

## PPSE / PSE

| Name | AID (hex string) | Channel |
|------|------------------|---------|
| PPSE | `325041592E5359532E4444463031` | Contactless |
| PSE | `315041592E5359532E4444463031` | Contact |

Implemented in `emvcore.c` `PSElist[]`.

---

## Functional Requirements (scheme support)

REQ-SCH-001: Terminal shall include `A0000002771010` in default candidate AIDs for Canadian lab profile.

REQ-SCH-002: Terminal shall map RID `A000000003` to Visa profile (TTQ, TAC defaults).

REQ-SCH-003: Terminal shall map RID `A000000004` to Mastercard profile.

REQ-SCH-004: Terminal shall treat `A0000000038010` (Plus) and `A0000000033010` (Interlink) as Visa-family with online-PIN-capable terminal flags.

REQ-SCH-005: Terminal shall load CAPK for Interac indices `03` and `07` when `-j` profile `interac` selected.

REQ-SCH-006: Interac contactless path shall skip CVM when card Flash rules indicate no CVM (per test card spec).

---

## Acceptance Criteria

AC-SCH-001: Given Interac test card TC01 contact, offline enciphered PIN `1111`, VERIFY succeeds with CAPK index 07.

AC-SCH-002: Given Visa qVSDC test card, PPSE selects `A0000000031010` and GEN AC returns ARQC or TC.

AC-SCH-003: `emv search` finds Interac AID on Canadian debit card.

---

## Open Questions

OQ-011: Auto-detect country profile from `9F1A` vs explicit `--profile interac` — see OPEN-QUESTIONS.md.

---

## References

- [Visa VSDC US Acquirer Implementation Guide](https://usa.visa.com/content/dam/VCOM/regional/na/us/partner-with-us/documents/visa-smart-debit-credit-contact-contactless-us-acquirer-implementation-guide.pdf)
- [Interac Flash Interoperability Test Card Set v2.1](https://b2ps.com/fileadmin/pdf/cardsetdocs/Interac_Flash_Interoperability_Test_Card_Set.pdf)
- [DEV Canada EMV Test Card Set v14](https://b2ps.com/fileadmin/pdf/cardsetdocs/DEV-Canada_Test_Card_Set_v14.pdf)
- [EFTlab AID list](https://www.eftlab.com/knowledge-base/complete-list-of-application-identifiers-aid)
- [lumag/emv-tools](https://github.com/lumag/emv-tools) — CAPK file format, VERIFY, ARPC patterns
- [ntufar/EMV](https://github.com/ntufar/EMV) — phase architecture reference
- Existing: `doc/emv_notes.md`, `client/resources/aidlist.json`, `client/resources/capk.txt`
