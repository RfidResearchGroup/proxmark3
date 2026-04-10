# AID list (`aidlist.json`)
<a id="top"></a>

This file acts as a database of ISO/IEC 7816 application identifiers (AIDs) and their human-readable metadata.

It is used by commands that try known app selections and then print decoded information (for example `hf 14a info --aidsearch`, `hf 14b info --aidsearch`, etc.).

## Format
Each entry in `client/resources/aidlist.json` must contain all of the fields below (use an empty string if data is unknown):

- `AID`: Application Identifier as a hex string, no spaces or separators, representing raw bytes in ISO7816 select order (big-endian byte order as transmitted in APDU data).
- `Vendor`: Organization, scheme, ecosystem owner, or issuer most directly associated with this AID. Specify multiple issuers with a comma or semicolon separator.
- `Country`: Primary country associated with the vendor or deployment context. Leave empty when unknown or globally used.
- `Name`: Short user-facing application name.
- `Description`: Extra context, disambiguation, references, legacy naming, known usage notes, or deployment-specific remarks.
- `Type`: High-level category tag (for example `transport`, `emv`, `gp`, `pacs`, `ndef`).

## Optional fields
- `ResponseRegex`: Case-insensitive regex matched against the APDU SELECT response encoded as hex without separators. Current regex subset supports `^`, `$`, `.`, `*`, and `\` escape. Use this field when multiple protocols share the same AID and can be distinguished by response content.
- `Sources`: Array of strings describing where the AID metadata was sourced from. Supported formats:
  - `android://<package.name>` for Android apps that declare or use this AID.
  - `http://...` or `https://...` for public references used to add or verify the entry.
- `Protocol`: Application-layer protocol implemented by this AID. Use lowercase `snake_case` (for example `apple_vas`).
  If the protocol is vendor/ecosystem-specific, include an owner qualifier in the name (for example `google_smart_tap`, `ccc_digital_car_key`) instead of using a generic label.
  Known protocol names currently used:
  - `aep_vts`
  - `apple_access_key`
  - `apple_home_key`
  - `apple_vas`
  - `ccc_digital_car_key`
  - `cna_calypso`
  - `csa_aliro`
  - `google_smart_tap`
  - `hid_seos`
  - `ict_protege_mobile`
  - `kastle_presence`
  - `legic_connect`
  - `mifare_desfire`
  - `salto_justin_mobile`
  - `samsung_vas`
  - `schlage_mobile_access`
  - `stid_mobile_id`
  - `suprema_mobile`
  - `unifi_identity`

## Examples

Simple entry:
```json
{
    "AID": "A00000039656434103F1216000000000",
    "Vendor": "LV Monorail",
    "Country": "United States",
    "Name": "Las Vegas Monorail",
    "Description": "Used on Las Vegas Monorail during Google Wallet Mifare 2GO demo period",
    "Type": "transport"
}
```

Response format disambiguation example:
```json
{
    "AID": "4F53452E5641532E3031",
    "Vendor": "Google",
    "Country": "",
    "Name": "Google Smart Tap (OSE.VAS.01)",
    "Description": "Google Smart Tap",
    "Type": "loyalty",
    "Protocol": "google_smart_tap",
    "ResponseRegex": ".*500a416e64726f6964506179.*9000$"
}
```

Sources example:
```json
{
    "AID": "A0000004400001010001000002",
    "Vendor": "HID Global",
    "Country": "",
    "Name": "SEOS Mobile",
    "Description": "Declared by some SEOS-compatible HID partner applications for HCE",
    "Type": "access",
    "Sources": [
        "android://com.lane.lane",
        "https://example.com/reference"
    ]
}
```
