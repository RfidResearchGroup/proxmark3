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
- `ResponseContains`: Case-insensitive hex substring matched against the APDU SELECT response (encoded as hex without separators). Use this field when multiple protocols share the same AID and can be distinguished by response content.

Example:
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

Response-disambiguation example:
```json
{
    "AID": "4F53452E5641532E3031",
    "Vendor": "Google",
    "Country": "",
    "Name": "Google Smart Tap (OSE.VAS.01)",
    "Description": "Google Smart Tap",
    "Type": "loyalty",
    "ResponseContains": "500a416e64726f6964506179"
}
```
