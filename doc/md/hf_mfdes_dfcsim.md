# DESFire DFC emulator

The DESFire emulator accepts source credentials in `.dfc`, compiled `.dfcb`,
or complete Proxmark3 DESFire JSON format. RAM holds DFCB so the firmware and
client use the same canonical model.

```text
hf mfdes eload -f card.dfc
hf mfdes view --emu -v
hf mfdes sim
hf mfdes esave -f changed-card
```

Use `--format dfcb` or `--format json` with `esave` when another output format
is required. `eload --spiffs` and `esave --spiffs` transfer the standalone
mode's single fixed file, `hf_dfcsim.dfcb`.
`eview` remains an alias for `view --emu`.

JSON exports include `CommModeRaw` to preserve the complete file communication
settings byte. Older dumps with a recognized `CommMode` name still load; an
unknown name requires the raw byte instead of silently becoming plain mode.

## Direct test transport

The `etest` commands exercise the emulator without an RF reader. A session
keeps activation, authentication, injected randomness, and time state until it
ends.

```text
hf mfdes etest begin --machine
hf mfdes escan
hf mfdes erandom -d 5EE11A0743FB4EB5
hf mfdes eapdu --dialect native-apdu -d 900A0000010000
hf mfdes efieldoff
hf mfdes etest end
```

Machine mode emits one JSON object per command. Keep a single client process
open for the session. `estate` reports dirty state and random-byte underflow;
`etime` advances the emulator clock in milliseconds. An unrelated device
command ends the session, saves changes to emulator memory, and frees its
workspace.
