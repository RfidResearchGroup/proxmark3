# HF_DFCSIM, DESFire DFCB simulator

`HF_DFCSIM` simulates one DESFire credential stored in SPIFFS as
`hf_dfcsim.dfcb`. Reader writes are saved back to that file before exit.
If the file is missing, the mode creates and saves a factory-state card with
no applications or files, the default master key, and a generated UID. The card
uses the selected build generation, EV1 by default. An existing invalid file
is reported as an error and is not replaced.

## Prepare the credential

```text
hf mfdes eload -f card.dfc
hf mfdes esave --spiffs
```

The client also accepts `.dfcb` and complete Proxmark3 DESFire v1 JSON dumps.
JSON conversion refuses missing keys, unread file contents, and fields that DFC
cannot represent.

## Build

```text
make clean
make STANDALONE=HF_DFCSIM -j
./pm3-flash-all
```

The PM3 default build is a full DESFire EV1 profile. PM5 defaults to full EV3
with proximity checking enabled. Select a different DFC profile
at compile time when the credential or test requires newer commands:

```text
make clean
make STANDALONE=HF_DFCSIM DFC_SIM_PROFILE=EV2 -j
```

Supported profiles are `EV1`, `EV2`, `EV3`, `MINIMAL_EV1`, and
`MINIMAL_EV3`. Features outside the selected generation are left out of the
firmware. EV3 proximity checking is separately opt-in:

```text
make clean
make STANDALONE=HF_DFCSIM DFC_SIM_PROFILE=EV3 \
    DFC_SIM_PROXIMITY_CHECK=1 -j
```

`DFC_SIM_PROXIMITY_CHECK=1` is rejected for non-EV3 profiles. Run `make clean`
when changing profiles because these options alter every compiled DFC object.

The PM3 standalone defaults retain all features in the selected profile while
limiting one card to 28 applications, 28 files, 256 bytes of file data, and 512
bytes of keys. The EV1 credential workspace is 5,672 bytes with these limits.
It is allocated only while the emulator runs, then zeroed and returned to
BigBuf so unrelated commands retain the full working arena.
Increase them only when a credential needs more capacity:

```text
make clean
make STANDALONE=HF_DFCSIM DFC_SIM_MAX_APPS=32 DFC_SIM_MAX_FILES=32 \
    DFC_SIM_FILE_POOL_SIZE=2048 DFC_SIM_KEY_POOL_SIZE=512 -j
```

PM5 uses the full DFC capacities: 28 applications, 32 files, an 8,192-byte file
pool, and a 4,096-byte key pool. Its workspace is likewise released on exit.

This mode requires SPIFFS support. On RDV4, hold the button for at least
500 ms to save and exit. A USB command also saves and exits. Saving uses a
temporary file and backup rename so an interrupted write stays recoverable.
On PM5, start it with `hw standalone`; button-triggered entry is currently
disabled by the platform.
