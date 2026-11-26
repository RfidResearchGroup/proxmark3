# RTTTL playback on PM5

Play a monophonic RTTTL melody on the PM5 mainboard buzzer, from a string or a
text file. Available on PM5 with or without BWM. Use matching client and firmware.

## Contents

- [Usage](#usage)
- [Limits](#limits)
- [RTTTL format](#rtttl-format)
- [Firmware API](#firmware-api)

---

## Usage

```text
hw rtttl --data "Demo:d=8,o=5,b=120:c,e,g,4p"
hw rtttl --file "melody.rtttl"
```

Specify exactly one of `--data` or `--file`. Quote file paths containing spaces.
See `hw rtttl --help` for command options.

## Limits

- Maximum **2047 text bytes**, including the name, BOM and whitespace.
  Oversized or invalid input is rejected without truncation.
- Playback blocks the device until completion. Press the **pm5 button** or
  **<Enter>** in the client to abort it.
- Melodies are temporary: nothing is saved to flash or SPIFFS.

## RTTTL format

Use `name:defaults:notes`, with comma-separated notes. For example,
`Demo:d=8,o=5,b=120:c,e,g,4p` plays C, E, G, then a pause.

- Defaults: `d` = duration denominator, `o` = octave, `b` = tempo in BPM.
  The defaults section may be empty; omitted values use `d=4,o=6,b=63`.
- Duration denominators: **1..64**, including values such as 6, 12 and 24.
  Octaves: **4..7**. Tempo: **25..900 BPM**.
- Notes: `c d e f g a b`, `h` as an alias for `b`, and `p` for a pause.
  Notes may have a sharp (`c#`), a duration (`8c`), an octave (`c5`) and one
  dot (`c5.` or `c.5`). Flats and double dots are not supported.
- Names are nonempty printable ASCII, without a separate 10-character limit.
  A leading UTF-8 BOM, case-insensitive notes/defaults, and whitespace around
  notes and default assignments are accepted. Embedded NUL bytes are rejected.

## Firmware API

Standalone modes and other PM5 firmware features can use `armsrc/buzzer.h`:

```c
#ifdef PM5
static const char melody[] = "Demo:d=8,o=5,b=120:c,e,g,4p";
rtttl_status_t status = BuzzerPlayRtttl(melody, sizeof(melody) - 1);
#endif
```

The length excludes the final NUL. Keep the text alive and unchanged until
return. The call blocks, returns `RTTTL_OK`, `RTTTL_ABORTED` when a new button
press or incoming host data stops it, or an RTTTL error, and leaves the
buzzer silent. Do not call concurrently or from an ISR/time-critical handler.
Existing alerts are unchanged.
