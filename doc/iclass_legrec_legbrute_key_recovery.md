# iCLASS Legacy Key Recovery

A walkthrough of the `hf iclass legrec` / `hf iclass legbrute` / `hf iclass unhash` pipeline for recovering the full 64-bit diversified key of a legacy iCLASS card, and optionally tracing it back to the site master key.

## Background

iCLASS (Picopass) uses a per-card **diversified key** derived from a global **master key** and the card's unique **CSN** (Card Serial Number, block 0). For legacy-mode cards the derivation is:

```
div_key = hash0(DES_encrypt(CSN, master_key))
```

`hash0` is HID's proprietary permutation; its output always has exactly 4 bytes with LSB = 0 and 4 bytes with LSB = 1 (the "4-4 balance" property). This structural constraint is the foundation of the attacks described here.

### Authentication Protocol

1. Reader selects card and reads **CSN** (block 0, 8 bytes) and **ePurse** (block 2, 8 bytes).
2. Reader issues **READCHECK** to fetch the CC bytes (challenge counter) from block 2.
3. Reader sends a **CHECK** command containing NR (reader nonce, 4 bytes) and MAC_reader (4 bytes):
   ```
   MAC_reader = doMAC(ePurse || NR, div_key)
   ```
4. Card verifies the MAC and returns MAC_card to confirm the session.

The 8-byte MAC field seen in traces is `NR (4 bytes) || MAC_reader (4 bytes)`.

#### Example from a sniffed trace

After running `hf iclass sniff` and `hf iclass list`, a typical Kd (AA1) authentication looks like:

```
CSN:    9655a400f8ff12e0
ePurse: feffffffffffffff    <- block 2, also used as CCNR prefix
NR:     1306cad9            <- reader nonce (4 bytes)
MAC:    b6c24466            <- MAC_reader (4 bytes)

Combined --macs argument:   1306cad9b6c24466
Combined --epurse argument: feffffffffffffff
```

The `--macs` value passed to `legrec` and `legbrute` is always the 8-byte concatenation `NR || MAC_reader`. The `--epurse` value passed to `legbrute` is the 8-byte ePurse read from block 2.

The CCNR used for MAC computation is `ePurse (8 bytes) || NR (4 bytes)` = 12 bytes total. MAC_reader is the last 4 bytes of `doMAC(CCNR, div_key)`.

### Key Slots

| Slot | Block | Name |
|------|-------|------|
| AA1 (Kd) | 3 | Debit / application key |
| AA2 (Kc) | 4 | Credit key |

The attacks here target the AA1 (Kd) diversified key in block 3.

### The XOR Key Update Model

The iCLASS UPDATE command behavior depends on the **card mode**:

- **Application mode** (normal deployed card): UPDATE **XORs** the written value with the block's existing content:
  ```
  new_key = current_key XOR written_value
  ```
- **Personalization mode** (blank/factory card): UPDATE writes the value **directly** to the block, no XOR.

The entire `legrec` attack depends on the XOR behavior. Writing a delta key and writing it again cancels out (XOR is its own inverse), which is what allows the attack to safely search through candidates and restore the original key after each failed attempt.

**Verify the card mode before starting:**

```
hf iclass info
```

Look for the `Personalization` flag in the output. A card in personalization mode will show:

```
[=] Personalization mode....... YES
```

If that flag is set, `legrec` will overwrite the key directly with the trial value rather than XOR-ing it, destroying the original key on the first write. Do not run `legrec` on a card in personalization mode.

A deployed card (e.g., an office badge that has been issued and used) will always be in application mode.

---

## The Weak Key Property

If all 8 bytes of a diversified key share the same **lower 3 bits** value `c` (i.e., `key[i] & 0x07 == c` for all i), then the MAC output is fully determined by `c` alone, regardless of the specific ePurse or NR values. 
A key in this state is called a **weak key**. Authenticating against a weak key requires only guessing the single 3-bit value `c`, not the full 64-bit key.
By design `hash0` prevents any diversified key from being a weak key.

There are exactly 8 mac patterns, one per possible 3-bit LSB value, see examples below:

```c
// iclass_mac_table in armsrc/iclass.c
iclass_mac_table[0] = { 0x00, 0x00, 0x00, 0x00, 0xBF, 0x5D, 0x67, 0x7F }  // bits 000
iclass_mac_table[1] = { 0x00, 0x00, 0x00, 0x00, 0x10, 0xED, 0x6F, 0x11 }  // bits 001
...
iclass_mac_table[7] = { 0x00, 0x00, 0x00, 0x00, 0xE2, 0xD5, 0x69, 0xE9 }  // bits 111
```

Through this attack we are trying to induce a weak key state.
For example, for a card with diversified key: B4F12AADC5301A2D we would try to induce a weak key state through key updates via privilege escalation.
An example of an induced weak key state is: B0F028A8C0301828 as the last 3 LSB of each byte are all 000 and in such case it will be possible to authenticate with the mac from `iclass_mac_table[0]` to the card.

---

## Attack Pipeline Overview

The full recovery is three phases, spanning multiple commands:

| Phase | Command | Type | Recovers |
|-------|---------|------|---------|
|  1  | `hf iclass legrec` | Online (card required) | Lower 3 bits of each key byte (24 bits) |
| 2.a | `hf iclass legbrute` | Offline (CPU brute-force) | Upper 5 bits of each key byte (40 bits) |
| 2.b | Hashcat 40 bits cracking | Offline (GPU brute-force) | Upper 5 bits of each key byte (40 bits)  - a faster alternative to CPU cracking|
|  3  | `hf iclass unhash` | Offline | hash0 reversal, generates pre-images for DES cracking from Kdiv |
|  4  | Hashcat DES Cracking| Offline | Performs DES cracking of pre-images with CSN, the last step to retrieve the master key|

The 64-bit key space is split: legrec reduces it from 2^64 to 2^40, and legbrute/hashcat exhausts the remaining space.

---

## Phase 1: hf iclass legrec

### What It Does

`legrec` physically writes XOR delta keys to the card, one at a time, until it induces a weak key state. When it finds a delta that makes the card authenticate with one of the 8 weak-key patterns, it extracts the lower 3 bits of the original diversified key.

### Prerequisites

- Card on the Proxmark3 antenna for the entire run (may take more than 1 day).
- A captured AA1 authentication trace: the ePurse + NR + MAC_reader bytes from a legitimate reader interaction. Collect with `hf iclass sniff` followed by `hf iclass list`.
- The standard credit key must not have been changed from the factory default -- `legrec` uses the standard Kc to compute write MACs internally.

> **Warning:** This process writes to the card's key block. If interrupted at the wrong moment the card may become permanently unusable. Do not remove the card from the antenna mid-run.

### How It Works (Step by Step)

**Step 0 -- Select and authenticate**

The card is selected (`select_iclass_tag`) and authenticated using the captured AA1 MACs via replay (`authenticate_iclass_tag` with `use_replay = true`). If this fails the PM3 retries up to 5 times before aborting.

**Step 1 -- Privilege escalation**

`legrec` issues a **READCHECK_CC** command targeting the first block of AA2. In the iCLASS protocol, an unauthenticated READCHECK of an AA2 block is permitted -- it resets the card's cipher state and signals the card to accept subsequent writes authenticated with the AA2 (credit) MAC. This escalation is needed because block 3 (the AA1 key) can only be overwritten from the credit-key-authenticated session (as we don't know Kd).

**Step 2 -- Generate candidate delta**

The function `generate_single_key_block_inverted_opt(zero_key, index, genkeyblock)` produces an 8-byte block where:

- Byte 0 is always 0 (never modified).
- Bytes 1-7 have their top 5 bits = 0 and their low 3 bits set from the current index and a parity-balanced ending table.

The ending table has 70 entries (C(8,4) = 70), each a byte where exactly 4 bits are 1 and 4 bits are 0. This enforces the hash0 DES parity property: across all 8 key bytes, exactly 4 will have bit-0 = 1. Within each step of the outer loop, 16,383 mid-bit combinations are tried. Total search space: `70 × 16383 ≈ 1,146,810` XOR deltas -- all possible patterns of the lower 3 bits of bytes 1-7 that are DES-parity consistent.

**Step 3 -- Write the delta**

```
new_key = original_div_key XOR genkeyblock
```

`doMAC_N` computes the write MAC using `div_key2` (the AA2 diversified key, derived from the card's CSN and the standard Kc, computed on the client side and passed to the ARM). The MAC is required because block 3 writes are authenticated.

**Step 4 -- Test for diversified weak key**

The device issues a READCHECK of block 2 (resets cipher state to Kd context), then attempts authentication against each of the 8 `iclass_mac_table` entries. If `new_key` is weak (all low 3 bits identical), exactly one table entry will match. That entry's index `c` is `bits_found`.

The condition for a match:
```
(original_div_key[i] XOR genkeyblock[i]) & 0x07 == c    for all i in 0..7
```

Rearranging:
```
original_div_key[i] & 0x07 == c XOR (genkeyblock[i] & 0x07)
```

Or to explain it in a simpler way: if the card accepts one of the macs we're trying to authenticate with, the card's current key (`original_div_key XOR genkeyblock`) is a weak key. The matching table index `c` (0-7) is the value shared by the lower 3 bits of every byte of that key. From `c` and the known `genkeyblock`, the lower 3 bits of the original `div_key` can be derived directly -- which is the 24 bits this phase is after.

**Step 5 -- Restore and output**

The original key is restored by writing `genkeyblock` again (XOR is its own inverse). The output is:

```
partialkey[i] = genkeyblock[i] XOR bits_found
```

Because `partialkey[i] & 0x07 = (genkeyblock[i] & 0x07) XOR c = original_div_key[i] & 0x07`, the lower 3 bits of `partialkey` are exactly the lower 3 bits of the original diversified key. The upper 5 bits of `partialkey` are zero and must be found by `legbrute`.

### Running legrec

Before the first real run, use test mode to verify the card's ePurse updates are being heard:

```
hf iclass legrec --macs 0000000089cb984b
```

This performs a single dry-run write without advancing the index. Output:
- `CARD EPURSE IS LOUD` -- the card responds to writes. Safe to proceed.
- `CARD EPURSE IS SILENT` -- the card is not responding to writes. Do not proceed; the card may brick. In this case scan the card against the reader (this is needed), then capture traces again and retry. Repeat this process until the error goes away and the epurse becomes loud.

Once the test passes, start the real recovery:

```
hf iclass legrec --macs 0000000089cb984b --notest --loop 5000
```

`--loop N` sets how many candidate deltas to test per invocation. The command sends one `CMD_HF_ICLASS_RECOVER` payload to the ARM and waits; the ARM processes up to `N` cycles and returns.

To run overnight:

```
hf iclass legrec --macs 0000000089cb984b --notest --allnight --loop 5000
```

`--allnight` repeats the loop 10 times, advancing the index automatically each run.

To resume from a saved index after interruption:

```
hf iclass legrec --macs 0000000089cb984b --notest --index 340 --loop 5000
```

`--index` is in raw units (not millions).

### Speed Options

| Mode | Speed |
|------|-------|
| Default | ~4.6 key updates/second |
| `--fast` | ~7.4 key updates/second (higher brick risk) |
| `--sl` | Reduces comms delays, adds another ~10-15% |
| `--fast --sl` | ~8-10 key updates/second |

`--fast` skips the per-write restore and verification, accumulating the XOR delta until a weak key is found. The restoration at the end uses the accumulated XOR. This is faster but leaves the card in an unknown intermediate state for longer.

### Estimating Time

Use `--est` with the card on the antenna to estimate the number of writes needed for this specific card (requires the standard master key to be in use):

```
hf iclass legrec --est
```

This runs `CmdHFiClassLegacyRecSim` offline: it computes the actual diversified key from the CSN using the built-in standard Kd, then iterates the candidate table to find the exact index at which the weak key condition is met. The output shows the required write count and estimated time at each speed.

### Output

On success the ARM prints to the device console:
```
SUCCESS! Raw Key Partial Bytes:
04 01 02 05 05 00 02 05
```

The partial key has the correct lower 3 bits in every byte and zeroes in the upper 5 bits.

---

## Phase 2: hf iclass legbrute / hashcat

### What It Does

`legbrute` takes the 24-bit partial key from `legrec` and two independent sniffed MAC pairs, then exhausts all 2^40 combinations of the upper 5 bits of the diversified key. It is a pure offline CPU attack -- no card required.

Two MAC pairs are required so that a false positive (MAC collision for one pair) is eliminated by verifying against the second.

### Inputs Required

You need two distinct AUTH traces from the same card -- same CSN and ePurse, different NR values. Collect with `hf iclass sniff` across two separate reader presentations.

From each trace, extract:
- `ePurse` (8 bytes, block 2) -- should be the same in both traces if the card was not used between sniffs
- `macs` = NR (4 bytes) || MAC_reader (4 bytes), 8 bytes total

> **Note:** The ePurse is a counter that increments on each card use. If the ePurse differs between the two traces, the card was used between captures. Both traces must use the same ePurse value for the brute-force to work. Collect both traces in a single sniff session.

### Key Generation Logic

The worker function `generate_key_block_inverted` in [client/src/cmdhficlass.c](client/src/cmdhficlass.c#L6261) generates full candidate keys:

```c
void generate_key_block_inverted(const uint8_t *startingKey, uint64_t index, uint8_t *keyBlock) {
    // Preserves the lower 3 bits of startingKey[j]
    // Sets the upper 5 bits of each byte from 5-bit chunks of index
    carry = index;
    for (j = 7; j >= 0; j--) {
        keyBlock[j] = (startingKey[j] & 0x07) | ((carry & 0x1F) << 3);
        carry >>= 5;
    }
}
```

With `startingKey = partialKey` from `legrec`:
- The lower 3 bits of every candidate key byte equal the corresponding bits of the original `div_key`.
- The upper 5 bits step through all `2^(5×8) = 2^40` combinations.

For each candidate, the thread computes `doMAC_brute(ePurse || NR, div_key_candidate)` and compares against the captured MAC. A primary hit is verified against the second MAC pair before being reported.

### Running legbrute

```
hf iclass legbrute --epurse feffffffffffffff \
                   --macs1 1306cad9b6c24466 \
                   --macs2 f0bf905e35f97923 \
                   --pk 0401020505000205
```

By default it uses all available CPU threads, each working a non-overlapping slice of the 2^40 space.

To resume after aborting (index is printed in millions when you press Enter):

```
hf iclass legbrute --epurse feffffffffffffff \
                   --macs1 1306cad9b6c24466 \
                   --macs2 f0bf905e35f97923 \
                   --pk 0401020505000205 \
                   --index 250
```

`--index 250` resumes from 250 million keys in.

To control thread count:

```
hf iclass legbrute ... --threads 4
```

### Running hashcat.

A faster alternative is to run this command on hashcat to leverage GPU cracking speeds. This is much faster than CPU cracking in most scenarios.

Generate a hash file using the format:

$iclass_leg$<partial_key_16hex>$<ccnr1_24hex>$<mac1_8hex>$<ccnr2_24hex>$<mac2_8hex>

Note: 24 hex = 12 bytes / 8 hex = 4 bytes

Result should look like this:

$iclass_leg$0401020505000205$feffffffffffffff1306cad9$b6c24466$fefffffffffffffff0bf905e$35f97923

Run:

./hashcat.exe -a 3 -m 64000 hash.txt ?b?b?b?b?b

### Output

On success legbrute will return:
```
Found valid raw key B4F12AADC5301A2D
Hint: Run `hf iclass unhash -k B4F12AADC5301A2D` to find the needed pre-images
```

Hashcat's output will look like:
```
$iclass_leg$0401020505000205$feffffffffffffff1306cad9$b6c24466$fefffffffffffffff0bf905e$35f97923:B4F12AADC5301A2D
```

### Timing

| Threads | Speed | 2^40 keyspace |
|---------|-------|--------------|
| 1 | ~2M keys/s | ~6 days |
| 8 | ~16M keys/s | ~19 hours |
| 16 | ~32M keys/s | ~9.5 hours |

These are rough estimates; actual speed depends on CPU and memory bandwidth.

Using hashcat on a modern GPU (RTX 5070 Ti), this attack takes roughly <10 minutes to complete.

---

## Phase 3: hf iclass unhash

### What It Does

`unhash` reverses the `hash0` function to recover the DES-encrypted CSN (the pre-image that feeds into the master key DES step). Combined with the card's known CSN, this gives you a plaintext/ciphertext pair for DES, which can be cracked offline with hashcat to recover the global master key.

### Running unhash

```
hf iclass unhash -k B4F12AADC5301A2D
```

The command first validates the key against the hash0 4-4 balance property: exactly 4 bytes must have LSB = 0 and 4 must have LSB = 1. If this fails, the key was not generated by hash0 and may be AES-based rather than legacy DES.

On success it prints the pre-image bytes and shows the hashcat command:

```
hashcat.exe -a 3 -m 14000 preimage:csn -1 charsets/DES_full.hcchr --hex-charset ?1?1?1?1?1?1?1?1
OR
hashcat.exe -a 3 -m 14000 hash.txt -1 charsets/DES_full.hcchr --hex-charset ?1?1?1?1?1?1?1?1
```

Mode 14000 is single-DES. The format is `plaintext:ciphertext` in hex, where `plaintext = pre-image` and `ciphertext = CSN`.

This command may output multiple pre-images, which is totally normal and they can be added inside the hash.txt file.
Only one pre-image will match the correct DES Key.
---

## Complete Workflow

```
# 1. Sniff a reader interaction to get the card's auth trace
hf iclass sniff

# 2. Parse the trace to see ePurse and MACs
data list -t iclass

# 3. [Recommended] Test the card responds to writes before committing
hf iclass legrec --macs <NR+MAC from trace>

# 4. Run the online key bit recovery (takes hours to days, card must stay on antenna)
hf iclass legrec --macs <NR+MAC> --notest --loop 5000 --allnight

#    If interrupted, resume with:
hf iclass legrec --macs <NR+MAC> --notest --index <saved_index> --loop 5000

# 5. Collect two MAC pairs (same ePurse) from the sniff session
#    macs1 and macs2 are two different NR+MAC lines with the same ePurse value

# 6. Brute-force the remaining 40 bits offline
hf iclass legbrute --epurse <epurse> --macs1 <NR+MAC_1> --macs2 <NR+MAC_2> --pk <partial_key>

# 7. Reverse hash0 to get DES pre-image
hf iclass unhash -k <found_div_key>

# 8. Crack DES with hashcat to recover the master key
hashcat -a 3 -m 14000 <preimage>:<csn> -1 DES_full.hcchr --hex-charset ?1?1?1?1?1?1?1?1
```

---

## Troubleshooting

### "CARD EPURSE IS SILENT! RISK OF BRICKING!"
The card is not updating its ePurse counter on writes. This usually means the card is not responding to UPDATE commands at all, or the authentication failed silently. Scan the card on a legitimate reader to force an ePurse update, capture a fresh trace, and retry.

### "Unable to select or authenticate with card multiple times"
The card moved off the antenna or the replay MACs expired (the ePurse counter changed since the trace was captured). Capture a fresh trace and restart.

### "Key not found in the given keyspace"
legbrute exhausted all 2^40 candidates without a match. This can happen if the card was used (ePurse changed) while gathering macs for legbrute. Repeat legbrute again with fresh Macs, making sure they're captured without updating the card's epurse (use hf iclass sim for that).

### "Incorrect LSB Distribution" from unhash
The recovered key does not have the 4-4 LSB balance that hash0 requires. Either the key belongs to an AES-based iCLASS SE/SR card (not a legacy card), or legbrute found a false positive. Verify the key authenticates: `hf iclass info -k <key>`.

### Card becomes unresponsive mid-run
This is the brick scenario. The last written key block is printed to the device console when legrec detects the failure. Might happen if the card was moved from the Proxmark3 during legrec. Prevent this by taping the card to the proxmark or securing it with a rubber band.

---

## Notes on Key Types

These commands target **legacy standard-keyed** cards where the master key has not been changed from the HID factory default. The pipeline will also work on cards with a custom master key -- legrec recovers the diversified key regardless of what master key was used -- but the `unhash` + hashcat step will not recover an AES master key.

Cards in **Elite** mode use a different diversification algorithm and are not attacked by this pipeline. Use `hf iclass loclass` for Elite-mode readers (see [loclass_notes.md](loclass_notes.md)).
