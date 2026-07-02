# hf mfu esetblk — Design Document

**Date:** 2026-07-02
**Branch:** hf-mfu-esetblk
**Goal:** Add `hf mfu esetblk`, mirroring `hf mf esetblk` but for Ultralight/NTAG (MFU) 4-byte page memory, so users can set emulator-memory page(s) directly (for building/patching an emulated UL/NTAG tag without re-running a full `eload`).

---

## Background

`hf mf esetblk` ([cmdhfmf.c:5216](../../client/src/cmdhfmf.c#L5216), `CmdHF14AMfESet`) sets exactly one 16-byte MIFARE Classic block in emulator memory: it requires precisely 16 hex bytes and calls `mf_elm_set_mem(data, blk, 1)`.

MFU/NTAG emulator memory is different: 4-byte **pages**, stored in BigBuf as an `mfu_dump_t` — a **56-byte prefix** (version[8], tbo, pages, signature[32], counter_tearing[12]) followed by page data. The firmware sim serves GET_VERSION/READ_SIG from that prefix and READ(0x30)/FAST_READ(0x3A) from the page data at BigBuf offset `page*4 + 56`.

No `hf mfu esetblk` exists yet — the MFU emulator family is only `eload` / `esave` / `eview` ([cmdhfmfu.c:8082-8084](../../client/src/cmdhfmfu.c#L8082-L8084)).

The write path is **already width-parameterized**: `mf_eml_set_mem_xt(data, blockNum, count, width)` ([mifarehost.c:1098](../../client/src/mifare/mifarehost.c#L1098)) → `CMD_HF_MIFARE_EML_MEMSET` → device `emlSetMem_xt` (offset = `blockNum * width`). MFU `eload` already calls it with `width = MFU_BLOCK_SIZE (4)`. **So this is a client-only command — no firmware change, no new helper.**

---

## Command

`hf mfu esetblk` — handler `CmdHF14AMfUeSetBlk` in `cmdhfmfu.c`, registered in the MFU command table next to `eload`/`esave`/`eview`:
```c
{"esetblk", CmdHF14AMfUeSetBlk, IfPm3Iso14443a, "Set emulator memory block"},
```

**Args** (mirror `esetblk`):
- `-b` / `--blk <dec>` — start page (required)
- `-d` / `--data <hex>` — page bytes; length a nonzero multiple of 4 (one page = 4 bytes)

**Frictionless multi-page:** the page count is inferred from the data length — no extra flag. One page (`-d <8 hex>`) is the common case (`count = 1`); longer data writes consecutive pages from `--blk`.

---

## Semantics / internals

Write `count = datalen / MFU_BLOCK_SIZE` pages starting at card page `blk`:
```c
mf_eml_set_mem_xt(data, blk + (MFU_DUMP_PREFIX_LENGTH / MFU_BLOCK_SIZE), count, MFU_BLOCK_SIZE);
//                       page blk +  14 (skip the 56-byte mfu_dump_t prefix)   width 4
```
The `+14` targets page data past the prefix, exactly as the firmware's own WRITE(0xA2) handler does (`emlSetMem_xt(..., block + MFU_DUMP_PREFIX_LENGTH/4, 1, 4)`).

Then: `PrintAndLogEx(SUCCESS, "Set %u page(s) from page %u", count, blk)`.

---

## Validation

- `datalen == 0 || datalen % MFU_BLOCK_SIZE != 0` → `"data must be whole pages (multiples of 4 bytes)"`, `PM3_EINVARG`.
- **Max page 254** (not 255): the live MFU emulator data region is `MFU_MAX_BYTES = MFU_MAX_BLOCKS(0xFF) * MFU_BLOCK_SIZE = 1020` bytes = 255 pages, indices **0–254**. Page 255 (`data[1020..1024]`) is beyond what `esave`/`eview` transfer, so cap so everything set is round-trippable:
  ```c
  if ((blk + count) * MFU_BLOCK_SIZE > MFU_MAX_BYTES) {  // last page must be <= 254
      PrintAndLogEx(WARNING, "page range exceeds emulator memory (max page %u)",
                    (MFU_MAX_BYTES / MFU_BLOCK_SIZE) - 1);
      return PM3_EINVARG;
  }
  ```
- Parse `-d` into a buffer sized `MFU_MAX_BYTES` (1020).

> Note on the constants: `MFU_MAX_BLOCKS = 0xFF` is a page **count**, not a max index; `eview`/`esave` validate `end > MFU_MAX_BLOCKS`, which loosely admits `--end 255` even though only pages 0–254 are live. `esetblk` uses the tighter, correct `MFU_MAX_BYTES` bound.

---

## Reuse (no duplication)

- `mf_eml_set_mem_xt` — existing width-parameterized emulator-write helper.
- `CMD_HF_MIFARE_EML_MEMSET` / `emlSetMem_xt` — existing device path, unchanged.
- Model the handler on `CmdHF14AMfESet` ([cmdhfmf.c:5216](../../client/src/cmdhfmf.c#L5216)); the deltas are width 4, the `+14` prefix offset, multi-page count, and the max-254 bound.

---

## Testing

Emulator-memory commands need a connected PM3 but **no card**, and have no offline unit path, so verification is a hardware smoke test:
1. `hf mfu esetblk -b 4 -d 04E10CDA` → `hf mfu eview`, confirm page 4 = `04 E1 0C DA`.
2. Multi-page: `hf mfu esetblk -b 4 -d 04E10CDA993C8048` → `eview`, confirm pages 4-5.
3. Error cases rejected cleanly: odd length (`-d 04E10C`), and out-of-range (`-b 254 -d <16+ bytes>` → would touch page 255).

---

## Out of scope (YAGNI)

- Setting `mfu_dump_t` prefix fields (version/signature/counters) — use `eload` of a full dump.
- `eget` / `eclr` for MFU.
