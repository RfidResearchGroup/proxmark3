# hf mfu esetblk Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a client-only `hf mfu esetblk` command that writes one or more 4-byte pages into MFU/NTAG emulator memory, mirroring `hf mf esetblk` but for Ultralight page structures.

**Architecture:** A single new handler `CmdHF14AMfUeSetBlk` in `client/src/cmdhfmfu.c` that parses `--blk`/`--data`, validates whole-page data and the max-254 page bound, and calls the existing width-parameterized helper `mf_eml_set_mem_xt(...)` with `width=4` and a `+14` page offset (to skip the 56-byte `mfu_dump_t` prefix). Registered in the MFU command table. No firmware change, no new helpers.

**Tech Stack:** C (proxmark3 client), CLIParser arg tables, `mf_eml_set_mem_xt` → `CMD_HF_MIFARE_EML_MEMSET`. Build: `make client`. Design: `docs/plans/2026-07-02-hf-mfu-esetblk-design.md`.

**Note on testing:** MFU emulator commands are `IfPm3Iso14443a` (device required) and have **no offline unit-test path**. So this plan is not TDD — verification is: clean build, `-h` help renders offline, and an on-device smoke test (PM3 needed, **no card**). The logic is a close structural copy of the already-working `hf mf esetblk`.

---

## Task 1: Implement and register `hf mfu esetblk`

**Files:**
- Modify: `client/src/cmdhfmfu.c` — add handler `CmdHF14AMfUeSetBlk` (near the other `CmdHF14AMfUe*` handlers) + one command-table row.
- Reference (read, do not modify): `client/src/cmdhfmf.c:5216` (`CmdHF14AMfESet`, the template); `client/src/mifare/mifarehost.c:1098` (`mf_eml_set_mem_xt` signature).

**Step 1: Confirm the helper is declared for this translation unit.**

Run: `grep -nE 'mf_eml_set_mem_xt' /home/work/proxmark3/.worktrees/hf-mfu-esetblk/client/src/mifare/mifarehost.h`
Expected: a prototype line. If cmdhfmfu.c does not already include `mifare/mifarehost.h`, add `#include "mifare/mifarehost.h"` with the other includes. (Confirm it compiles in Step 4.)

Signature to use:
```c
int mf_eml_set_mem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);
```

**Step 2: Add the handler** in `client/src/cmdhfmfu.c` (place it just above the `CommandTable[]` array, next to `CmdHF14AMfuEView` / `CmdHF14AMfUeLoad`):

```c
static int CmdHF14AMfUeSetBlk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu esetblk",
                  "Set emulator memory page(s). One page = 4 bytes; pass multiple\n"
                  "whole pages of data to set consecutive pages from --blk.",
                  "hf mfu esetblk --blk 4 -d 04E10CDA\n"
                  "hf mfu esetblk --blk 4 -d 04E10CDA993C8048   -> sets pages 4-5\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "page number to start at"),
        arg_str0("d", "data", "<hex>", "bytes to write, whole pages (multiple of 4 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int blk = arg_get_int_def(ctx, 1, 0);

    uint8_t data[MFU_MAX_BYTES] = {0x00};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &datalen);
    CLIParserFree(ctx);
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    if (blk < 0) {
        PrintAndLogEx(WARNING, "page number must be positive");
        return PM3_EINVARG;
    }

    if (datalen == 0 || (datalen % MFU_BLOCK_SIZE) != 0) {
        PrintAndLogEx(WARNING, "data must be whole pages (multiples of %d bytes). Got %i", MFU_BLOCK_SIZE, datalen);
        return PM3_EINVARG;
    }

    int count = datalen / MFU_BLOCK_SIZE;

    // live MFU emulator data region is MFU_MAX_BYTES (pages 0..254); page 255 is not round-trippable
    if ((blk + count) * MFU_BLOCK_SIZE > MFU_MAX_BYTES) {
        PrintAndLogEx(WARNING, "page range exceeds emulator memory (max page %u)", (MFU_MAX_BYTES / MFU_BLOCK_SIZE) - 1);
        return PM3_EINVARG;
    }

    // MFU emulator page data starts after the 56-byte mfu_dump_t prefix, so shift the
    // page index by MFU_DUMP_PREFIX_LENGTH/MFU_BLOCK_SIZE (=14), width = MFU_BLOCK_SIZE (4).
    res = mf_eml_set_mem_xt(data, blk + (MFU_DUMP_PREFIX_LENGTH / MFU_BLOCK_SIZE), count, MFU_BLOCK_SIZE);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed to set emulator memory");
        return res;
    }

    PrintAndLogEx(SUCCESS, "Set " _YELLOW_("%d") " page(s) from page " _YELLOW_("%d"), count, blk);
    return PM3_SUCCESS;
}
```

**Step 3: Register the command** in the MFU `CommandTable[]` (near `eload`/`esave`/`eview`, ~cmdhfmfu.c:8082-8084):

```c
    {"esetblk",  CmdHF14AMfUeSetBlk,        IfPm3Iso14443a,  "Set emulator memory block"},
```

**Step 4: Build.**

Run: `cd /home/work/proxmark3/.worktrees/hf-mfu-esetblk && make client -j"$(nproc)"`
Expected: clean build, no warnings on cmdhfmfu.c, `client/proxmark3` linked.

**Step 5: Verify help renders (offline).**

Run: `QT_QPA_PLATFORM=offscreen ./pm3 -o -c 'hf mfu esetblk -h'`
Expected: usage text with `--blk` and `--data`, no crash.
Also confirm it now appears in the menu: `QT_QPA_PLATFORM=offscreen ./pm3 -o -c 'hf mfu help'` lists `esetblk`.

**Step 6: Commit.**

```bash
cd /home/work/proxmark3/.worktrees/hf-mfu-esetblk
git add client/src/cmdhfmfu.c
git commit -m "feat(mfu): add hf mfu esetblk to set emulator memory pages"
```

---

## Task 2: On-device smoke test (requires a PM3, no card)

Not automatable here — hand these to the user. Record results in the commit/PR notes.

1. **Single page:** `hf mfu esetblk -b 4 -d 04E10CDA` → then `hf mfu eview` → page 4 shows `04 E1 0C DA`.
2. **Multi-page:** `hf mfu esetblk -b 4 -d 04E10CDA993C8048` → `eview` → pages 4 and 5 both set.
3. **Odd length rejected:** `hf mfu esetblk -b 4 -d 04E10C` → `"data must be whole pages…"`, no write.
4. **Out of range rejected:** `hf mfu esetblk -b 254 -d 0011223344556677` (2 pages → would touch page 255) → `"page range exceeds emulator memory (max page 254)"`.
5. **Round-trip:** `esetblk` a few pages → `hf mfu esave -f /tmp/t` → reload/compare, confirm the set pages persisted.

---

## YAGNI / out of scope
- Setting `mfu_dump_t` prefix fields (version/signature/counters) — use `eload`.
- `eget`/`eclr` for MFU.
- Any firmware change (none needed).
