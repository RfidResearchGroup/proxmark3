//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// ELF file flasher
//-----------------------------------------------------------------------------

#include "flash.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "ui.h"
#include "elf.h"
#include "proxendian.h"
#include "at91sam7s512.h"
#include "util_posix.h"
#include "comms.h"

#define FLASH_START            0x100000

#define BOOTLOADER_SIZE        0x2000
#define BOOTLOADER_END         (FLASH_START + BOOTLOADER_SIZE)

#define BLOCK_SIZE             0x200

#define FLASHER_VERSION        BL_VERSION_1_0_0

static const uint8_t elf_ident[] = {
    0x7f, 'E', 'L', 'F',
    ELFCLASS32,
    ELFDATA2LSB,
    EV_CURRENT
};

static int chipid_to_mem_avail(uint32_t iChipID) {
    int mem_avail = 0;
    switch ((iChipID & 0xF00) >> 8) {
        case 0:
            mem_avail = 0;
            break;
        case 1:
            mem_avail = 8;
            break;
        case 2:
            mem_avail = 16;
            break;
        case 3:
            mem_avail = 32;
            break;
        case 5:
            mem_avail = 64;
            break;
        case 7:
            mem_avail = 128;
            break;
        case 9:
            mem_avail = 256;
            break;
        case 10:
            mem_avail = 512;
            break;
        case 12:
            mem_avail = 1024;
            break;
        case 14:
            mem_avail = 2048;
    }
    return mem_avail;
}

// Turn PHDRs into flasher segments, checking for PHDR sanity and merging adjacent
// unaligned segments if needed
static int build_segs_from_phdrs(flash_file_t *ctx, FILE *fd, Elf32_Phdr_t *phdrs, uint16_t num_phdrs, uint32_t flash_end) {
    Elf32_Phdr_t *phdr = phdrs;
    flash_seg_t *seg;
    uint32_t last_end = 0;

    ctx->segments = calloc(sizeof(flash_seg_t) * num_phdrs, sizeof(uint8_t));
    if (!ctx->segments) {
        PrintAndLogEx(ERR, "Out of memory");
        return PM3_EMALLOC;
    }
    ctx->num_segs = 0;
    seg = ctx->segments;

    PrintAndLogEx(SUCCESS, "Loading usable ELF segments:");
    for (int i = 0; i < num_phdrs; i++) {
        if (le32(phdr->p_type) != PT_LOAD) {
            phdr++;
            continue;
        }
        uint32_t vaddr = le32(phdr->p_vaddr);
        uint32_t paddr = le32(phdr->p_paddr);
        uint32_t filesz = le32(phdr->p_filesz);
        uint32_t memsz = le32(phdr->p_memsz);
        uint32_t offset = le32(phdr->p_offset);
        uint32_t flags = le32(phdr->p_flags);
        if (!filesz) {
            phdr++;
            continue;
        }
        PrintAndLogEx(SUCCESS, "   "_YELLOW_("%d")": V 0x%08x P 0x%08x (0x%08x->0x%08x) [%c%c%c] @0x%x",
                      i, vaddr, paddr, filesz, memsz,
                      (flags & PF_R) ? 'R' : ' ',
                      (flags & PF_W) ? 'W' : ' ',
                      (flags & PF_X) ? 'X' : ' ',
                      offset);
        if (filesz != memsz) {
            PrintAndLogEx(ERR, "Error: PHDR file size does not equal memory size\n"
                          "(DATA+BSS PHDRs do not make sense on ROM platforms!)");
            return PM3_EFILE;
        }
        if (paddr < last_end) {
            PrintAndLogEx(ERR, "Error: PHDRs not sorted or overlap");
            return PM3_EFILE;
        }
        if (paddr < FLASH_START || (paddr + filesz) > flash_end) {
            PrintAndLogEx(ERR, "Error: PHDR is not contained in Flash");
            if ((paddr + filesz) > flash_end) {
                PrintAndLogEx(ERR, "Firmware is probably too big for your device");
                PrintAndLogEx(ERR, "See README.md for information on compiling for platforms with 256KB of flash memory");
            }
            return PM3_EFILE;
        }
        if (vaddr >= FLASH_START && vaddr < flash_end && (flags & PF_W)) {
            PrintAndLogEx(ERR, "Error: Flash VMA segment is writable");
            return PM3_EFILE;
        }

        uint8_t *data;
        // make extra space if we need to move the data forward
        data = calloc(filesz + BLOCK_SIZE, sizeof(uint8_t));
        if (!data) {
            PrintAndLogEx(ERR, "Error: Out of memory");
            return PM3_EMALLOC;
        }
        if (fseek(fd, offset, SEEK_SET) < 0 || fread(data, 1, filesz, fd) != filesz) {
            PrintAndLogEx(ERR, "Error while reading PHDR payload");
            free(data);
            return PM3_EFILE;
        }

        uint32_t block_offset = paddr & (BLOCK_SIZE - 1);
        if (block_offset) {
            if (ctx->num_segs) {
                flash_seg_t *prev_seg = seg - 1;
                uint32_t this_end = paddr + filesz;
                uint32_t this_firstblock = paddr & ~(BLOCK_SIZE - 1);
                uint32_t prev_lastblock = (last_end - 1) & ~(BLOCK_SIZE - 1);

                if (this_firstblock == prev_lastblock) {
                    uint32_t new_length = this_end - prev_seg->start;
                    uint32_t this_offset = paddr - prev_seg->start;
                    uint32_t hole = this_offset - prev_seg->length;
                    uint8_t *new_data = calloc(new_length, sizeof(uint8_t));
                    if (!new_data) {
                        PrintAndLogEx(ERR, "Error: Out of memory");
                        free(data);
                        return PM3_EMALLOC;
                    }
                    memset(new_data, 0xff, new_length);
                    memcpy(new_data, prev_seg->data, prev_seg->length);
                    memcpy(new_data + this_offset, data, filesz);
                    PrintAndLogEx(INFO, "Note: Extending previous segment from 0x%x to 0x%x bytes",
                                  prev_seg->length, new_length);
                    if (hole)
                        PrintAndLogEx(INFO, "Note: 0x%x-byte hole created", hole);
                    free(data);
                    free(prev_seg->data);
                    prev_seg->data = new_data;
                    prev_seg->length = new_length;
                    last_end = this_end;
                    phdr++;
                    continue;
                }
            }
            PrintAndLogEx(WARNING, "Warning: segment does not begin on a block boundary, will pad");
            memmove(data + block_offset, data, filesz);
            memset(data, 0xFF, block_offset);
            filesz += block_offset;
            paddr -= block_offset;
        }

        seg->data = data;
        seg->start = paddr;
        seg->length = filesz;
        seg++;
        ctx->num_segs++;

        last_end = paddr + filesz;
        phdr++;
    }
    return PM3_SUCCESS;
}

// Sanity check segments and check for bootloader writes
static int check_segs(flash_file_t *ctx, int can_write_bl, uint32_t flash_end) {
    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        if (seg->start & (BLOCK_SIZE - 1)) {
            PrintAndLogEx(ERR, "Error: Segment is not aligned");
            return PM3_EFILE;
        }
        if (seg->start < FLASH_START) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return PM3_EFILE;
        }
        if (seg->start + seg->length > flash_end) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return PM3_EFILE;
        }
        if (!can_write_bl && seg->start < BOOTLOADER_END) {
            PrintAndLogEx(ERR, "Attempted to write bootloader but bootloader writes are not enabled");
            return PM3_EINVARG;
        }
        if (can_write_bl && seg->start < BOOTLOADER_END && (seg->start + seg->length > BOOTLOADER_END)) {
            PrintAndLogEx(ERR, "Error: Segment is outside of bootloader bounds");
            return PM3_EFILE;
        }
    }
    return PM3_SUCCESS;
}

// Load an ELF file and prepare it for flashing
int flash_load(flash_file_t *ctx, const char *name, int can_write_bl, int flash_size) {
    FILE *fd;
    Elf32_Ehdr_t ehdr;
    Elf32_Phdr_t *phdrs = NULL;
    uint16_t num_phdrs;
    uint32_t flash_end  = FLASH_START + flash_size;
    int res = PM3_EUNDEF;

    fd = fopen(name, "rb");
    if (!fd) {
        PrintAndLogEx(ERR, _RED_("Could not open file") " %s  >>> ", name);
        res = PM3_EFILE;
        goto fail;
    }

    PrintAndLogEx(SUCCESS, _CYAN_("Loading ELF file") _YELLOW_(" %s"), name);

    if (fread(&ehdr, sizeof(ehdr), 1, fd) != 1) {
        PrintAndLogEx(ERR, "Error while reading ELF file header");
        res = PM3_EFILE;
        goto fail;
    }
    if (memcmp(ehdr.e_ident, elf_ident, sizeof(elf_ident))
            || le32(ehdr.e_version) != 1) {
        PrintAndLogEx(ERR, "Not an ELF file or wrong ELF type");
        res = PM3_EFILE;
        goto fail;
    }
    if (le16(ehdr.e_type) != ET_EXEC) {
        PrintAndLogEx(ERR, "ELF is not executable");
        res = PM3_EFILE;
        goto fail;
    }
    if (le16(ehdr.e_machine) != EM_ARM) {
        PrintAndLogEx(ERR, "Wrong ELF architecture");
        res = PM3_EFILE;
        goto fail;
    }
    if (!ehdr.e_phnum || !ehdr.e_phoff) {
        PrintAndLogEx(ERR, "ELF has no PHDRs");
        res = PM3_EFILE;
        goto fail;
    }
    if (le16(ehdr.e_phentsize) != sizeof(Elf32_Phdr_t)) {
        // could be a structure padding issue...
        PrintAndLogEx(ERR, "Either the ELF file or this code is made of fail");
        res = PM3_EFILE;
        goto fail;
    }
    num_phdrs = le16(ehdr.e_phnum);

    phdrs = calloc(le16(ehdr.e_phnum) * sizeof(Elf32_Phdr_t), sizeof(uint8_t));
    if (!phdrs) {
        PrintAndLogEx(ERR, "Out of memory");
        res = PM3_EMALLOC;
        goto fail;
    }
    if (fseek(fd, le32(ehdr.e_phoff), SEEK_SET) < 0) {
        PrintAndLogEx(ERR, "Error while reading ELF PHDRs");
        res = PM3_EFILE;
        goto fail;
    }
    if (fread(phdrs, sizeof(Elf32_Phdr_t), num_phdrs, fd) != num_phdrs) {
        res = PM3_EFILE;
        PrintAndLogEx(ERR, "Error while reading ELF PHDRs");
        goto fail;
    }

    res = build_segs_from_phdrs(ctx, fd, phdrs, num_phdrs, flash_end);
    if (res != PM3_SUCCESS)
        goto fail;
    res = check_segs(ctx, can_write_bl, flash_end);
    if (res != PM3_SUCCESS)
        goto fail;

    free(phdrs);
    fclose(fd);
    ctx->filename = name;
    return PM3_SUCCESS;

fail:
    if (phdrs)
        free(phdrs);
    if (fd)
        fclose(fd);
    flash_free(ctx);
    return res;
}

// Get the state of the proxmark, backwards compatible
static int get_proxmark_state(uint32_t *state) {
    SendCommandBL(CMD_DEVICE_INFO, 0, 0, 0, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_UNKNOWN, &resp);  // wait for any response. No timeout.

    // Three outcomes:
    // 1. The old bootrom code will ignore CMD_DEVICE_INFO, but respond with an ACK
    // 2. The old os code will respond with CMD_DEBUG_PRINT_STRING and "unknown command"
    // 3. The new bootrom and os codes will respond with CMD_DEVICE_INFO and flags

    switch (resp.cmd) {
        case CMD_ACK:
            *state = DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM;
            break;
        case CMD_DEBUG_PRINT_STRING:
            *state = DEVICE_INFO_FLAG_CURRENT_MODE_OS;
            break;
        case CMD_DEVICE_INFO:
            *state = resp.oldarg[0];
            break;
        default:
            PrintAndLogEx(ERR, _RED_("Error:") " Couldn't get Proxmark3 state, bad response type: 0x%04x", resp.cmd);
            return PM3_EFATAL;
            break;
    }
    return PM3_SUCCESS;
}

// Enter the bootloader to be able to start flashing
static int enter_bootloader(char *serial_port_name) {
    uint32_t state;
    int ret;

    if ((ret = get_proxmark_state(&state)) != PM3_SUCCESS)
        return ret;

    /* Already in flash state, we're done. */
    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM)
        return PM3_SUCCESS;

    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) {
        PrintAndLogEx(SUCCESS, _CYAN_("Entering bootloader..."));

        if ((state & DEVICE_INFO_FLAG_BOOTROM_PRESENT)
                && (state & DEVICE_INFO_FLAG_OSIMAGE_PRESENT)) {
            // New style handover: Send CMD_START_FLASH, which will reset the board
            // and enter the bootrom on the next boot.
            SendCommandBL(CMD_START_FLASH, 0, 0, 0, NULL, 0);
            PrintAndLogEx(SUCCESS, "(Press and release the button only to " _YELLOW_("abort") ")");
        } else {
            // Old style handover: Ask the user to press the button, then reset the board
            SendCommandBL(CMD_HARDWARE_RESET, 0, 0, 0, NULL, 0);
            PrintAndLogEx(SUCCESS, "Press and hold down button NOW if your bootloader requires it.");
        }
        msleep(100);
        CloseProxmark(g_session.current_device);
        // Let time to OS to make the port disappear
        msleep(1000);

        if (OpenProxmark(&g_session.current_device, serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
            PrintAndLogEx(NORMAL, _GREEN_(" found"));
            return PM3_SUCCESS;
        } else {
            PrintAndLogEx(ERR, _RED_("Error:") " Proxmark3 not found.");
            return PM3_ETIMEOUT;
        }
    }

    PrintAndLogEx(ERR, _RED_("Error:") " Unknown Proxmark3 mode");
    return PM3_EFATAL;
}

static int wait_for_ack(PacketResponseNG *ack) {
    WaitForResponse(CMD_UNKNOWN, ack);

    if (ack->cmd != CMD_ACK) {
        PrintAndLogEx(ERR, "Error: Unexpected reply 0x%04x %s (expected ACK)",
                      ack->cmd,
                      (ack->cmd == CMD_NACK) ? "NACK" : ""
                     );
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static bool gs_printed_msg = false;
static void flash_suggest_update_bootloader(void) {
    if (gs_printed_msg)
        return;

    PrintAndLogEx(ERR, _RED_("It is recommended that you first" _YELLOW_(" update your bootloader") _RED_(" alone,")));
    PrintAndLogEx(ERR, _RED_("reboot the Proxmark3 then only update the main firmware") "\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(ERR, "------------- " _CYAN_("Follow these steps") " -------------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(ERR, " 1)   ./pm3-flash-bootrom");
    PrintAndLogEx(ERR, " 2)   ./pm3-flash-all");
    PrintAndLogEx(ERR, " 3)   ./pm3");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
    gs_printed_msg = true;
}

static void flash_suggest_update_flasher(void) {
    PrintAndLogEx(ERR, _RED_("It is recommended that you first " _YELLOW_("update your flasher")));
}

// Go into flashing mode
int flash_start_flashing(int enable_bl_writes, char *serial_port_name, uint32_t *max_allowed) {
    uint32_t state;
    uint32_t chipinfo = 0;
    int ret;

    ret = enter_bootloader(serial_port_name);
    if (ret != PM3_SUCCESS)
        return ret;

    ret = get_proxmark_state(&state);
    if (ret != PM3_SUCCESS)
        return ret;

    if (state & DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO) {
        SendCommandBL(CMD_CHIP_INFO, 0, 0, 0, NULL, 0);
        PacketResponseNG resp;
        WaitForResponse(CMD_CHIP_INFO, &resp);
        chipinfo = resp.oldarg[0];
    }

    int version = BL_VERSION_INVALID;
    if (state & DEVICE_INFO_FLAG_UNDERSTANDS_VERSION) {
        SendCommandBL(CMD_BL_VERSION, 0, 0, 0, NULL, 0);
        PacketResponseNG resp;
        WaitForResponse(CMD_BL_VERSION, &resp);
        version = resp.oldarg[0];
        if ((BL_VERSION_MAJOR(version) < BL_VERSION_FIRST_MAJOR) || (BL_VERSION_MAJOR(version) > BL_VERSION_LAST_MAJOR)) {
            // version info seems fishy
            version = BL_VERSION_INVALID;
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ==========================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader reported an invalid version number"));
            flash_suggest_update_bootloader();
            //
        } else if (BL_VERSION_MAJOR(version) < BL_VERSION_MAJOR(FLASHER_VERSION)) {
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ==================================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader reported a version older than this flasher"));
            flash_suggest_update_bootloader();
        } else if (BL_VERSION_MAJOR(version) > BL_VERSION_MAJOR(FLASHER_VERSION)) {
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ========================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader is more recent than this flasher"));
            flash_suggest_update_flasher();
        }
    } else {
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ==========================================="));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" CMD_BL_VERSION") _RED_(" command")));
        flash_suggest_update_bootloader();
    }

    uint32_t flash_end = FLASH_START + AT91C_IFLASH_PAGE_SIZE * AT91C_IFLASH_NB_OF_PAGES / 2;
    *max_allowed = 256;

    int mem_avail = chipid_to_mem_avail(chipinfo);
    if (mem_avail != 0) {
        PrintAndLogEx(INFO, "Available memory on this board: "_YELLOW_("%uK") " bytes\n", mem_avail);
        if (mem_avail > 256) {
            if (BL_VERSION_MAJOR(version) < BL_VERSION_MAJOR(BL_VERSION_1_0_0)) {
                PrintAndLogEx(ERR, _RED_("====================== OBS ! ======================"));
                PrintAndLogEx(ERR, _RED_("Your bootloader does not support writing above 256k"));
                flash_suggest_update_bootloader();
            } else {
                flash_end = FLASH_START + AT91C_IFLASH_PAGE_SIZE * AT91C_IFLASH_NB_OF_PAGES;
                *max_allowed = mem_avail;
            }
        }
    } else {
        PrintAndLogEx(INFO, "Available memory on this board: "_RED_("UNKNOWN")"\n");
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ======================================"));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" CHIP_INFO") _RED_(" command")));
        flash_suggest_update_bootloader();
    }

    if (enable_bl_writes) {
        PrintAndLogEx(INFO, "Permitted flash range: 0x%08x-0x%08x", FLASH_START, flash_end);
    } else {
        PrintAndLogEx(INFO, "Permitted flash range: 0x%08x-0x%08x", BOOTLOADER_END, flash_end);
    }
    if (state & DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) {
        PacketResponseNG resp;

        if (enable_bl_writes) {
            SendCommandBL(CMD_START_FLASH, FLASH_START, flash_end, START_FLASH_MAGIC, NULL, 0);
        } else {
            SendCommandBL(CMD_START_FLASH, BOOTLOADER_END, flash_end, 0, NULL, 0);
        }
        return wait_for_ack(&resp);
    } else {
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ========================================"));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" START_FLASH") _RED_(" command")));
        flash_suggest_update_bootloader();
    }
    return PM3_SUCCESS;
}

static int write_block(uint32_t address, uint8_t *data, uint32_t length) {
    uint8_t block_buf[BLOCK_SIZE];
    memset(block_buf, 0xFF, BLOCK_SIZE);
    memcpy(block_buf, data, length);
    PacketResponseNG resp;
#if defined ICOPYX
    SendCommandBL(CMD_FINISH_WRITE, address, 0xff, 0x1fd, block_buf, length);
#else
    SendCommandBL(CMD_FINISH_WRITE, address, 0, 0, block_buf, length);
#endif
    int ret = wait_for_ack(&resp);
    if (ret && resp.oldarg[0]) {
        uint32_t lock_bits = resp.oldarg[0] >> 16;
        bool lock_error = resp.oldarg[0] & AT91C_MC_LOCKE;
        bool prog_error = resp.oldarg[0] & AT91C_MC_PROGE;
        bool security_bit = resp.oldarg[0] & AT91C_MC_SECURITY;
        PrintAndLogEx(NORMAL, "%s", lock_error ? "       Lock Error" : "");
        PrintAndLogEx(NORMAL, "%s", prog_error ? "       Invalid Command or bad Keyword" : "");
        PrintAndLogEx(NORMAL, "%s", security_bit ? "       Security Bit is set!" : "");
        PrintAndLogEx(NORMAL, "       Lock Bits:      0x%04x", lock_bits);
    }
    return ret;
}

static const char ice[] =
    "...................................................................\n        @@@  @@@@@@@ @@@@@@@@ @@@@@@@@@@   @@@@@@  @@@  @@@\n"
    "        @@! !@@      @@!      @@! @@! @@! @@!  @@@ @@!@!@@@\n        !!@ !@!      @!!!:!   @!! !!@ @!@ @!@!@!@! @!@@!!@!\n"
    "        !!: :!!      !!:      !!:     !!: !!:  !!! !!:  !!!\n        :    :: :: : : :: :::  :      :    :   : : ::    : \n"
    _RED_("        .    .. .. . . .. ...  .      .    .   . . ..    . ")
    "\n...................................................................\n"
    "...................................................................\n"
    ;

// Write a file's segments to Flash
int flash_write(flash_file_t *ctx) {
    int len = 0;

    PrintAndLogEx(SUCCESS, "Writing segments for file: %s", ctx->filename);

    bool filter_ansi = !g_session.supports_colors;

    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        uint32_t length = seg->length;
        uint32_t blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        uint32_t end = seg->start + length;

        PrintAndLogEx(SUCCESS, " 0x%08x..0x%08x [0x%x / %u blocks]", seg->start, end - 1, length, blocks);
        fflush(stdout);
        int block = 0;
        uint8_t *data = seg->data;
        uint32_t baddr = seg->start;

        while (length) {
            uint32_t block_size = length;
            if (block_size > BLOCK_SIZE)
                block_size = BLOCK_SIZE;

            if (write_block(baddr, data, block_size) < 0) {
                PrintAndLogEx(ERR, "Error writing block %d of %u", block, blocks);
                return PM3_EFATAL;
            }

            data += block_size;
            baddr += block_size;
            length -= block_size;
            block++;
            if (len < strlen(ice)) {
                if (filter_ansi && !isalpha(ice[len])) {
                    len++;
                } else {
                    fprintf(stdout, "%c", ice[len++]);
                }
            } else {
                fprintf(stdout, ".");
            }
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, " " _GREEN_("OK"));
        fflush(stdout);
    }
    return PM3_SUCCESS;
}

// free a file context
void flash_free(flash_file_t *ctx) {
    if (!ctx)
        return;
    if (ctx->segments) {
        for (int i = 0; i < ctx->num_segs; i++)
            free(ctx->segments[i].data);
        free(ctx->segments);
        ctx->segments = NULL;
        ctx->num_segs = 0;
    }
}

// just reset the unit
int flash_stop_flashing(void) {
    SendCommandBL(CMD_HARDWARE_RESET, 0, 0, 0, NULL, 0);
    msleep(100);
    return PM3_SUCCESS;
}
