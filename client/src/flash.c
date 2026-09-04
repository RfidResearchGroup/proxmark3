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
#include <signal.h>

#include "ui.h"
#include "elf.h"
#include "proxendian.h"
#include "util_posix.h"
#include "comms.h"
#include "commonutil.h"
#include "fileutils.h"
#include "frame_progress.h"

#include "at91sam7s512.h"
// #include "at32f435_437_flash.h" TODO DXL makefile include dirs need add 'armlib/at32_sys/drivers/inc'

// #define BLOCK_SIZE_AT32             0x800 // For at32, if flash size is 4m, the sector size is 4096byte, otherwise 2048byte.
#define FLASH_START_AT32            0x08000000
#define BOOTLOADER_SIZE_AT32        0x4000 // defined in 'ldscript.defs.at32'
#define BOOTLOADER_END_AT32         (FLASH_START_AT32 + BOOTLOADER_SIZE_AT32)

// AT91 series universal definition.
#define BLOCK_SIZE_AT91             0x200 // For at91, 512byte = 2page
#define FLASH_START_AT91            0x100000
#define BOOTLOADER_SIZE_AT91        0x2000 // defined in 'ldscript.defs.at91'
#define BOOTLOADER_END_AT91         (FLASH_START_AT91 + BOOTLOADER_SIZE_AT91)

// It is best for the version number of the flasher to be consistent with the version number of the bootrom,
// otherwise some capabilities may be missing.
#define FLASHER_VERSION        BL_VERSION_1_0_0

static const uint8_t elf_ident[] = {
    0x7f, 'E', 'L', 'F',
    ELFCLASS32,
    ELFDATA2LSB,
    EV_CURRENT
};

// TODO DXL It's best to encapsulate and reuse the code here, and put it in commonutil
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

// TODO DXL It's best to encapsulate and reuse the code here, and put it in commonutil
static int chipid_to_mem_avail_at32(uint32_t idcode) {
    struct {
        uint32_t id;         // idcode
        uint32_t flash_size; // KB
    } at32_idcode_mem_map[] = {
        {0x70084540, 4032},   // AT32F435ZMT7
        {0x70083341, 1024},   // AT32F435ZGT7
        {0x70083242, 256},    // AT32F435ZCT7
        {0x70084543, 4032},   // AT32F435VMT7
        {0x70083344, 1024},   // AT32F435VGT7
        {0x70083245, 256},    // AT32F435VCT7
        {0x70084546, 4032},   // AT32F435RMT7
        {0x70083347, 1024},   // AT32F435RGT7
        {0x70083248, 256},    // AT32F435RCT7
        {0x70084549, 4032},   // AT32F435CMT7
        {0x7008334A, 1024},   // AT32F435CGT7
        {0x7008324B, 256},    // AT32F435CCT7
        {0x7008454C, 4032},   // AT32F435CMU7
        {0x7008334D, 1024},   // AT32F435CGU7
        {0x7008324E, 256},    // AT32F435CCU7
        {0x7008454F, 4032},   // AT32F437ZMT7
        {0x70083350, 1024},   // AT32F437ZGT7
        {0x70083251, 256},    // AT32F437ZCT7
        {0x70084552, 4032},   // AT32F437VMT7
        {0x70083353, 1024},   // AT32F437VGT7
        {0x70083254, 256},    // AT32F437VCT7
        {0x70084555, 4032},   // AT32F437RMT7
        {0x70083356, 1024},   // AT32F437RGT7
        {0x70083257, 256},    // AT32F437RCT7
    };
    for (size_t i = 0; i < ARRAYLEN(at32_idcode_mem_map); i++) {
        if (at32_idcode_mem_map[i].id == idcode) {
            return at32_idcode_mem_map[i].flash_size;
        }
    }
    return 256; // No idcode found? return a min size.
}

// Turn PHDRs into flasher segments, checking for PHDR sanity and merging adjacent
// unaligned segments if needed
static int build_segs_from_phdrs(flash_file_t *ctx, flash_dev_t *flash_dev) {
    Elf32_Phdr_t *phdr = ctx->phdrs;
    flash_seg_t *seg;
    uint32_t last_end = 0;

    ctx->segments = calloc(sizeof(flash_seg_t) * ctx->num_phdrs, sizeof(uint8_t));
    if (!ctx->segments) {
        PrintAndLogEx(ERR, "Out of memory");
        return PM3_EMALLOC;
    }
    ctx->num_segs = 0;
    seg = ctx->segments;

    PrintAndLogEx(SUCCESS, "Loading usable ELF segments:");
    for (int i = 0; i < ctx->num_phdrs; i++) {
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
        if (paddr < flash_dev->flash_start || (paddr + filesz) > flash_dev->flash_end) {
            PrintAndLogEx(ERR, "Error: PHDR is not contained in Flash");
            if ((paddr + filesz) > flash_dev->flash_end) {
                PrintAndLogEx(ERR, "Firmware is probably too big for your device");
                PrintAndLogEx(ERR, "See README.md for information on compiling for platforms with 256KB of flash memory");
            }
            return PM3_EFILE;
        }
        if (vaddr >= flash_dev->flash_start && vaddr < flash_dev->flash_end && (flags & PF_W)) {
            PrintAndLogEx(ERR, "Error: Flash VMA segment is writable");
            return PM3_EFILE;
        }

        uint8_t *data;
        // make extra space if we need to move the data forward
        data = calloc(filesz + flash_dev->block_size, sizeof(uint8_t));
        if (!data) {
            PrintAndLogEx(ERR, "Error: Out of memory");
            return PM3_EMALLOC;
        }
        memcpy(data, ctx->elf + offset, filesz);

        uint32_t block_offset = paddr & (flash_dev->block_size - 1);
        if (block_offset) {
            if (ctx->num_segs) {
                flash_seg_t *prev_seg = seg - 1;
                uint32_t this_end = paddr + filesz;
                uint32_t this_firstblock = paddr & ~(flash_dev->block_size - 1);
                uint32_t prev_lastblock = (last_end - 1) & ~(flash_dev->block_size - 1);

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
static int check_segs(flash_file_t *ctx, int can_write_bl, flash_dev_t *flash_dev) {
    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        if (seg->start & (flash_dev->block_size - 1)) {
            PrintAndLogEx(ERR, "Error: Segment is not aligned");
            return PM3_EFILE;
        }
        if (seg->start < flash_dev->flash_start) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return PM3_EFILE;
        }
        if (seg->start + seg->length > flash_dev->flash_end) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return PM3_EFILE;
        }
        if (!can_write_bl && seg->start < flash_dev->boot_end) {
            PrintAndLogEx(ERR, "Attempted to write bootloader but bootloader writes are not enabled");
            return PM3_EINVARG;
        }
        if (can_write_bl && seg->start < flash_dev->boot_end && (seg->start + seg->length > flash_dev->boot_end)) {
            PrintAndLogEx(ERR, "Error: Segment is outside of bootloader bounds");
            return PM3_EFILE;
        }
    }
    return PM3_SUCCESS;
}

// Check version information section for sanity and compatibility with the client, and print it if valid
static int print_and_validate_version(flash_file_t *ctx) {
    if (!CheckValidInformationMagic(ctx->ver_info)) {
        PrintAndLogEx(ERR, _RED_("ELF file does not contain valid version information"
                                 "(magic = 0x%08x)"), ctx->ver_info->magic);
        return PM3_EFILE;
    }

    // same limit as for ARM image
    char temp[PM3_CMD_DATA_SIZE - 12] = {0};
    FormatVersionInformation(temp, sizeof(temp), "", ctx->ver_info);
    PrintAndLogEx(SUCCESS, _CYAN_("ELF file version") _YELLOW_(" %s"), temp);

    if (strlen(g_version_information.armsrc) == 9) {
        if (strncmp(ctx->ver_info->armsrc, g_version_information.armsrc, 9) != 0) {
            PrintAndLogEx(WARNING, _RED_("ARM firmware does not match the source at the time the client was compiled"));
            return PM3_EINVARG;
        } else {
            return PM3_SUCCESS;
        }
    }
    return PM3_EUNDEF;
}

// Load an ELF file for flashing
int flash_load(flash_file_t *ctx, bool force) {
    FILE *fd;
    Elf32_Ehdr_t *ehdr;
    Elf32_Shdr_t *shdrs = NULL;
    uint8_t *shstr = NULL;
    int res = PM3_EUNDEF;

    fd = fopen(ctx->filename, "rb");
    if (fd == NULL) {
        PrintAndLogEx(ERR, _RED_("Could not open file") " %s  >>> ", ctx->filename);
        res = PM3_EFILE;
        goto fail;
    }

    PrintAndLogEx(SUCCESS, _CYAN_("Loading ELF file") _YELLOW_(" %s"), ctx->filename);

    // get filesize in order to malloc memory
    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(ERR, "Error, when getting filesize");
        res = PM3_EFILE;
        fclose(fd);
        goto fail;
    }

    ctx->elf = calloc(fsize + 1, sizeof(uint8_t));
    if (ctx->elf == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        res = PM3_EMALLOC;
        fclose(fd);
        goto fail;
    }

    size_t bytes_read = fread(ctx->elf, 1, fsize, fd);
    fclose(fd);

    if (bytes_read != fsize) {
        PrintAndLogEx(ERR, "Error, bytes read mismatch file size");
        res = PM3_EFILE;
        goto fail;
    }

    ehdr = (Elf32_Ehdr_t *)ctx->elf;
    if (memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))
            || le32(ehdr->e_version) != 1) {
        PrintAndLogEx(ERR, "Not an ELF file or wrong ELF type");
        res = PM3_EFILE;
        goto fail;
    }

    if (le16(ehdr->e_type) != ET_EXEC) {
        PrintAndLogEx(ERR, "ELF is not executable");
        res = PM3_EFILE;
        goto fail;
    }

    if (le16(ehdr->e_machine) != EM_ARM) {
        PrintAndLogEx(ERR, "Wrong ELF architecture");
        res = PM3_EFILE;
        goto fail;
    }

    if (!ehdr->e_phnum || !ehdr->e_phoff) {
        PrintAndLogEx(ERR, "ELF has no PHDRs");
        res = PM3_EFILE;
        goto fail;
    }

    if (le16(ehdr->e_phentsize) != sizeof(Elf32_Phdr_t)) {
        // could be a structure padding issue...
        PrintAndLogEx(ERR, "Either the ELF file or this code is made of fail");
        res = PM3_EFILE;
        goto fail;
    }

    ctx->num_phdrs = le16(ehdr->e_phnum);
    ctx->phdrs = (Elf32_Phdr_t *)(ctx->elf + le32(ehdr->e_phoff));
    shdrs = (Elf32_Shdr_t *)(ctx->elf + le32(ehdr->e_shoff));
    shstr = ctx->elf + le32(shdrs[ehdr->e_shstrndx].sh_offset);

    for (uint16_t i = 0; i < le16(ehdr->e_shnum); i++) {

        if (strcmp(((char *)shstr) + shdrs[i].sh_name, ".version_information") == 0) {
            ctx->ver_info = (struct version_information_t *)(ctx->elf + le32(shdrs[i].sh_offset));
            res = print_and_validate_version(ctx);
            break;
        }

        if (strcmp(((char *)shstr) + shdrs[i].sh_name, ".bootphase1") == 0) {
            uint32_t offset;
            memcpy(&offset, ctx->elf + le32(shdrs[i].sh_offset) + le32(shdrs[i].sh_size) - 4, sizeof(uint32_t));
            if (offset >= le32(shdrs[i].sh_addr)) {
                offset -= le32(shdrs[i].sh_addr);
                if (offset < le32(shdrs[i].sh_size)) {
                    ctx->ver_info = (struct version_information_t *)(ctx->elf + le32(shdrs[i].sh_offset) + offset);
                    res = print_and_validate_version(ctx);
                }
            }
            break;
        }
    }

    if (res == PM3_SUCCESS) {
        return res;
    }

    // We could not find proper version_information
    if (res == PM3_EUNDEF) {
        PrintAndLogEx(WARNING, "Unable to check version_information");
    }

    if (force) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO,  "Make sure to flash a correct and up-to-date version");
    PrintAndLogEx(INFO,  "You can force flashing this firmware by using the option '--force'");
fail:
    flash_free(ctx);
    return res;
}

// Prepare an ELF file for flashing
int flash_prepare(flash_file_t *ctx, int can_write_bl, flash_dev_t *flash_dev) {
    int res = PM3_EUNDEF;

    // Check elf file is build for currently connected device?
    if (!CheckInformationMagicAndChipType(ctx->ver_info, flash_dev->chiptype)) {
        PrintAndLogEx(ERR, "The elf file is not applicable to the currently connected device.", flash_dev->chiptype);
        res = PM3_EFILE;
        goto fail;
    }

    res = build_segs_from_phdrs(ctx, flash_dev);
    if (res != PM3_SUCCESS) {
        goto fail;
    }

    res = check_segs(ctx, can_write_bl, flash_dev);
    if (res != PM3_SUCCESS) {
        goto fail;
    }

    return PM3_SUCCESS;

fail:
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
        case CMD_ACK: {
            *state = DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM;
            break;
        }
        case CMD_DEBUG_PRINT_STRING: {
            *state = DEVICE_INFO_FLAG_CURRENT_MODE_OS;
            break;
        }
        case CMD_DEVICE_INFO: {
            // bootloader replies are OLD frames by design, see doc/new_frame_format.md
            *state = resp.oldarg[0];
            break;
        }
        default: {
            PrintAndLogEx(ERR, _RED_("Error:") " Couldn't get Proxmark3 state, bad response type: 0x%04x", resp.cmd);
            return PM3_EFATAL;
        }
    }
    return PM3_SUCCESS;
}

// Enter the bootloader to be able to start flashing
static int enter_bootloader(char *serial_port_name, bool wait_appear) {

    uint32_t state = 0;
    int ret = get_proxmark_state(&state);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    /* Already in flash state, we're done. */
    if ((state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) == DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) {
        return PM3_SUCCESS;
    }

    if ((state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) == DEVICE_INFO_FLAG_CURRENT_MODE_OS) {
        PrintAndLogEx(SUCCESS, _CYAN_("Entering bootloader..."));

        if (
            ((state & DEVICE_INFO_FLAG_BOOTROM_PRESENT) == DEVICE_INFO_FLAG_BOOTROM_PRESENT) &&
            ((state & DEVICE_INFO_FLAG_OSIMAGE_PRESENT) == DEVICE_INFO_FLAG_OSIMAGE_PRESENT)) {
            // New style handover: Send CMD_START_FLASH, which will reset the board
            // and enter the bootrom on the next boot.
            SendCommandBL(CMD_START_FLASH, 0, 0, 0, NULL, 0);
            PrintAndLogEx(SUCCESS, "(Press and release the button only to " _YELLOW_("abort") ")");
        } else {
            // Old style handover: Ask the user to press the button, then reset the board
            SendCommandBL(CMD_HARDWARE_RESET, 0, 0, 0, NULL, 0);
            PrintAndLogEx(SUCCESS, "Press and hold down button NOW if your bootloader requires it.");
        }
        msleep(500);
        PrintAndLogEx(SUCCESS, _CYAN_("Trigger restart..."));
        CloseProxmark(g_session.current_device);
        // Let time to OS to make the port disappear
        msleep(1000);

        if (wait_appear == false) {
            return PM3_SUCCESS;
        } else if (OpenProxmark(&g_session.current_device, serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
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

// Wait for the device to respond with either ACK or NACK.
static int wait_for_ack(PacketResponseNG *ack) {
    WaitForResponse(CMD_UNKNOWN, ack);
    if (ack->cmd != CMD_ACK) {
        PrintAndLogEx(ERR, "\nError: Unexpected reply 0x%04x %s (expected ACK)",
                      ack->cmd,
                      (ack->cmd == CMD_NACK) ? "NACK" : ""
                     );
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

// If the BOOTLOADER is too old or damaged, we can suggest that the user update the BOOT.
// If the current session is already (re)flashing the bootloader (--unlock-bootloader), there is
// nothing more to suggest: the fix is already under way.
static void flash_suggest_update_bootloader(bool bootloader_being_flashed) {
    // Since it's only used internally, we can define it internally.
    static bool gs_printed_msg = false;
    if (gs_printed_msg) {
        return;
    }

    if (bootloader_being_flashed) {
        PrintAndLogEx(WARNING, _YELLOW_("Your bootloader is outdated, but this operation will update it"));
        gs_printed_msg = true;
        return;
    }

    PrintAndLogEx(ERR, _RED_("It is recommended that you first" _YELLOW_(" update your bootloader") _RED_(" alone,")));
    PrintAndLogEx(ERR, _RED_("reboot the Proxmark3 then only update the main firmware") "\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(ERR, "------------- " _CYAN_("Follow these steps") " -------------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(ERR, " 1)   ./pm3-flash-bootrom");
    PrintAndLogEx(ERR, " 2)   ./pm3-flash-fullimage");
    PrintAndLogEx(ERR, " 3)   ./pm3");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
    gs_printed_msg = true;
    if (g_session.stdinOnTTY) {
        PrintAndLogEx(INFO, "Press ENTER to continue or CTRL-C to cancel...");
        fflush(stdout);
        while (kbd_enter_pressed() == false) {
            msleep(100);
        }
    }
}

// If the device's boot is newer than the current flasher, we can suggest the user update the flasher.
static void flash_suggest_update_flasher(void) {
    PrintAndLogEx(ERR, _RED_("It is recommended that you first " _YELLOW_("update your flasher")));
}

// AT32 series has a wide range of flash sizes, so we check the chipinfo to set the flash end address and block size.
static void flash_dev_at32_init(uint32_t chipinfo, flash_dev_t *flash_dev) {
    flash_dev->flash_start = FLASH_START_AT32;
    uint32_t flash_size = chipid_to_mem_avail_at32(chipinfo);
    if (flash_size > 1024) {
        flash_dev->block_size = 0x1000; // 4K block size for >1M flash
    } else {
        flash_dev->block_size = 0x800; // 2K block size for <=1M flash
    }
    flash_dev->flash_end = FLASH_START_AT32 + flash_size * 1024;
    flash_dev->boot_size = BOOTLOADER_SIZE_AT32;
    flash_dev->boot_end = BOOTLOADER_END_AT32;
}

// AT91 series has some variations in flash size, so we check the chipinfo to set the flash end address
// and warn the user if they have a large flash but an old bootloader that doesn't support it.
static void flash_dev_at91_init(uint32_t chipinfo, flash_dev_t *flash_dev, int version, bool bl_targeted) {
    flash_dev->block_size = BLOCK_SIZE_AT91;
    flash_dev->flash_start = FLASH_START_AT91;
    flash_dev->flash_end = FLASH_START_AT91 + AT91C_IFLASH_PAGE_SIZE * AT91C_IFLASH_NB_OF_PAGES / 2; // Default 256K MAX
    flash_dev->boot_size = BOOTLOADER_SIZE_AT91;
    flash_dev->boot_end = BOOTLOADER_END_AT91;
    // Check the flash capacity based on the idcode returned by the device, that is, enable support for 512K FLASH.
    int mem_avail = chipid_to_mem_avail(chipinfo);
    if (mem_avail != 0) {
        PrintAndLogEx(INFO, "Available memory on this board: "_YELLOW_("%uK") " bytes\n", mem_avail);
        if (mem_avail > 256) {
            if (BL_VERSION_MAJOR(version) < BL_VERSION_MAJOR(BL_VERSION_1_0_0)) {
                PrintAndLogEx(ERR, _RED_("====================== OBS ! ======================"));
                PrintAndLogEx(ERR, _RED_("Your bootloader does not support writing above 256k"));
                flash_suggest_update_bootloader(bl_targeted);
            } else {
                // The capacity of the main chip of the device is greater than 256K,
                // and BL also supports OTA for chips with such a large capacity.
                flash_dev->flash_end = FLASH_START_AT91 + AT91C_IFLASH_PAGE_SIZE * AT91C_IFLASH_NB_OF_PAGES;
            }
        }
    } else {
        PrintAndLogEx(INFO, "Available memory on this board: "_RED_("UNKNOWN")"\n");
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ======================================"));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" CHIP_INFO") _RED_(" command")));
        flash_suggest_update_bootloader(bl_targeted);
    }
}

// True if at least one loaded ELF file has a PHDR matching the bootrom start address,
// i.e. this operation actually writes bootloader code (as opposed to merely being allowed to via --unlock-bootloader).
static bool files_target_bootloader(flash_file_t *files, uint8_t num_files, uint32_t boot_start) {
    for (uint8_t f = 0; f < num_files; f++) {
        Elf32_Phdr_t *phdr = files[f].phdrs;
        for (uint16_t i = 0; i < files[f].num_phdrs; i++, phdr++) {
            if (le32(phdr->p_type) != PT_LOAD || !le32(phdr->p_filesz)) {
                continue;
            }
            if (le32(phdr->p_paddr) == boot_start) {
                return true;
            }
        }
    }
    return false;
}

// Sending simple cmd without any parameters or data payload, just for arg0.
static void send_cmd_for_arg0(const uint64_t cmd, uint32_t *arg0) {
    SendCommandBL(cmd, 0, 0, 0, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(cmd, &resp);
    *arg0 = resp.oldarg[0];
}

// Go into flashing mode
int flash_start_flashing(int enable_bl_writes, char *serial_port_name, flash_dev_t *flash_dev, flash_file_t *files, uint8_t num_files) {

    int ret = enter_bootloader(serial_port_name, true);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    uint32_t state = 0;
    ret = get_proxmark_state(&state);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    flash_dev->chiptype = MAIN_CHIP_TYPE_NONE;
    if ((state & DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_TYPE) == DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_TYPE) {
        send_cmd_for_arg0(CMD_CHIP_TYPE, &flash_dev->chiptype);
    }

    uint32_t chipinfo = 0;
    if ((state & DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO) == DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO) {
        send_cmd_for_arg0(CMD_CHIP_INFO, &chipinfo);
    }

    // --unlock-bootloader only permits bootloader writes, it doesn't mean the loaded files actually contain one,
    // so derive the real intent from the PHDR address ranges of the files being flashed.
    uint32_t boot_start_guess = (flash_dev->chiptype == MAIN_CHIP_TYPE_AT32) ? FLASH_START_AT32 : FLASH_START_AT91;
    bool bl_targeted = files_target_bootloader(files, num_files, boot_start_guess);

    int version = BL_VERSION_INVALID;
    if ((state & DEVICE_INFO_FLAG_UNDERSTANDS_VERSION) == DEVICE_INFO_FLAG_UNDERSTANDS_VERSION) {
        // Get bootrom version for features and sanity checks
        send_cmd_for_arg0(CMD_BL_VERSION, (uint32_t *)&version);
        // Is version invalid or outside of expected range? maybe bootrom is very old or corrupted?
        if ((BL_VERSION_MAJOR(version) < BL_VERSION_FIRST_MAJOR) || (BL_VERSION_MAJOR(version) > BL_VERSION_LAST_MAJOR)) {
            version = BL_VERSION_INVALID; // version info seems fishy
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ==========================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader reported an invalid version number"));
            flash_suggest_update_bootloader(bl_targeted);
        } else if (BL_VERSION_MAJOR(version) < BL_VERSION_MAJOR(FLASHER_VERSION)) {
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ==================================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader reported a version older than this flasher"));
            flash_suggest_update_bootloader(bl_targeted);
        } else if (BL_VERSION_MAJOR(version) > BL_VERSION_MAJOR(FLASHER_VERSION)) {
            PrintAndLogEx(ERR, _RED_("====================== OBS ! ========================="));
            PrintAndLogEx(ERR, _RED_("Note: Your bootloader is more recent than this flasher"));
            flash_suggest_update_flasher();
        }
    } else {
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ==========================================="));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" CMD_BL_VERSION") _RED_(" command")));
        flash_suggest_update_bootloader(bl_targeted);
    }

    // 1. The old bootloader does not support pm5, nor does it support the 'CMD_CHIP_TYPE' command.
    // 2. In the absence of CMD_CHIP_TYPE cmd support, pm3 (at91 platform) is selected as a backup solution.
    // 3. Only by combining the parameters of chiptype and chipinfo can the detailed information of the chip currently used by the device be correctly obtained
    // 4. This function does not check if the elf file is compatible with the device, so it needs to be checked within the flash_prepare function
    switch (flash_dev->chiptype) {
        case MAIN_CHIP_TYPE_NONE:
            PrintAndLogEx(ERR, _RED_("Bootloader does not support CMD_CHIP_TYPE, assuming AT91 platform"));
            flash_dev->chiptype = MAIN_CHIP_TYPE_AT91;
            flash_suggest_update_bootloader(bl_targeted);
        // break; -> Don't break !!! We want to execute the code for MAIN_CHIP_TYPE_AT91 as well to initialize flash_dev with correct values.

        case MAIN_CHIP_TYPE_AT91:
        default:
            flash_dev_at91_init(chipinfo, flash_dev, version, bl_targeted);
            break;

        case MAIN_CHIP_TYPE_AT32:
            flash_dev_at32_init(chipinfo, flash_dev);
            break;
    }

    // If you need to flash bootrom, the start addr must be 'flash_start', otherwise, it can be 'boot_end' to skip the bootrom area and save some time.
    uint32_t start_flash_addr = enable_bl_writes ? flash_dev->flash_start : flash_dev->boot_end;
    PrintAndLogEx(INFO, "Permitted flash range: 0x%08x-0x%08x", start_flash_addr, flash_dev->flash_end);

    if ((state & DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) == DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) {
        if (enable_bl_writes) {
            SendCommandBL(CMD_START_FLASH, start_flash_addr, flash_dev->flash_end, START_FLASH_MAGIC, NULL, 0);
        } else {
            SendCommandBL(CMD_START_FLASH, start_flash_addr, flash_dev->flash_end, 0, NULL, 0);
        }
        PacketResponseNG resp;
        return wait_for_ack(&resp);
    } else {
        PrintAndLogEx(ERR, _RED_("====================== OBS ! ========================================"));
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new" _YELLOW_(" START_FLASH") _RED_(" command")));
        flash_suggest_update_bootloader(bl_targeted);
    }
    return PM3_SUCCESS;
}

// Reboot into bootloader
int flash_reboot_bootloader(char *serial_port_name, bool wait_appear) {
    return enter_bootloader(serial_port_name, wait_appear);
}

// Show error information after write failed on AT91 platform.
static void flash_write_err_on_at91(uint32_t err) {
    if (err) {
        uint32_t lock_bits = err >> 16;
        bool lock_error = err & AT91C_MC_LOCKE;
        bool prog_error = err & AT91C_MC_PROGE;
        bool security_bit = err & AT91C_MC_SECURITY;
        PrintAndLogEx(NORMAL, "%s", lock_error ? "       Lock Error" : "");
        PrintAndLogEx(NORMAL, "%s", prog_error ? "       Invalid Command or bad Keyword" : "");
        PrintAndLogEx(NORMAL, "%s", security_bit ? "       Security Bit is set!" : "");
        PrintAndLogEx(NORMAL, "       Lock Bits:      0x%04x", lock_bits);
    }
}

// Show error information after write failed on AT32 platform.
static void flash_write_err_on_at32(uint32_t err) {
    // TODO DXL Need to add the header file path of at32 in the makefile/cake of the client(for flash_status_type).
    //  In order to quickly compile and verify, we will temporarily define constant value.
    //  However, later on, the types in the header file should be used.
    switch (err) {
        case 0: // FLASH_OPERATE_BUSY
            PrintAndLogEx(ERR, "Flash is busy");
            break;
        case 1: // FLASH_PROGRAM_ERROR
            PrintAndLogEx(ERR, "Flash program error");
            break;
        case 2: // FLASH_EPP_ERROR
            PrintAndLogEx(ERR, "Erase/Program protection error");
            break;
        case 3: // FLASH_OPERATE_DONE
            // Nothing to do...
            break;
        case 4: // FLASH_OPERATE_TIMEOUT
            PrintAndLogEx(ERR, "Flash operation timeout");
            break;
        default:
            PrintAndLogEx(ERR, "Unknown flash error");
            break;
    }
}

// The error did not occur while writing to the flash memory, but rather during data copying and write boundary checks.
// This is a software error and is unrelated to the hardware.
static void flash_write_err_software(int pm3_err) {
    if (pm3_err == PM3_EINVARG) {
        PrintAndLogEx(ERR, _RED_("Error:") " Device rejected the firmware, invalid argument");
        PrintAndLogEx(ERR, "This may be because the firmware is not compatible with the device or the bootloader is too old");
        PrintAndLogEx(ERR, "Make sure to use a compatible ELF file and try updating the bootloader if it's old");
    } else if (pm3_err == PM3_EOVFLOW) {
        PrintAndLogEx(ERR, _RED_("Error:") " Device rejected the firmware, overflow");
        PrintAndLogEx(ERR, "This may be because the firmware is too large for the device");
        PrintAndLogEx(ERR, "Make sure to use a compatible ELF file and try updating the bootloader if it's old");
    } else if (pm3_err == PM3_EOUTOFBOUND) {
        PrintAndLogEx(ERR, _RED_("Error:") " Device rejected the firmware, out of bound");
        PrintAndLogEx(ERR, "This may be because the firmware is trying to write outside of the flash bounds");
        PrintAndLogEx(ERR, "Make sure to use a compatible ELF file and try updating the bootloader if it's old");
    } else {
        PrintAndLogEx(ERR, _RED_("Error:") " Device rejected the firmware with error code 0x%02x", pm3_err);
        PrintAndLogEx(ERR, "Make sure to use a compatible ELF file and try updating the bootloader if it's old");
    }
}

// Send finish write cmd and waiting for response.
// The send_buf length is always 512byte(PM3_CMD_DATA_SIZE_OLD)
static int send_finish_write_cmd(uint32_t address, int magic, uint8_t *send_buf, PacketResponseNG *resp) {
    // The sending length is always PM3_CMD_DATA_SIZE_OLD, which is 512 bytes, because of the limitation of the old frame.
    const int send_len = PM3_CMD_DATA_SIZE_OLD;
#if defined ICOPYX
    // To prevent users from flashing unsupported firmware, icopyx checks arg1 and arg2 in this command.
    // Therefore, when sending magic to the device, we should not choose a value that happens to be the same as icopyx.
    // In fact, neither PM3V nor PM5V will be 0xff or 0x1fd, so this should have strong robustness.
    SendCommandBL(CMD_FINISH_WRITE, address, 0xff, 0x1fd, send_buf, send_len);
#else
    // If it's an older version of the flasher or a flasher specific to icopyx, then arg1 should be 0x00 or 0xff,
    //  not a valid magic value. The client is specifically designed for icopyx.
    // ---
    // For devices with older firmware, it doesn't care about arg1,
    //  so OTA can be performed regardless of whether it's a new version of flasher (sending arg1)
    //  or an old version of flasher (arg1 is not a valid magic).
    // ---
    // For devices with new firmware, if the sent magic is a valid magic value,
    //  but the firmware cannot work on the device, the device will refuse to write the firmware.
    // ---
    // The older client version could always OTA update older devices,
    //  but it couldn't OTA update newer PM5 versions.
    //  This met our needs because the older client version didn't support PM5's ELF files.
    // ---
    // The new client version can always continue to OTA update the device version,
    //  and can also OTA update the latest version of PM5.
    SendCommandBL(CMD_FINISH_WRITE, address, magic, 0, send_buf, send_len);
#endif
    return wait_for_ack(resp);
}

// Write a block of data to flash, padding to the block size if needed. The bootloader will read the entire block,
// so we need to make sure to pad it with 0xFF if the data is smaller than the block size.
static int write_block(uint32_t address, int magic, uint8_t *data, uint32_t length, flash_dev_t *flash_dev) {
    // Align length to PM3_CMD_DATA_SIZE_OLD or block_size
    // It is necessary to align with the minimum write unit of the target chip,
    // otherwise it may cause the device to lose the data or offset errors.
    uint32_t padded_len = length % MAX(PM3_CMD_DATA_SIZE_OLD, flash_dev->block_size);
    if (padded_len) {
        padded_len = MAX(PM3_CMD_DATA_SIZE_OLD, flash_dev->block_size) - padded_len;
    }
    // After aligning PM3_CMD_DATA_SIZE_OLD, allocate a new buffer, copy the data, and pad the end with 0xFF.
    uint32_t aligned_len = length + padded_len;
    uint8_t *block_buf = malloc(aligned_len);
    if (block_buf == NULL) {
        return PM3_EMALLOC;
    }
    memset(block_buf, 0xFF, aligned_len); // fill 0xFF by aligned length
    memcpy(block_buf, data, length); // copy data by valid length
    // Send in packets
    int ret = PM3_SUCCESS;
    uint32_t sent = 0;
    while (sent < aligned_len) {
        PacketResponseNG resp;
        ret = send_finish_write_cmd(address, magic, block_buf + sent, &resp);
        if (ret) {
            // On new version of flasher, the arg1 is error code of PM3_E*, old version is 0x00, so we can always check it.
            if (resp.oldarg[1]) { // 0x00 == PM3_SUCCESS
                flash_write_err_software(resp.oldarg[1]);
            } else {
                // If not PM3_E*, maybe some errors of flash write occurred. Or is old version boot.
                if (flash_dev->chiptype == MAIN_CHIP_TYPE_AT91) {
                    flash_write_err_on_at91(resp.oldarg[0]);
                } else if (flash_dev->chiptype == MAIN_CHIP_TYPE_AT32) {
                    flash_write_err_on_at32(resp.oldarg[0]);
                } else {
                    PrintAndLogEx(ERR, "Unknown chip type, cannot decode error information");
                }
            }
            break;
        }
        sent += PM3_CMD_DATA_SIZE_OLD;
    }
    free(block_buf); // remember to free buffer
    return ret;
}

// Write a file's segments to Flash
int flash_write(flash_file_t *ctx, flash_dev_t *flash_dev) {

    PrintAndLogEx(SUCCESS, "Writing segments for file: %s", ctx->filename);

    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        uint32_t length = seg->length;
        uint32_t blocks = (length + flash_dev->block_size - 1) / flash_dev->block_size;
        uint32_t end = seg->start + length;

        PrintAndLogEx(SUCCESS, " 0x%08x..0x%08x [0x%x / %u blocks]", seg->start, end - 1, length, blocks);

        fflush(stdout);
        uint32_t block = 0;
        uint8_t *data = seg->data;
        uint32_t baddr = seg->start;

        int pct = 0;
        if (blocks > 50) {

            signal(SIGINT, hadouken_on_sigint);
#ifndef _WIN32
            signal(SIGWINCH, hadouken_on_sigwinch);
#endif

            hadouken_start(30.0, 0, 1);
        }

        while (length) {

            uint32_t block_size = length;
            if (block_size > flash_dev->block_size) {
                block_size = flash_dev->block_size;
            }

            if (write_block(baddr, ctx->ver_info->magic, data, block_size, flash_dev) < 0) {
                if (blocks > 50) {
                    hadouken_stop();
                }
                PrintAndLogEx(ERR, "Error writing block %d of %u", block, blocks);
                return PM3_EFATAL;
            }

            data += block_size;
            baddr += block_size;
            length -= block_size;
            block++;

            if (blocks > 50) {
                pct = (int)(block * 100) / blocks;
                hadouken_set_progress(pct);
            }
        }

        if (blocks > 50) {
            hadouken_stop();
        }
        fflush(stdout);
    }
    return PM3_SUCCESS;
}

// free a file context
void flash_free(flash_file_t *ctx) {

    if (ctx == NULL) {
        return;
    }

    if (ctx->filename != NULL) {
        free(ctx->filename);
        ctx->filename = NULL;
    }

    if (ctx->elf) {
        free(ctx->elf);
        ctx->elf = NULL;
        ctx->phdrs = NULL;
        ctx->num_phdrs = 0;
    }

    if (ctx->segments) {

        for (int i = 0; i < ctx->num_segs; i++) {
            free(ctx->segments[i].data);
        }

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
