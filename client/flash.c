//-----------------------------------------------------------------------------
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ELF file flasher
//-----------------------------------------------------------------------------

#include "flash.h"

#define FLASH_START            0x100000

#ifdef HAS_512_FLASH
# define FLASH_SIZE             (512*1024)
#else
# define FLASH_SIZE             (256*1024)
#endif

#define FLASH_END              (FLASH_START + FLASH_SIZE)
#define BOOTLOADER_SIZE        0x2000
#define BOOTLOADER_END         (FLASH_START + BOOTLOADER_SIZE)

#define BLOCK_SIZE             0x200

static const uint8_t elf_ident[] = {
    0x7f, 'E', 'L', 'F',
    ELFCLASS32,
    ELFDATA2LSB,
    EV_CURRENT
};

// Turn PHDRs into flasher segments, checking for PHDR sanity and merging adjacent
// unaligned segments if needed
static int build_segs_from_phdrs(flash_file_t *ctx, FILE *fd, Elf32_Phdr *phdrs, uint16_t num_phdrs) {
    Elf32_Phdr *phdr = phdrs;
    flash_seg_t *seg;
    uint32_t last_end = 0;

    ctx->segments = calloc(sizeof(flash_seg_t) * num_phdrs, sizeof(uint8_t));
    if (!ctx->segments) {
        PrintAndLogEx(ERR, "Out of memory");
        return -1;
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
            return -1;
        }
        if (paddr < last_end) {
            PrintAndLogEx(ERR, "Error: PHDRs not sorted or overlap");
            return -1;
        }
        if (paddr < FLASH_START || (paddr + filesz) > FLASH_END) {
            PrintAndLogEx(ERR, "Error: PHDR is not contained in Flash");
            return -1;
        }
        if (vaddr >= FLASH_START && vaddr < FLASH_END && (flags & PF_W)) {
            PrintAndLogEx(ERR, "Error: Flash VMA segment is writable");
            return -1;
        }

        uint8_t *data;
        // make extra space if we need to move the data forward
        data = calloc(filesz + BLOCK_SIZE, sizeof(uint8_t));
        if (!data) {
            PrintAndLogEx(ERR, "Error: Out of memory");
            return -1;
        }
        if (fseek(fd, offset, SEEK_SET) < 0 || fread(data, 1, filesz, fd) != filesz) {
            PrintAndLogEx(ERR, "Error while reading PHDR payload");
            free(data);
            return -1;
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
                        return -1;
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
    return 0;
}

// Sanity check segments and check for bootloader writes
static int check_segs(flash_file_t *ctx, int can_write_bl) {
    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        if (seg->start & (BLOCK_SIZE - 1)) {
            PrintAndLogEx(ERR, "Error: Segment is not aligned");
            return -1;
        }
        if (seg->start < FLASH_START) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return -1;
        }
        if (seg->start + seg->length > FLASH_END) {
            PrintAndLogEx(ERR, "Error: Segment is outside of flash bounds");
            return -1;
        }
        if (!can_write_bl && seg->start < BOOTLOADER_END) {
            PrintAndLogEx(ERR, "Attempted to write bootloader but bootloader writes are not enabled");
            return -1;
        }
    }
    return 0;
}

// Load an ELF file and prepare it for flashing
int flash_load(flash_file_t *ctx, const char *name, int can_write_bl) {
    FILE *fd;
    Elf32_Ehdr ehdr;
    Elf32_Phdr *phdrs = NULL;
    uint16_t num_phdrs;
    int res;

    fd = fopen(name, "rb");
    if (!fd) {
        PrintAndLogEx(ERR, _RED_("Could not open file") "%s  >>> ", name);
        perror(NULL);
        goto fail;
    }

    PrintAndLogEx(SUCCESS, _BLUE_("Loading ELF file") _YELLOW_("%s"), name);

    if (fread(&ehdr, sizeof(ehdr), 1, fd) != 1) {
        PrintAndLogEx(ERR, "Error while reading ELF file header");
        goto fail;
    }
    if (memcmp(ehdr.e_ident, elf_ident, sizeof(elf_ident))
            || le32(ehdr.e_version) != 1) {
        PrintAndLogEx(ERR, "Not an ELF file or wrong ELF type");
        goto fail;
    }
    if (le16(ehdr.e_type) != ET_EXEC) {
        PrintAndLogEx(ERR, "ELF is not executable");
        goto fail;
    }
    if (le16(ehdr.e_machine) != EM_ARM) {
        PrintAndLogEx(ERR, "Wrong ELF architecture");
        goto fail;
    }
    if (!ehdr.e_phnum || !ehdr.e_phoff) {
        PrintAndLogEx(ERR, "ELF has no PHDRs");
        goto fail;
    }
    if (le16(ehdr.e_phentsize) != sizeof(Elf32_Phdr)) {
        // could be a structure padding issue...
        PrintAndLogEx(ERR, "Either the ELF file or this code is made of fail");
        goto fail;
    }
    num_phdrs = le16(ehdr.e_phnum);

    phdrs = calloc(le16(ehdr.e_phnum) * sizeof(Elf32_Phdr), sizeof(uint8_t));
    if (!phdrs) {
        PrintAndLogEx(ERR, "Out of memory");
        goto fail;
    }
    if (fseek(fd, le32(ehdr.e_phoff), SEEK_SET) < 0) {
        PrintAndLogEx(ERR, "Error while reading ELF PHDRs");
        goto fail;
    }
    if (fread(phdrs, sizeof(Elf32_Phdr), num_phdrs, fd) != num_phdrs) {
        PrintAndLogEx(ERR, "Error while reading ELF PHDRs");
        goto fail;
    }

    res = build_segs_from_phdrs(ctx, fd, phdrs, num_phdrs);
    if (res < 0)
        goto fail;
    res = check_segs(ctx, can_write_bl);
    if (res < 0)
        goto fail;

    free(phdrs);
    fclose(fd);
    ctx->filename = name;
    return 0;

fail:
    if (phdrs)
        free(phdrs);
    if (fd)
        fclose(fd);
    flash_free(ctx);
    return -1;
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
            PrintAndLogEx(ERR, _RED_("Error:") "Couldn't get Proxmark3 state, bad response type: 0x%04x", resp.cmd);
            return -1;
            break;
    }
    return 0;
}

// Enter the bootloader to be able to start flashing
static int enter_bootloader(char *serial_port_name) {
    uint32_t state;

    if (get_proxmark_state(&state) < 0)
        return -1;

    /* Already in flash state, we're done. */
    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM)
        return 0;

    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) {
        PrintAndLogEx(SUCCESS, _BLUE_("Entering bootloader..."));

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
        CloseProxmark();
        // Let time to OS to make the port disappear
        msleep(1000);

        if (OpenProxmark(serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
            PrintAndLogEx(NORMAL, " " _GREEN_("Found"));
            return 0;
        } else {
            PrintAndLogEx(ERR, _RED_("Error:") "Proxmark3 not found.");
            return -1;
        }
    }

    PrintAndLogEx(ERR, _RED_("Error:") "Unknown Proxmark3 mode");
    return -1;
}

static int wait_for_ack(PacketResponseNG *ack) {
    WaitForResponse(CMD_UNKNOWN, ack);

    if (ack->cmd != CMD_ACK) {
        PrintAndLogEx(ERR, "Error: Unexpected reply 0x%04x %s (expected ACK)",
                      ack->cmd,
                      (ack->cmd == CMD_NACK) ? "NACK" : ""
                     );
        return -1;
    }
    return 0;
}

// Go into flashing mode
int flash_start_flashing(int enable_bl_writes, char *serial_port_name) {
    uint32_t state;

    if (enter_bootloader(serial_port_name) < 0)
        return -1;

    if (get_proxmark_state(&state) < 0)
        return -1;

    if (state & DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) {
        // This command is stupid. Why the heck does it care which area we're
        // flashing, as long as it's not the bootloader area? The mind boggles.
        PacketResponseNG resp;

        if (enable_bl_writes) {
            SendCommandBL(CMD_START_FLASH, FLASH_START, FLASH_END, START_FLASH_MAGIC, NULL, 0);
        } else {
            SendCommandBL(CMD_START_FLASH, BOOTLOADER_END, FLASH_END, 0, NULL, 0);
        }
        return wait_for_ack(&resp);
    } else {
        PrintAndLogEx(ERR, _RED_("Note: Your bootloader does not understand the new START_FLASH command"));
        PrintAndLogEx(ERR, _RED_("It is recommended that you update your bootloader") "\n");
    }
    return 0;
}

static int write_block(uint32_t address, uint8_t *data, uint32_t length) {
    uint8_t block_buf[BLOCK_SIZE];
    memset(block_buf, 0xFF, BLOCK_SIZE);
    memcpy(block_buf, data, length);
    PacketResponseNG resp;
    SendCommandBL(CMD_FINISH_WRITE, address, 0, 0, block_buf, length);
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

// Write a file's segments to Flash
int flash_write(flash_file_t *ctx) {
    PrintAndLogEx(SUCCESS, "Writing segments for file: %s", ctx->filename);
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
                return -1;
            }

            data += block_size;
            baddr += block_size;
            length -= block_size;
            block++;
            fprintf(stdout, ".");
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, " " _GREEN_("OK"));
        fflush(stdout);
    }
    return 0;
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
    return 0;
}
