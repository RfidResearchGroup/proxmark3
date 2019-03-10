//-----------------------------------------------------------------------------
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ELF file flasher
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util_posix.h"
#include "proxusb.h"
#include "flash.h"
#include "elf.h"
#include "proxendian.h"

#define FLASH_START            0x100000
#define FLASH_SIZE             (256*1024)
#define FLASH_END              (FLASH_START + FLASH_SIZE)
#define BOOTLOADER_SIZE        0x2000
#define BOOTLOADER_END         (FLASH_START + BOOTLOADER_SIZE)

#define BLOCK_SIZE             0x100

static const uint8_t elf_ident[] = {
    0x7f, 'E', 'L', 'F',
    ELFCLASS32,
    ELFDATA2LSB,
    EV_CURRENT
};

// Turn PHDRs into flasher segments, checking for PHDR sanity and merging adjacent
// unaligned segments if needed
static int build_segs_from_phdrs(flash_file_t *ctx, FILE *fd, Elf32_Phdr *phdrs, int num_phdrs) {
    Elf32_Phdr *phdr = phdrs;
    flash_seg_t *seg;
    uint32_t last_end = 0;

    ctx->segments = calloc(sizeof(flash_seg_t) * num_phdrs, sizeof(uint8_t));
    if (!ctx->segments) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    ctx->num_segs = 0;
    seg = ctx->segments;

    fprintf(stderr, "Loading usable ELF segments:\n");
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
        fprintf(stderr, "%d: V 0x%08x P 0x%08x (0x%08x->0x%08x) [%c%c%c] @0x%x\n",
                i, vaddr, paddr, filesz, memsz,
                flags & PF_R ? 'R' : ' ',
                flags & PF_W ? 'W' : ' ',
                flags & PF_X ? 'X' : ' ',
                offset);
        if (filesz != memsz) {
            fprintf(stderr, "Error: PHDR file size does not equal memory size\n"
                    "(DATA+BSS PHDRs do not make sense on ROM platforms!)\n");
            return -1;
        }
        if (paddr < last_end) {
            fprintf(stderr, "Error: PHDRs not sorted or overlap\n");
            return -1;
        }
        if (paddr < FLASH_START || (paddr + filesz) > FLASH_END) {
            fprintf(stderr, "Error: PHDR is not contained in Flash\n");
            return -1;
        }
        if (vaddr >= FLASH_START && vaddr < FLASH_END && (flags & PF_W)) {
            fprintf(stderr, "Error: Flash VMA segment is writable\n");
            return -1;
        }

        uint8_t *data;
        // make extra space if we need to move the data forward
        data = calloc(filesz + BLOCK_SIZE, sizeof(uint8_t));
        if (!data) {
            fprintf(stderr, "Out of memory\n");
            return -1;
        }
        if (fseek(fd, offset, SEEK_SET) < 0 || fread(data, 1, filesz, fd) != filesz) {
            fprintf(stderr, "Error while reading PHDR payload\n");
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
                        fprintf(stderr, "Out of memory\n");
                        free(data);
                        return -1;
                    }
                    memset(new_data, 0xff, new_length);
                    memcpy(new_data, prev_seg->data, prev_seg->length);
                    memcpy(new_data + this_offset, data, filesz);
                    fprintf(stderr, "Note: Extending previous segment from 0x%x to 0x%x bytes\n",
                            prev_seg->length, new_length);
                    if (hole)
                        fprintf(stderr, "Note: 0x%x-byte hole created\n", hole);
                    free(data);
                    free(prev_seg->data);
                    prev_seg->data = new_data;
                    prev_seg->length = new_length;
                    last_end = this_end;
                    phdr++;
                    continue;
                }
            }
            fprintf(stderr, "Warning: segment does not begin on a block boundary, will pad\n");
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
            fprintf(stderr, "Error: Segment is not aligned\n");
            return -1;
        }
        if (seg->start < FLASH_START) {
            fprintf(stderr, "Error: Segment is outside of flash bounds\n");
            return -1;
        }
        if (seg->start + seg->length > FLASH_END) {
            fprintf(stderr, "Error: Segment is outside of flash bounds\n");
            return -1;
        }
        if (!can_write_bl && seg->start < BOOTLOADER_END) {
            fprintf(stderr, "Attempted to write bootloader but bootloader writes are not enabled\n");
            return -1;
        }
    }
    return 0;
}

// Load an ELF file and prepare it for flashing
int flash_load(flash_file_t *ctx, const char *name, int can_write_bl) {
    FILE *fd = NULL;
    Elf32_Ehdr ehdr;
    Elf32_Phdr *phdrs = NULL;
    int num_phdrs;
    int res;

    fd = fopen(name, "rb");
    if (!fd) {
        fprintf(stderr, "Could not open file '%s': ", name);
        perror(NULL);
        goto fail;
    }

    fprintf(stderr, "Loading ELF file '%s'...\n", name);

    if (fread(&ehdr, sizeof(ehdr), 1, fd) != 1) {
        fprintf(stderr, "Error while reading ELF file header\n");
        goto fail;
    }
    if (memcmp(ehdr.e_ident, elf_ident, sizeof(elf_ident))
            || le32(ehdr.e_version) != 1) {
        fprintf(stderr, "Not an ELF file or wrong ELF type\n");
        goto fail;
    }
    if (le16(ehdr.e_type) != ET_EXEC) {
        fprintf(stderr, "ELF is not executable\n");
        goto fail;
    }
    if (le16(ehdr.e_machine) != EM_ARM) {
        fprintf(stderr, "Wrong ELF architecture\n");
        goto fail;
    }
    if (!ehdr.e_phnum || !ehdr.e_phoff) {
        fprintf(stderr, "ELF has no PHDRs\n");
        goto fail;
    }
    if (le16(ehdr.e_phentsize) != sizeof(Elf32_Phdr)) {
        // could be a structure padding issue...
        fprintf(stderr, "Either the ELF file or this code is made of fail\n");
        goto fail;
    }
    num_phdrs = le16(ehdr.e_phnum);

    phdrs = calloc(le16(ehdr.e_phnum) * sizeof(Elf32_Phdr), sizeof(uint8_t));
    if (!phdrs) {
        fprintf(stderr, "Out of memory\n");
        goto fail;
    }
    if (fseek(fd, le32(ehdr.e_phoff), SEEK_SET) < 0) {
        fprintf(stderr, "Error while reading ELF PHDRs\n");
        goto fail;
    }
    if (fread(phdrs, sizeof(Elf32_Phdr), num_phdrs, fd) != num_phdrs) {
        fprintf(stderr, "Error while reading ELF PHDRs\n");
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
    UsbCommand c = {CMD_DEVICE_INFO};
    SendCommand(&c);
    UsbCommand resp;
    ReceiveCommand(&resp);

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
            *state = resp.arg[0];
            break;
        default:
            fprintf(stderr, "Error: Couldn't get proxmark state, bad response type: 0x%04x\n", resp.cmd);
            return -1;
            break;
    }

    return 0;
}

// Enter the bootloader to be able to start flashing
static int enter_bootloader(void) {
    uint32_t state;

    if (get_proxmark_state(&state) < 0)
        return -1;

    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) {
        /* Already in flash state, we're done. */
        return 0;
    }

    if (state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) {
        fprintf(stderr, "Entering bootloader...\n");
        UsbCommand c;
        memset(&c, 0, sizeof(c));

        if ((state & DEVICE_INFO_FLAG_BOOTROM_PRESENT)
                && (state & DEVICE_INFO_FLAG_OSIMAGE_PRESENT)) {
            // New style handover: Send CMD_START_FLASH, which will reset the board
            // and enter the bootrom on the next boot.
            c.cmd = CMD_START_FLASH;
            SendCommand(&c);
            fprintf(stderr, "(Press and release the button only to abort)\n");
        } else {
            // Old style handover: Ask the user to press the button, then reset the board
            c.cmd = CMD_HARDWARE_RESET;
            SendCommand(&c);
            fprintf(stderr, "Press and hold down button NOW if your bootloader requires it.\n");
        }
        fprintf(stderr, "Waiting for Proxmark to reappear on USB...");

        CloseProxmark();
        msleep(1000);
        while (!OpenProxmark(0)) {
            msleep(1000);
            fprintf(stderr, ".");
            fflush(stdout);
        }
        fprintf(stderr, " Found.\n");

        return 0;
    }

    fprintf(stderr, "Error: Unknown Proxmark mode\n");
    return -1;
}

static int wait_for_ack(void) {
    UsbCommand ack;
    ReceiveCommand(&ack);
    if (ack.cmd != CMD_ACK) {
        printf("Error: Unexpected reply 0x%04x (expected ACK)\n", ack.cmd);
        return -1;
    }
    return 0;
}

// Go into flashing mode
int flash_start_flashing(int enable_bl_writes) {
    uint32_t state;

    if (enter_bootloader() < 0)
        return -1;

    if (get_proxmark_state(&state) < 0)
        return -1;

    if (state & DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) {
        // This command is stupid. Why the heck does it care which area we're
        // flashing, as long as it's not the bootloader area? The mind boggles.
        UsbCommand c = {CMD_START_FLASH};

        if (enable_bl_writes) {
            c.arg[0] = FLASH_START;
            c.arg[1] = FLASH_END;
            c.arg[2] = START_FLASH_MAGIC;
        } else {
            c.arg[0] = BOOTLOADER_END;
            c.arg[1] = FLASH_END;
            c.arg[2] = 0;
        }
        SendCommand(&c);
        return wait_for_ack();
    } else {
        fprintf(stderr, "Note: Your bootloader does not understand the new START_FLASH command\n");
        fprintf(stderr, "      It is recommended that you update your bootloader\n\n");
    }

    return 0;
}

static int write_block(uint32_t address, uint8_t *data, uint32_t length) {
    uint8_t block_buf[BLOCK_SIZE];

    memset(block_buf, 0xFF, BLOCK_SIZE);
    memcpy(block_buf, data, length);

    UsbCommand c = {CMD_SETUP_WRITE};
    for (int i = 0; i < 240; i += 48) {
        memcpy(c.d.asBytes, block_buf + i, 48);
        c.arg[0] = i / 4;
        SendCommand(&c);
        if (wait_for_ack() < 0)
            return -1;
    }

    c.cmd = CMD_FINISH_WRITE;
    c.arg[0] = address;
    memcpy(c.d.asBytes, block_buf + 240, 16);
    SendCommand(&c);
    return wait_for_ack();
}

// Write a file's segments to Flash
int flash_write(flash_file_t *ctx) {
    fprintf(stderr, "Writing segments for file: %s\n", ctx->filename);
    for (int i = 0; i < ctx->num_segs; i++) {
        flash_seg_t *seg = &ctx->segments[i];

        uint32_t length = seg->length;
        uint32_t blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        uint32_t end = seg->start + length;

        fprintf(stderr, " 0x%08x..0x%08x [0x%x / %d blocks]",
                seg->start, end - 1, length, blocks);

        int block = 0;
        uint8_t *data = seg->data;
        uint32_t baddr = seg->start;

        while (length) {
            uint32_t block_size = length;
            if (block_size > BLOCK_SIZE)
                block_size = BLOCK_SIZE;

            if (write_block(baddr, data, block_size) < 0) {
                fprintf(stderr, " ERROR\n");
                fprintf(stderr, "Error writing block %d of %d\n", block, blocks);
                return -1;
            }

            data += block_size;
            baddr += block_size;
            length -= block_size;
            block++;
            fprintf(stderr, ".");
            fflush(stdout);
        }
        fprintf(stderr, " OK\n");
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
    UsbCommand c = {CMD_HARDWARE_RESET};
    SendCommand(&c);
    return 0;
}
