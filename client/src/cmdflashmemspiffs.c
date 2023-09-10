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
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#include "cmdflashmemspiffs.h"
#include <ctype.h>
#include "cmdparser.h"  // command_t
#include "pmflash.h"
#include "fileutils.h"  //saveFile
#include "comms.h"      //getfromdevice
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

int flashmem_spiffs_load(char *destfn, uint8_t *data, size_t datalen) {

    int ret_val = PM3_SUCCESS;

    // We want to mount before multiple operation so the lazy writes/append will not
    // trigger a mount + umount each loop iteration (lazy ops device side)
    SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);

    // Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;

    // fast push mode
    g_conn.block_after_ACK = true;

    while (bytes_remaining > 0) {

        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        flashmem_write_t *payload = calloc(1, sizeof(flashmem_write_t) + bytes_in_packet);

        payload->append = (bytes_sent > 0);

        uint8_t fnlen = MIN(sizeof(payload->fn), strlen(destfn));

        payload->fnlen = fnlen;
        memcpy(payload->fn, destfn, fnlen);

        payload->bytes_in_packet = bytes_in_packet;
        memset(payload->data, 0, bytes_in_packet);
        memcpy(payload->data, data + bytes_sent, bytes_in_packet);

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_SPIFFS_WRITE, (uint8_t *)payload, sizeof(flashmem_write_t) + bytes_in_packet);

        free(payload);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        uint8_t retry = 3;
        while (WaitForResponseTimeout(CMD_SPIFFS_WRITE, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            retry--;
            if (retry == 0) {
                ret_val = PM3_ETIMEOUT;
                goto out;
            }
        }
    }

out:
    clearCommandBuffer();

    // turn off fast push mode
    g_conn.block_after_ACK = false;

    // We want to unmount after these to set things back to normal but more than this
    // unmouting ensure that SPIFFS CACHES are all flushed so our file is actually written on memory
    SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);
    return ret_val;
}

int flashmem_spiffs_download(char *fn, uint8_t fnlen, void **pdest, size_t *destlen) {
    // get size from spiffs itself !
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_STAT, (uint8_t *)fn, fnlen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SPIFFS_STAT, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    uint32_t len = resp.data.asDwords[0];
    if (len == 0) {
        PrintAndLogEx(ERR, "error, failed to retrieve file stats on SPIFFSS");
        return PM3_EFAILED;
    }

    *pdest = calloc(len, sizeof(uint8_t));
    if (*pdest == false) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    uint32_t start_index = 0;
    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u") " bytes from `" _YELLOW_("%s") "` (spiffs)", len, fn);

    if (GetFromDevice(SPIFFS, *pdest, len, start_index, (uint8_t *)fn, fnlen, NULL, -1, true) == 0) {
        PrintAndLogEx(FAILED, "error, downloading from spiffs");
        free(*pdest);
        return PM3_EFLASH;
    }

    *destlen = len;
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSMount(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs mount",
                  "Mount the SPIFFS file system if not already mounted",
                  "mem spiffs mount");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSUnmount(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs unmount",
                  "Un-mount the SPIFFS file system",
                  "mem spiffs unmount");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs test",
                  "Test SPIFFS Operations, require wiping pages 0 and 1",
                  "mem spiffs test");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_TEST, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSCheck(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs check",
                  "Check/try to defrag faulty/fragmented SPIFFS file system",
                  "mem spiffs check");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_CHECK, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSTree(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs tree",
                  "Print the Flash memory file system tree",
                  "mem spiffs tree");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "--- " _CYAN_("Flash Memory tree (SPIFFS)") " -----------------");
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_PRINT_TREE, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs info",
                  "Print file system info and usage statistics",
                  "mem spiffs info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "--- " _CYAN_("Flash Memory info (SPIFFS)") " -----------------");
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_PRINT_FSINFO, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSRemove(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs remove",
                  "Remove a file from SPIFFS filesystem",
                  "mem spiffs remove -f lasttag.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "file to remove"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, 32, &fnlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "Removing `" _YELLOW_("%s") "`", filename);
    struct {
        uint8_t len;
        uint8_t fn[32];
    } PACKED payload;
    payload.len = fnlen;
    memcpy(payload.fn, filename, fnlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_REMOVE, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_REMOVE, &resp);
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(INFO, "Done!");

    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSRename(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs rename",
                  "Rename/move a file from SPIFFS filesystem.",
                  "mem spiffs rename -s aaa.bin -d bbb.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "source file name"),
        arg_str1("d", "dest", "<fn>", "destination file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "Rename from `" _YELLOW_("%s") "` -> `" _YELLOW_("%s") "`", src, dest);

    struct {
        uint8_t slen;
        uint8_t src[32];
        uint8_t dlen;
        uint8_t dest[32];
    } PACKED payload;
    payload.slen = slen;
    payload.dlen = dlen;

    memcpy(payload.src, src, slen);
    memcpy(payload.dest, dest, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_RENAME, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_RENAME, &resp);
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(INFO, "Done!");

    PrintAndLogEx(HINT, "Try `" _YELLOW_("mem spiffs tree") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSCopy(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs copy",
                  "Copy a file to another (destructively) in SPIFFS file system",
                  "mem spiffs copy -s aaa.bin -d aaa_cpy.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "source file name"),
        arg_str1("d", "dest", "<fn>", "destination file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    struct {
        uint8_t slen;
        uint8_t src[32];
        uint8_t dlen;
        uint8_t dest[32];
    } PACKED payload;
    payload.slen = slen;
    payload.dlen = dlen;

    memcpy(payload.src, src, slen);
    memcpy(payload.dest, dest, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_COPY, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_COPY, &resp);
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(INFO, "Done!");

    PrintAndLogEx(HINT, "Try `" _YELLOW_("mem spiffs tree") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs dump",
                  "Dumps device SPIFFS file to a local file\n"
                  "Size is handled by first sending a STAT command against file to verify existence",
                  "mem spiffs dump -s tag.bin             --> download binary file from device\n"
                  "mem spiffs dump -s tag.bin -d aaa -e   --> download tag.bin, save as aaa.eml format"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "SPIFFS file to save"),
        arg_str0("d", "dest", "<fn>", "file name to save to <w/o .bin>"),
        arg_lit0("e", "eml", "also save in EML format"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, FILE_PATH_SIZE, &dlen);

    bool eml = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // get size from spiffs itself !
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_STAT, (uint8_t *)src, slen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SPIFFS_STAT, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    uint32_t len = resp.data.asDwords[0];
    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    // download from device
    uint32_t start_index = 0;
    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u") " bytes from `" _YELLOW_("%s") "` (spiffs)", len, src);
    if (!GetFromDevice(SPIFFS, dump, len, start_index, (uint8_t *)src, slen, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "error, downloading from spiffs");
        free(dump);
        return PM3_EFLASH;
    }

    // save to file
    char fn[FILE_PATH_SIZE] = {0};
    if (dlen == 0) {
        strncpy(fn, src, slen);
    } else {
        strncpy(fn, dest, dlen);
    }

    // set file extension
    char *suffix = strchr(fn, '.');
    if (suffix)
        saveFile(fn, suffix, dump, len);
    else
        saveFile(fn, ".bin", dump, len); // default

    if (eml) {
        uint8_t eml_len = 16;
        if (strstr(fn, "class") != NULL)
            eml_len = 8;
        else if (strstr(fn, "mfu") != NULL)
            eml_len = 4;

        saveFileEML(fn, dump, len, eml_len);
    }
    free(dump);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs wipe",
                  _RED_("* * *  Warning  * * *") " \n"
                  _CYAN_("This command wipes all files on the device SPIFFS file system"),
                  "mem spiffs wipe");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Wiping all files from SPIFFS file system");
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_WIPE, NULL, 0);
    WaitForResponse(CMD_SPIFFS_WIPE, &resp);
    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(INFO, "Done!");

    PrintAndLogEx(HINT, "Try `" _YELLOW_("mem spiffs tree") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSUpload(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs upload",
                  "Uploads binary-wise file into device file system\n"
                  "Warning: mem area to be written must have been wiped first.\n"
                  "This is already taken care when loading dictionaries.\n"
                  "File names can only be 32 bytes long on device SPIFFS",
                  "mem spiffs upload -s local.bin -d dest.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "source file name"),
        arg_str1("d", "dest", "<fn>", "destination file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, FILE_PATH_SIZE, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "Upload `" _YELLOW_("%s") "` -> `" _YELLOW_("%s") "`", src, dest);

    size_t datalen = 0;
    uint8_t *data = NULL;

    int res = loadFile_safe(src, "", (void **)&data, &datalen);
    if (res != PM3_SUCCESS) {
        free(data);
        return PM3_EFILE;
    }

    res = flashmem_spiffs_load(dest, data, datalen);
    free(data);

    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%zu") " bytes to file "_GREEN_("%s"), datalen, dest);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("mem spiffs tree") "` to verify");
    return res;
}

static int CmdFlashMemSpiFFSView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs view",
                  "View a file on flash memory on devicer in console",
                  "mem spiffs view -f tag.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "SPIFFS file to view"),
        arg_int0("c", "cols", "<dec>", "column breaks (def 16)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char fn[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)fn, 32, &fnlen);

    int breaks = arg_get_int_def(ctx, 2, 16);
    CLIParserFree(ctx);

    uint8_t *dump = NULL;
    size_t dumplen = 0;
    int res = flashmem_spiffs_download(fn, fnlen, (void **)&dump, &dumplen);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    print_hex_break(dump, dumplen, breaks);
    PrintAndLogEx(NORMAL, "");
    free(dump);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,                  AlwaysAvailable, "This help"},
    {"copy",    CmdFlashMemSpiFFSCopy,    IfPm3Flash, "Copy a file to another (destructively) in SPIFFS file system"},
    {"check",   CmdFlashMemSpiFFSCheck,   IfPm3Flash, "Check/try to defrag faulty/fragmented file system"},
    {"dump",    CmdFlashMemSpiFFSDump,    IfPm3Flash, "Dump a file from SPIFFS file system"},
    {"info",    CmdFlashMemSpiFFSInfo,    IfPm3Flash, "Print file system info and usage statistics"},
    {"mount",   CmdFlashMemSpiFFSMount,   IfPm3Flash, "Mount the SPIFFS file system if not already mounted"},
    {"remove",  CmdFlashMemSpiFFSRemove,  IfPm3Flash, "Remove a file from SPIFFS file system"},
    {"rename",  CmdFlashMemSpiFFSRename,  IfPm3Flash, "Rename/move a file in SPIFFS file system"},
    {"test",    CmdFlashMemSpiFFSTest,    IfPm3Flash, "Test SPIFFS Operations"},
    {"tree",    CmdFlashMemSpiFFSTree,    IfPm3Flash, "Print the Flash memory file system tree"},
    {"unmount", CmdFlashMemSpiFFSUnmount, IfPm3Flash, "Un-mount the SPIFFS file system"},
    {"upload",  CmdFlashMemSpiFFSUpload,  IfPm3Flash, "Upload file into SPIFFS file system"},
    {"view",    CmdFlashMemSpiFFSView,    IfPm3Flash, "View file on SPIFFS file system"},
    {"wipe",    CmdFlashMemSpiFFSWipe,    IfPm3Flash, "Wipe all files from SPIFFS file system   * " _RED_("dangerous") " *" },
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdFlashMemSpiFFS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
