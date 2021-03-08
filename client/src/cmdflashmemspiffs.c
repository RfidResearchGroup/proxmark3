//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

static int usage_flashmemspiffs_copy(void) {
    PrintAndLogEx(NORMAL, "Copy a file to another (destructively) in spiffs filesystem\n");
    PrintAndLogEx(NORMAL, "Usage:  mem spiffs copy <source> <destination>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        mem spiffs copy lasttag.bin lasttag_cpy.bin"));
    return PM3_SUCCESS;
}

static int usage_flashmemspiffs_dump(void) {
    PrintAndLogEx(NORMAL, "Dumps flash memory on device into a file or in console");
    PrintAndLogEx(NORMAL, "Size is handled by first sending a STAT command against file existence\n");
    PrintAndLogEx(NORMAL, "Usage:  mem spiffs dump o <filename> [f <file name> [e]] [p]");
    PrintAndLogEx(NORMAL, "  o <filename>        - filename in SPIFFS");
    PrintAndLogEx(NORMAL, "  f <filename>        - file name to save to <w/o .bin>");
    PrintAndLogEx(NORMAL, "  p                   - print dump in console");
    PrintAndLogEx(NORMAL, "  e                   - also save in EML format (good for tags save and dictonnary files)");
    PrintAndLogEx(NORMAL, " You must specify at lease option f or option p, both if you wish");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        mem spiffs dump o lasttag.bin f lasttag e"));
    PrintAndLogEx(NORMAL, _YELLOW_("        mem spiffs dump o lasttag.bin p"));
    return PM3_SUCCESS;
}

static int usage_flashmemspiffs_load(void) {
    PrintAndLogEx(NORMAL, "Uploads binary-wise file into device filesystem");
    PrintAndLogEx(NORMAL, "Warning: mem area to be written must have been wiped first");
    PrintAndLogEx(NORMAL, "(this is already taken care when loading dictionaries)\n");
    PrintAndLogEx(NORMAL, "Usage:  mem spiffs load o <filename> f <filename>");
    PrintAndLogEx(NORMAL, "  o <filename>       - destination filename");
    PrintAndLogEx(NORMAL, "  f <filename>       - local filename");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        mem spiffs load f myfile o myapp.conf"));
    return PM3_SUCCESS;
}

static int usage_flashmemspiffs_wipe(void) {
    PrintAndLogEx(NORMAL, "wipes all files on the device filesystem " _RED_("* Warning *"));
    PrintAndLogEx(NORMAL, "Usage:  mem spiffs wipe [h]");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        mem spiffs wipe"));
    return PM3_SUCCESS;
}


int flashmem_spiffs_load(uint8_t *destfn, uint8_t *data, size_t datalen) {

    int ret_val = PM3_SUCCESS;

    // We want to mount before multiple operation so the lazy writes/append will not
    // trigger a mount + umount each loop iteration (lazy ops device side)
    SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);

    // Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;
    uint32_t append = 0;

    // fast push mode
    conn.block_after_ACK = true;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        clearCommandBuffer();

        char fdata[32 + bytes_in_packet];
        memset(fdata, 0, sizeof(fdata));
        memcpy(fdata, destfn, 32);
        memcpy(fdata + 32, data + bytes_sent, bytes_in_packet);

        if (bytes_sent > 0)
            append = 1;

        SendCommandOLD(CMD_SPIFFS_WRITE, append, bytes_in_packet, 0, fdata, 32 + bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        PacketResponseNG resp;

        uint8_t retry = 3;
        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            retry--;
            if (retry == 0) {
                ret_val = PM3_ETIMEOUT;
                goto out;
            }
        }

        uint8_t isok = resp.oldarg[0] & 0xFF;
        if (!isok) {
            PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);
            ret_val = PM3_EFLASH;
            break;
        }
    }

out:
    clearCommandBuffer();

    // turn off fast push mode
    conn.block_after_ACK = false;

    // We want to unmount after these to set things back to normal but more than this
    // unmouting ensure that SPIFFS CACHES are all flushed so our file is actually written on memory
    SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);

    return ret_val;
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
        arg_str1("f", "filename", "<fn>", "file to remove"),
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
    int len = strlen(Cmd);
    if (len < 1) {
        return usage_flashmemspiffs_copy();
    }

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (len == 1 && ctmp == 'h') {
        return usage_flashmemspiffs_copy();
    }


    char srcfilename[32] = {0};
    char destfilename[32] = {0};
    bool errors = false;

    if (param_getstr(Cmd, 0, srcfilename, 32) >= 32) {
        PrintAndLogEx(FAILED, "Source Filename too long");
        errors = true;
    }
    if (srcfilename[0] == '\0') {
        PrintAndLogEx(FAILED, "Source Filename missing or invalid");
        errors = true;
    }

    if (param_getstr(Cmd, 1, destfilename, 32) >= 32) {
        PrintAndLogEx(FAILED, "Source Filename too long");
        errors = true;
    }
    if (destfilename[0] == '\0') {
        PrintAndLogEx(FAILED, "Source Filename missing or invalid");
        errors = true;
    }

    // check null filename ?
    if (errors) {
        usage_flashmemspiffs_copy();
        return PM3_EINVARG;
    }

    char data[65];
    sprintf(data, "%s,%s", srcfilename, destfilename);
    SendCommandMIX(CMD_SPIFFS_COPY, 0, 0, 0, (uint8_t *)data, 65);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSDump(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t cmdp = 0;
    bool errors = false;
    bool print = false;
    uint32_t start_index = 0, len = FLASH_MEM_MAX_SIZE;
    char destfilename[32] = {0};
    bool eml = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmemspiffs_dump();
            /*case 'l':
                len = param_get32ex(Cmd, cmdp + 1, FLASH_MEM_MAX_SIZE, 10);
                cmdp += 2;
                break;*/
            case 'o':
                param_getstr(Cmd, cmdp + 1, destfilename, 32);
                cmdp += 2;
                break;
            case 'p':
                print = true;
                cmdp += 1;
                break;
            case 'e':
                eml = true;
                cmdp += 1;
                break;
            case 'f':
                // File handling
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if ((filename[0] == '\0') && (!print)) {
        PrintAndLogEx(FAILED, "No print asked and local dump filename missing or invalid");
        errors = true;
    }

    if (destfilename[0] == '\0') {
        PrintAndLogEx(FAILED, "SPIFFS filename missing or invalid");
        errors = true;
    }

    // Validations
    if (errors || cmdp == 0) {
        usage_flashmemspiffs_dump();
        return PM3_EINVARG;
    }

    // get size from spiffs itself !
    SendCommandMIX(CMD_SPIFFS_STAT, 0, 0, 0, (uint8_t *)destfilename, 32);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    len = resp.oldarg[0];

    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u") " bytes from spiffs (flashmem)", len);
    if (!GetFromDevice(SPIFFS, dump, len, start_index, (uint8_t *)destfilename, 32, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "ERROR; downloading from spiffs(flashmemory)");
        free(dump);
        return PM3_EFLASH;
    }

    if (print) {
        print_hex_break(dump, len, 32);
    }

    if (filename[0] != '\0') {
        saveFile(filename, ".bin", dump, len);
        if (eml) {
            uint8_t eml_len = 16;

            if (strstr(filename, "class") != NULL)
                eml_len = 8;
            else if (strstr(filename, "mfu") != NULL)
                eml_len = 4;

            saveFileEML(filename, dump, len, eml_len);
        }
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSWipe(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') {
        return usage_flashmemspiffs_wipe();
    }

    PrintAndLogEx(INFO, "Wiping all files from SPIFFS FileSystem");
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_WIPE, NULL, 0);
    WaitForResponse(CMD_SPIFFS_WIPE, &resp);
    PrintAndLogEx(INFO, "Done!");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("mem spiffs tree") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSLoad(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t destfilename[32] = {0};
    bool errors = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmemspiffs_load();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'o':
                param_getstr(Cmd, cmdp + 1, (char *)destfilename, 32);
                if (strlen((char *)destfilename) == 0) {
                    PrintAndLogEx(FAILED, "Destination Filename missing or invalid");
                    errors = true;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // Validations
    if (errors || cmdp == 0)
        return usage_flashmemspiffs_load();

    size_t datalen = 0;
    uint8_t *data = NULL;

    int res = loadFile_safe(filename, "", (void **)&data, &datalen);
    // int res = loadFileEML( filename, data, &datalen);
    if (res != PM3_SUCCESS) {
        free(data);
        return PM3_EFILE;
    }

    res = flashmem_spiffs_load(destfilename, data, datalen);

    free(data);

    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%zu") " bytes to file "_GREEN_("%s"), datalen, destfilename);

    return res;
}

static command_t CommandTable[] = {
    {"help", CmdHelp, AlwaysAvailable, "This help"},
    {"copy",    CmdFlashMemSpiFFSCopy,    IfPm3Flash, "Copy a file to another (destructively) in SPIFFS file system"},
    {"check",   CmdFlashMemSpiFFSCheck,   IfPm3Flash, "Check/try to defrag faulty/fragmented file system"},
    {"dump",    CmdFlashMemSpiFFSDump,    IfPm3Flash, "Dump a file from SPIFFS file system"},
    {"info",    CmdFlashMemSpiFFSInfo,    IfPm3Flash, "Print file system info and usage statistics"},
    {"load",    CmdFlashMemSpiFFSLoad,    IfPm3Flash, "Upload file into SPIFFS file system"},
    {"mount",   CmdFlashMemSpiFFSMount,   IfPm3Flash, "Mount the SPIFFS file system if not already mounted"},
    {"remove",  CmdFlashMemSpiFFSRemove,  IfPm3Flash, "Remove a file from SPIFFS file system"},
    {"rename",  CmdFlashMemSpiFFSRename,  IfPm3Flash, "Rename/move a file in SPIFFS file system"},
    {"test",    CmdFlashMemSpiFFSTest,    IfPm3Flash, "Test SPIFFS Operations"},
    {"tree",    CmdFlashMemSpiFFSTree,    IfPm3Flash, "Print the Flash memory file system tree"},
    {"unmount", CmdFlashMemSpiFFSUnmount, IfPm3Flash, "Un-mount the SPIFFS file system"},
    {"wipe",    CmdFlashMemSpiFFSWipe,    IfPm3Flash, "Wipe all files from SPIFFS file system. * " _RED_("dangerous") " *" },
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
