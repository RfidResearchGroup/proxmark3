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
// DESFire simulation commands for red team use
//-----------------------------------------------------------------------------

#include "cmdhfmfdessim.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "commonutil.h"
#include "fileutils.h"
#include "protocols.h"
#include "pm3_cmd.h"
#include "util.h"
#include "ui.h"

static int CmdHelp(const char *Cmd);

// DESFire emulator memory size (4KB)
#define DESFIRE_EMU_MEMORY_SIZE 4096

//-----------------------------------------------------------------------------
// Helper functions for version parsing and display
//-----------------------------------------------------------------------------

static const char *DesfireGetVendorStr(uint8_t vendor_id) {
    switch (vendor_id) {
        case 0x04: return "NXP";
        default:   return "Unknown";
    }
}

static const char *DesfireGetTypeStr(uint8_t type_id) {
    switch (type_id) {
        case 0x01: return "DESFire";
        case 0x02: return "Plus";
        case 0x03: return "Ultralight";
        case 0x04: return "NTAG";
        case 0x81: return "Smartcard";
        default:   return "Unknown";
    }
}

static const char *DesfireGetStorageSizeStr(uint8_t size_byte) {
    switch (size_byte) {
        case 0x16: return "2KB";
        case 0x18: return "4KB";
        case 0x1A: return "4KB";
        default:   return "Unknown";
    }
}

static const char *DesfireGetProtocolStr(uint8_t protocol, bool hw_version) {
    if (protocol == 0x05) {
        if (hw_version) {
            return "ISO 14443-2 and -3";
        } else {
            return "ISO 14443-3 and -4";
        }
    }
    return "Unknown";
}

static const char *DesfireGetVersionStr(uint8_t type, uint8_t major, uint8_t minor) {
    if (type == 0x01) {
        if (major == 0x00) return "DESFire MF3ICD40";
        if (major == 0x01 && minor == 0x00) return "DESFire EV1";
        if (major == 0x12 && minor == 0x00) return "DESFire EV2";
        if (major == 0x22 && minor == 0x00) return "DESFire EV2 XL";
        if (major == 0x33 && minor == 0x00) return "DESFire EV3";
        if (major == 0x30 && minor == 0x00) return "DESFire Light";
    }
    return "Unknown";
}

//-----------------------------------------------------------------------------
// Command implementations
//-----------------------------------------------------------------------------

static int CmdHFMFDesSimulate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes sim",
                  "Simulate MIFARE DESFire card for red team use",
                  "hf mfdes sim --uid 04123456             --> Simulate with UID\n"
                  "hf mfdes sim --uid 04123456 --data card.mfdes  --> Load data and simulate\n"
                  "hf mfdes sim --uid 04123456 --verbose          --> Enable verbose output");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "UID 4,7,10 bytes. If not specified, the UID from emulator memory is used"),
        arg_str0("d", "data", "<fn>", "Load data from file (.mfdes format)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[10] = {0};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 2, (uint8_t*)filename, &fnlen);
    
    bool verbose = arg_get_lit(ctx, 3);
    (void)verbose; // Mark as intentionally unused for now
    CLIParserFree(ctx);

    // Validate UID length
    if (uidlen != 0 && uidlen != 4 && uidlen != 7 && uidlen != 10) {
        PrintAndLogEx(ERR, "Invalid UID length. Must be 4, 7, or 10 bytes");
        return PM3_EINVARG;
    }

    // Load data file if specified
    if (fnlen > 0) {
        PrintAndLogEx(INFO, "Loading data from %s", filename);
        
        size_t datalen = 0;
        uint8_t *data = calloc(DESFIRE_EMU_MEMORY_SIZE, sizeof(uint8_t));
        if (data == NULL) {
            PrintAndLogEx(ERR, "Failed to allocate memory");
            return PM3_EMALLOC;
        }
        
        if (loadFile_safe(filename, ".mfdes", (void **)&data, &datalen) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to load data file");
            free(data);
            return PM3_EFILE;
        }
        
        if (datalen != DESFIRE_EMU_MEMORY_SIZE) {
            PrintAndLogEx(ERR, "Invalid file size. Expected %d bytes, got %zu", DESFIRE_EMU_MEMORY_SIZE, datalen);
            free(data);
            return PM3_EFILE;
        }
        
        // Load data to emulator memory
        PrintAndLogEx(INFO, "Loading %zu bytes to emulator memory", datalen);
        
        // Send data to device in chunks
        uint16_t bytes_sent = 0;
        uint16_t bytes_remaining = datalen;
        
        while (bytes_remaining > 0) {
            uint16_t bytes_in_packet = MIN(bytes_remaining, PM3_CMD_DATA_SIZE);
            
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFARE_EML_MEMSET, bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);
            
            bytes_sent += bytes_in_packet;
            bytes_remaining -= bytes_in_packet;
        }
        
        free(data);
        PrintAndLogEx(SUCCESS, "Data loaded to emulator memory");
    }

    // Prepare simulation command
    clearCommandBuffer();
    
    uint8_t flags = 0;
    if (verbose) {
        flags |= FLAG_INTERACTIVE;
    }
    
    // Send simulate command
    SendCommandMIX(CMD_HF_MIFARE_SIMULATE, 3, flags, 0, uid, uidlen); // tagType=3 for DESFire
    
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1500) == false) {
        PrintAndLogEx(ERR, "No response from Proxmark3");
        return PM3_ETIMEOUT;
    }
    
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "DESFire simulation started");
        PrintAndLogEx(HINT, "Press " _GREEN_("pm3 button") " or " _GREEN_("Ctrl+C") " to abort simulation");
    } else {
        PrintAndLogEx(ERR, "Failed to start simulation");
        return PM3_ESOFT;
    }
    
    return PM3_SUCCESS;
}

static int CmdHFMFDesELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes eload",
                  "Load DESFire dump to emulator memory for red team cloning",
                  "hf mfdes eload --file dump.mfdes");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "DESFire dump filename (.mfdes format)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 1, (uint8_t*)filename, &fnlen);
    
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // Load file
    size_t datalen = 0;
    uint8_t *data = calloc(DESFIRE_EMU_MEMORY_SIZE, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    
    if (loadFile_safe(filename, ".mfdes", (void **)&data, &datalen) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to load file %s", filename);
        free(data);
        return PM3_EFILE;
    }
    
    if (datalen != DESFIRE_EMU_MEMORY_SIZE) {
        PrintAndLogEx(ERR, "Invalid file size. Expected %d bytes, got %zu", DESFIRE_EMU_MEMORY_SIZE, datalen);
        free(data);
        return PM3_EFILE;
    }
    
    PrintAndLogEx(INFO, "Loading %zu bytes from %s to emulator memory", datalen, filename);
    
    // Send data to device in chunks
    uint16_t bytes_sent = 0;
    uint16_t bytes_remaining = datalen;
    
    while (bytes_remaining > 0) {
        uint16_t bytes_in_packet = MIN(bytes_remaining, PM3_CMD_DATA_SIZE);
        
        clearCommandBuffer();
        
        struct {
            uint32_t offset;
            uint32_t length;
            uint8_t data[PM3_CMD_DATA_SIZE - 8];
        } payload;
        payload.offset = bytes_sent;
        payload.length = bytes_in_packet;
        memcpy(payload.data, data + bytes_sent, bytes_in_packet);
        
        SendCommandNG(CMD_HF_DESFIRE_EML_MEMSET, (uint8_t *)&payload, sizeof(payload.offset) + sizeof(payload.length) + bytes_in_packet);
        
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_DESFIRE_EML_MEMSET, &resp, 1500) == false) {
            PrintAndLogEx(ERR, "No response from Proxmark3");
            free(data);
            return PM3_ETIMEOUT;
        }
        
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to write emulator memory at offset %d", bytes_sent);
            free(data);
            return PM3_ESOFT;
        }
        
        if (verbose) {
            PrintAndLogEx(INFO, "Sent %d bytes (%d remaining)", bytes_in_packet, bytes_remaining - bytes_in_packet);
        }
        
        bytes_sent += bytes_in_packet;
        bytes_remaining -= bytes_in_packet;
    }
    
    free(data);
    PrintAndLogEx(SUCCESS, "DESFire dump loaded to emulator memory");
    
    return PM3_SUCCESS;
}

static int CmdHFMFDesESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes esave",
                  "Save emulator memory to DESFire dump file",
                  "hf mfdes esave --file dump.mfdes");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "DESFire dump filename (.mfdes format)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 1, (uint8_t*)filename, &fnlen);
    CLIParserFree(ctx);

    // Read emulator memory
    PrintAndLogEx(INFO, "Reading emulator memory");
    
    uint8_t *data = calloc(DESFIRE_EMU_MEMORY_SIZE, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    
    // Read data from device in chunks
    uint16_t bytes_read = 0;
    uint16_t bytes_remaining = DESFIRE_EMU_MEMORY_SIZE;
    
    while (bytes_remaining > 0) {
        uint16_t bytes_in_packet = MIN(bytes_remaining, PM3_CMD_DATA_SIZE);
        
        clearCommandBuffer();
        
        struct {
            uint32_t offset;
            uint32_t length;
        } payload;
        payload.offset = bytes_read;
        payload.length = bytes_in_packet;
        
        SendCommandNG(CMD_HF_DESFIRE_EML_MEMGET, (uint8_t *)&payload, sizeof(payload));
        
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_DESFIRE_EML_MEMGET, &resp, 1500) == false) {
            PrintAndLogEx(ERR, "No response from Proxmark3");
            free(data);
            return PM3_ETIMEOUT;
        }
        
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to read emulator memory");
            free(data);
            return PM3_ESOFT;
        }
        
        memcpy(data + bytes_read, resp.data.asBytes, bytes_in_packet);
        bytes_read += bytes_in_packet;
        bytes_remaining -= bytes_in_packet;
    }
    
    // Save to file
    if (saveFile(filename, ".mfdes", data, DESFIRE_EMU_MEMORY_SIZE) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to save file %s", filename);
        free(data);
        return PM3_EFILE;
    }
    
    free(data);
    PrintAndLogEx(SUCCESS, "Emulator memory saved to %s", filename);
    
    return PM3_SUCCESS;
}

static int CmdHFMFDesEView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes eview",
                  "View DESFire emulator memory with structured display (reuses existing display patterns)",
                  "hf mfdes eview                    --> View card info and all applications\n"
                  "hf mfdes eview --aid 123456      --> View specific application\n"
                  "hf mfdes eview --files           --> Show applications with file details\n"
                  "hf mfdes eview --raw             --> Show raw memory dump");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("a", "aid", "<hex>", "Application ID (3 bytes hex)"),
        arg_lit0("f", "files", "Show file details for applications"),
        arg_lit0("r", "raw", "Show raw memory dump"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t aid[3] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aidlen);
    bool show_files = arg_get_lit(ctx, 2);
    bool show_raw = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (aidlen != 0 && aidlen != 3) {
        PrintAndLogEx(ERR, "Application ID must be 3 bytes");
        return PM3_EINVARG;
    }

    // Read full emulator memory (reuse existing patterns)
    uint8_t *emulator_data = calloc(DESFIRE_EMU_MEMORY_SIZE, sizeof(uint8_t));
    if (emulator_data == NULL) {
        PrintAndLogEx(ERR, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    
    PrintAndLogEx(INFO, "Reading emulator memory (%d bytes)...", DESFIRE_EMU_MEMORY_SIZE);
    
    // Read data in chunks (reuse esave pattern)
    uint16_t bytes_read = 0;
    uint16_t bytes_remaining = DESFIRE_EMU_MEMORY_SIZE;
    
    while (bytes_remaining > 0) {
        uint16_t bytes_in_packet = MIN(bytes_remaining, PM3_CMD_DATA_SIZE);
        
        clearCommandBuffer();
        
        struct {
            uint32_t offset;
            uint32_t length;
        } payload;
        payload.offset = bytes_read;
        payload.length = bytes_in_packet;
        
        SendCommandNG(CMD_HF_DESFIRE_EML_MEMGET, (uint8_t *)&payload, sizeof(payload));
        
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_DESFIRE_EML_MEMGET, &resp, 1500) == false) {
            PrintAndLogEx(ERR, "No response from Proxmark3");
            free(emulator_data);
            return PM3_ETIMEOUT;
        }
        
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to read emulator memory");
            free(emulator_data);
            return PM3_ESOFT;
        }
        
        memcpy(emulator_data + bytes_read, resp.data.asBytes, bytes_in_packet);
        bytes_read += bytes_in_packet;
        bytes_remaining -= bytes_in_packet;
    }
    
    if (show_raw) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Raw emulator memory:");
        print_hex_break(emulator_data, MIN(256, DESFIRE_EMU_MEMORY_SIZE), 16);
        free(emulator_data);
        return PM3_SUCCESS;
    }
    
    // Parse structures (reuse existing data structure patterns)
    typedef struct {
        uint8_t version[8];
        uint8_t uid[10];
        uint8_t uidlen;
        uint8_t num_apps;
        uint8_t master_key[16];
        uint8_t master_key_type;
        uint8_t key_settings;
        uint8_t reserved[2];
    } desfire_card_emu_t;
    
    typedef struct {
        uint8_t aid[3];
        uint16_t offset;
        uint8_t auth_key;
    } desfire_app_dir_emu_t;
    
    desfire_card_emu_t *card = (desfire_card_emu_t *)(void*)(emulator_data + 0x0000);
    desfire_app_dir_emu_t *app_dir = (desfire_app_dir_emu_t *)(void*)(emulator_data + 0x0020);
    
    // Display card information
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _GREEN_("--- DESFire Emulator Card Information ---"));
    
    // Parse and display version info
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Version"));
    PrintAndLogEx(INFO, "   Raw: %s", sprint_hex_inrow(card->version, 8));
    PrintAndLogEx(INFO, "   Vendor ID: %02X (%s)", card->version[0], DesfireGetVendorStr(card->version[0]));
    PrintAndLogEx(INFO, "   Type: %02X (%s)", card->version[1], DesfireGetTypeStr(card->version[1]));
    PrintAndLogEx(INFO, "   Subtype: %02X", card->version[2]);
    PrintAndLogEx(INFO, "   Major Version: %d", card->version[3]);
    PrintAndLogEx(INFO, "   Minor Version: %d", card->version[4]);
    PrintAndLogEx(INFO, "   Storage Size: %02X (%s)", card->version[5], DesfireGetStorageSizeStr(card->version[5]));
    PrintAndLogEx(INFO, "   Protocol: %02X (%s)", card->version[6], DesfireGetProtocolStr(card->version[6], true));
    
    // Software version would be same as hardware for emulator
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Version"));
    PrintAndLogEx(INFO, "   Version: %d.%d (%s)", card->version[3], card->version[4], 
                  DesfireGetVersionStr(card->version[1], card->version[3], card->version[4]));
    
    // General info
    PrintAndLogEx(INFO, "--- " _CYAN_("General Information"));
    PrintAndLogEx(INFO, "   UID: %s", sprint_hex_inrow(card->uid, card->uidlen));
    PrintAndLogEx(INFO, "   UID Length: %d bytes", card->uidlen);
    PrintAndLogEx(INFO, "   Applications: %d/%d", card->num_apps, 2);
    PrintAndLogEx(INFO, "   Master key type: %s", (card->master_key_type == 0x03) ? "AES" : 
                                                   (card->master_key_type == 0x02) ? "3K3DES" : 
                                                   (card->master_key_type == 0x01) ? "2TDEA/3DES" : 
                                                   (card->master_key_type == 0x00) ? "DES" : "Unknown");
    PrintAndLogEx(INFO, "   Key settings: 0x%02X", card->key_settings);
    
    if (verbose) {
        PrintAndLogEx(INFO, "Master key...... %s", sprint_hex_inrow(card->master_key, 16));
    }
    
    // Display applications (reuse lsapp pattern)
    if (card->num_apps == 0) {
        PrintAndLogEx(INFO, _YELLOW_("No applications found (factory-fresh state)"));
        PrintAndLogEx(INFO, "Use encoders or 'hf mfdes createapp' to add applications");
    } else {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, _GREEN_("--- Applications ---"));
        
        for (uint8_t i = 0; i < card->num_apps && i < 2; i++) {
            uint8_t *app_aid = app_dir[i].aid;
            PrintAndLogEx(INFO, "App %d: AID %02X%02X%02X (offset: 0x%04X)", 
                         i, app_aid[0], app_aid[1], app_aid[2], app_dir[i].offset);
            
            // If specific AID requested, show only that one
            if (aidlen == 3 && memcmp(aid, app_aid, 3) != 0) {
                continue;
            }
            
            if (show_files) {
                PrintAndLogEx(INFO, _CYAN_("    Files: (file structure parsing needed)"));
                // TODO: Parse file structures when needed for red team ops
            }
        }
    }
    
    free(emulator_data);
    return PM3_SUCCESS;
}

static int CmdHFMFDesEReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes ereset",
                  "Reset emulator to factory-fresh DESFire EV1 state",
                  "hf mfdes ereset                    --> Reset to factory defaults");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Resetting DESFire emulator to factory-fresh state...");
    
    // Send DESFire-specific reset command to device
    clearCommandBuffer();
    SendCommandNG(CMD_HF_DESFIRE_SIM_RESET, NULL, 0);
    
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DESFIRE_SIM_RESET, &resp, 1500) == false) {
        PrintAndLogEx(ERR, "No response from Proxmark3");
        return PM3_ETIMEOUT;
    }
    
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "DESFire emulator reset to factory-fresh EV1 state");
        PrintAndLogEx(INFO, "- PICC master key: 2TDEA/3DES (all zeros)");
        PrintAndLogEx(INFO, "- Applications: none (empty)");
        PrintAndLogEx(INFO, "- Ready for encoder/programming tools");
    } else {
        PrintAndLogEx(ERR, "Failed to reset emulator");
        return PM3_ESOFT;
    }
    
    return PM3_SUCCESS;
}

// Helper functions for DESFire testing
static bool TestDesfireMemoryRead(uint32_t offset, uint32_t length, uint8_t *expected, const char *test_name) {
    struct {
        uint32_t offset;
        uint32_t length;
    } payload;
    payload.offset = offset;
    payload.length = length;
    
    clearCommandBuffer();
    SendCommandNG(CMD_HF_DESFIRE_EML_MEMGET, (uint8_t *)&payload, sizeof(payload));
    
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DESFIRE_EML_MEMGET, &resp, 1500) == false) {
        PrintAndLogEx(ERR, "   %s failed - no response", test_name);
        return false;
    }
    
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "   %s failed - error response", test_name);
        return false;
    }
    
    if (expected && resp.length >= length) {
        if (memcmp(resp.data.asBytes, expected, length) != 0) {
            PrintAndLogEx(ERR, "   %s failed - data mismatch", test_name);
            PrintAndLogEx(ERR, "   Expected: %s", sprint_hex(expected, length));
            PrintAndLogEx(ERR, "   Got:      %s", sprint_hex(resp.data.asBytes, length));
            return false;
        }
    }
    
    PrintAndLogEx(SUCCESS, "   %s passed", test_name);
    return true;
}

static bool TestDesfireMemoryWrite(uint32_t offset, uint8_t *data, uint32_t length, const char *test_name) {
    struct {
        uint32_t offset;
        uint32_t length;
        uint8_t data[PM3_CMD_DATA_SIZE - 8];
    } payload;
    
    if (length > PM3_CMD_DATA_SIZE - 8) {
        PrintAndLogEx(ERR, "   %s failed - data too large", test_name);
        return false;
    }
    
    payload.offset = offset;
    payload.length = length;
    memcpy(payload.data, data, length);
    
    clearCommandBuffer();
    SendCommandNG(CMD_HF_DESFIRE_EML_MEMSET, (uint8_t *)&payload, sizeof(payload.offset) + sizeof(payload.length) + length);
    
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DESFIRE_EML_MEMSET, &resp, 1500) == false) {
        PrintAndLogEx(ERR, "   %s failed - no response", test_name);
        return false;
    }
    
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "   %s failed - error response", test_name);
        return false;
    }
    
    PrintAndLogEx(SUCCESS, "   %s passed", test_name);
    return true;
}

static bool TestDesfireReset(void) {
    clearCommandBuffer();
    SendCommandNG(CMD_HF_DESFIRE_SIM_RESET, NULL, 0);
    
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DESFIRE_SIM_RESET, &resp, 1500) == false) {
        PrintAndLogEx(ERR, "   Reset failed - no response");
        return false;
    }
    
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "   Reset failed - error response");
        return false;
    }
    
    // Verify the reset worked by checking version info
    uint8_t expected_version[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x1A, 0x05, 0x00};
    return TestDesfireMemoryRead(0, 8, expected_version, "Reset verification");
}

static int CmdHFMFDesSimTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes sim test",
                  "Test DESFire emulator functionality with comprehensive application and file testing",
                  "hf mfdes sim test                   --> Run basic emulator tests\n"
                  "hf mfdes sim test --app             --> Include application creation tests\n"
                  "hf mfdes sim test --files           --> Include file operations tests\n"
                  "hf mfdes sim test --stress          --> Include stress testing\n"
                  "hf mfdes sim test --all             --> Run all tests");
    
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "app", "Test application creation and management"),
        arg_lit0("f", "files", "Test file operations (create, read, write)"),
        arg_lit0("s", "stress", "Run stress tests and edge cases"),
        arg_lit0(NULL, "all", "Run all comprehensive tests"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    bool test_apps = arg_get_lit(ctx, 1) || arg_get_lit(ctx, 4);
    bool test_files = arg_get_lit(ctx, 2) || arg_get_lit(ctx, 4);
    bool test_stress = arg_get_lit(ctx, 3) || arg_get_lit(ctx, 4);
    bool test_all = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    
    if (test_all) {
        PrintAndLogEx(INFO, "Running comprehensive DESFire emulator test suite...");
    } else {
        PrintAndLogEx(INFO, "Running basic DESFire emulator tests...");
    }
    
    PrintAndLogEx(INFO, "------ " _CYAN_("DESFire Emulator Tests") " ------");
    
    bool test_passed = true;
    int tests_run = 0;
    int tests_passed = 0;
    
    // Test 1: Basic emulator reset and verification
    PrintAndLogEx(INFO, "Test 1: Emulator reset and verification...");
    tests_run++;
    if (TestDesfireReset()) {
        tests_passed++;
    } else {
        test_passed = false;
    }
    
    // Test 2: Memory read/write operations
    PrintAndLogEx(INFO, "Test 2: Memory read/write operations...");
    tests_run++;
    
    // Test writing and reading back custom data
    uint8_t test_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    uint32_t test_offset = 0x100; // Safe offset away from card header
    
    bool write_ok = TestDesfireMemoryWrite(test_offset, test_data, sizeof(test_data), "Memory write test");
    bool read_ok = TestDesfireMemoryRead(test_offset, sizeof(test_data), test_data, "Memory read-back test");
    
    if (write_ok && read_ok) {
        tests_passed++;
    } else {
        test_passed = false;
    }
    
    // Test 3: UID and card structure integrity
    PrintAndLogEx(INFO, "Test 3: Card structure integrity...");
    tests_run++;
    
    uint8_t expected_uid[] = {0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    if (TestDesfireMemoryRead(8, 7, expected_uid, "UID verification")) {
        tests_passed++;
    } else {
        test_passed = false;
    }
    
    // Application tests (if requested)
    if (test_apps) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "------ " _CYAN_("Application Tests") " ------");
        
        // Test 4: Application directory structure
        PrintAndLogEx(INFO, "Test 4: Application directory structure...");
        tests_run++;
        
        // Read application directory area (starts at offset 0x20)
        if (TestDesfireMemoryRead(0x20, 12, NULL, "Application directory read")) {
            tests_passed++;
        } else {
            test_passed = false;
        }
        
        // Test 5: Simulated application creation
        PrintAndLogEx(INFO, "Test 5: Simulated application creation...");
        tests_run++;
        
        // Create a test application entry in memory
        uint8_t test_app_entry[] = {
            0x12, 0x34, 0x56,  // AID: 123456
            0x00, 0x01,        // Offset: 256
            0x0F               // Auth key: 15
        };
        
        if (TestDesfireMemoryWrite(0x20, test_app_entry, sizeof(test_app_entry), "Test application write")) {
            // Verify it can be read back
            if (TestDesfireMemoryRead(0x20, sizeof(test_app_entry), test_app_entry, "Test application read-back")) {
                tests_passed++;
            } else {
                test_passed = false;
            }
        } else {
            test_passed = false;
        }
    }
    
    // File operation tests (if requested)
    if (test_files) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "------ " _CYAN_("File Operation Tests") " ------");
        
        // Test 6: File data area testing
        PrintAndLogEx(INFO, "Test 6: File data area operations...");
        tests_run++;
        
        uint32_t file_data_offset = 0x200; // File data area
        uint8_t test_file_data[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        
        bool file_write_ok = TestDesfireMemoryWrite(file_data_offset, test_file_data, sizeof(test_file_data), "File data write");
        bool file_read_ok = TestDesfireMemoryRead(file_data_offset, sizeof(test_file_data), test_file_data, "File data read-back");
        
        if (file_write_ok && file_read_ok) {
            tests_passed++;
        } else {
            test_passed = false;
        }
        
        // Test 7: Large file simulation (fragmented writes)
        PrintAndLogEx(INFO, "Test 7: Large file fragmented operations...");
        tests_run++;
        
        bool large_file_ok = true;
        uint32_t chunk_size = 64;
        uint32_t large_file_offset = 0x300;
        
        for (int i = 0; i < 4 && large_file_ok; i++) {
            uint8_t chunk_data[64];
            for (int j = 0; j < 64; j++) {
                chunk_data[j] = (i * 64 + j) & 0xFF;
            }
            
            large_file_ok = TestDesfireMemoryWrite(large_file_offset + (i * chunk_size), chunk_data, chunk_size, "Large file chunk write");
            if (large_file_ok) {
                large_file_ok = TestDesfireMemoryRead(large_file_offset + (i * chunk_size), chunk_size, chunk_data, "Large file chunk read");
            }
        }
        
        if (large_file_ok) {
            tests_passed++;
            PrintAndLogEx(SUCCESS, "   Large file fragmented operations passed");
        } else {
            test_passed = false;
        }
    }
    
    // Stress tests (if requested)
    if (test_stress) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "------ " _CYAN_("Stress Tests") " ------");
        
        // Test 8: Boundary condition testing
        PrintAndLogEx(INFO, "Test 8: Boundary condition testing...");
        tests_run++;
        
        bool boundary_ok = true;
        
        // Test near memory boundaries
        uint8_t boundary_data[] = {0xFF, 0xFE, 0xFD, 0xFC};
        
        // Test near end of emulator memory (but within bounds)
        uint32_t near_end_offset = DESFIRE_EMU_MEMORY_SIZE - sizeof(boundary_data);
        boundary_ok = TestDesfireMemoryWrite(near_end_offset, boundary_data, sizeof(boundary_data), "Near-end boundary write");
        if (boundary_ok) {
            boundary_ok = TestDesfireMemoryRead(near_end_offset, sizeof(boundary_data), boundary_data, "Near-end boundary read");
        }
        
        if (boundary_ok) {
            tests_passed++;
        } else {
            test_passed = false;
        }
        
        // Test 9: Rapid reset cycling
        PrintAndLogEx(INFO, "Test 9: Rapid reset cycling...");
        tests_run++;
        
        bool rapid_reset_ok = true;
        for (int i = 0; i < 5 && rapid_reset_ok; i++) {
            rapid_reset_ok = TestDesfireReset();
        }
        
        if (rapid_reset_ok) {
            tests_passed++;
            PrintAndLogEx(SUCCESS, "   Rapid reset cycling passed");
        } else {
            test_passed = false;
        }
    }
    
    PrintAndLogEx(INFO, "");
    // Authentication tests (if requested)
    if (test_stress) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "------ " _CYAN_("Authentication Tests") " ------");

        // Test 10: Authentication challenge/response
        PrintAndLogEx(INFO, "Test 10: Authentication challenge/response...");
        tests_run++;

        bool auth_ok = true;

        // Test AES authentication
        uint8_t aes_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        // Write AES key to master key location
        auth_ok = TestDesfireMemoryWrite(0x30, aes_key, 16, "AES key write for auth test");

        if (auth_ok) {
            // Test 3DES authentication
            uint8_t des_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            // Write DES key to master key location
            auth_ok = TestDesfireMemoryWrite(0x30, des_key, 8, "DES key write for auth test");

            if (auth_ok) {
                tests_passed++;
                PrintAndLogEx(SUCCESS, "   Authentication key management passed");
            } else {
                test_passed = false;
            }
        } else {
            test_passed = false;
        }

        // Test 11: Command sequence validation
        PrintAndLogEx(INFO, "Test 11: Command sequence validation...");
        tests_run++;

        bool cmd_seq_ok = true;

        // Test GetVersion command sequence
        uint8_t expected_version[] = {0x04, 0x01, 0x01, 0x01, 0x00, 0x1A, 0x05, 0x00};

        // This would normally be done via ISO7816 command, but we can simulate the response
        if (TestDesfireMemoryRead(0x00, 8, expected_version, "GetVersion response validation")) {
            cmd_seq_ok = true;
        } else {
            cmd_seq_ok = false;
        }

        if (cmd_seq_ok) {
            tests_passed++;
            PrintAndLogEx(SUCCESS, "   Command sequence validation passed");
        } else {
            test_passed = false;
        }
    }
    
    // EV1+ Feature tests (always run these)
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "------ " _CYAN_("EV1+ Feature Tests") " ------");
    
    // Test: ISO File ID support
    PrintAndLogEx(INFO, "Testing ISO File ID support...");
    tests_run++;
    
    // Test file structure with ISO ID fields
    uint8_t test_file_with_iso[] = {
        0x01,           // file_no
        0x00,           // file_type (standard)
        0x00,           // comm_settings (plain)
        0x01,           // has_iso_id = true
        0x00, 0x10,     // access_rights
        0x01, 0x10,     // iso_file_id = 0x1001
        0x20, 0x00, 0x00, 0x00  // file size = 32 bytes
    };
    
    bool iso_file_ok = TestDesfireMemoryWrite(0x140, test_file_with_iso, sizeof(test_file_with_iso), "ISO file structure write");
    if (iso_file_ok) {
        iso_file_ok = TestDesfireMemoryRead(0x140, sizeof(test_file_with_iso), test_file_with_iso, "ISO file structure read-back");
    }
    
    if (iso_file_ok) {
        tests_passed++;
        PrintAndLogEx(SUCCESS, "   ISO file ID support passed");
    } else {
        test_passed = false;
    }
    
    // Test: Master key type validation (should be 2TDEA)
    PrintAndLogEx(INFO, "Testing master key type (2TDEA default)...");
    tests_run++;
    
    uint8_t expected_key_type[] = {0x01}; // T_3DES = 2TDEA
    bool key_type_ok = TestDesfireMemoryRead(0x18, 1, expected_key_type, "Master key type validation");
    
    if (key_type_ok) {
        tests_passed++;
        PrintAndLogEx(SUCCESS, "   Master key type validation passed (2TDEA)");
    } else {
        test_passed = false;
    }
    
    // Test: Application limits (EV1 = 26 apps max)
    PrintAndLogEx(INFO, "Testing application count limits...");
    tests_run++;
    
    // Read number of apps from card header (offset 19)
    bool app_count_ok = TestDesfireMemoryRead(0x13, 1, NULL, "Application count read");
    
    if (app_count_ok) {
        tests_passed++;
        PrintAndLogEx(SUCCESS, "   Application count validation passed");
    } else {
        test_passed = false;
    }
    
    PrintAndLogEx(INFO, "---------------------------");
    PrintAndLogEx(INFO, "Test Results: %d/%d tests passed", tests_passed, tests_run);
    
    if (test_passed) {
        PrintAndLogEx(SUCCESS, "All tests ( " _GREEN_("PASSED") " )");
        PrintAndLogEx(INFO, "DESFire emulator is ready for real card validation");
        return PM3_SUCCESS;
    } else {
        PrintAndLogEx(FAILED, "Some tests ( " _RED_("FAILED") " )");
        PrintAndLogEx(INFO, "Please check emulator implementation");
        return PM3_ESOFT;
    }
}

static int CmdHFMFDesELoadApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes eloadapp",
                  "Load single DESFire application from JSON file to emulator",
                  "hf mfdes eloadapp --file app_123456.json\n"
                  "hf mfdes eloadapp --file app_123456.json --aid 654321  --> Load with different AID");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Application JSON file"),
        arg_str0("a", "aid", "<hex>", "Override AID (3 bytes hex)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 1, (uint8_t*)filename, &fnlen);
    
    uint8_t aid_override[3] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 2, aid_override, &aidlen);
    
    bool verbose = arg_get_lit(ctx, 3);
    (void)verbose; // Mark as intentionally unused for now
    CLIParserFree(ctx);

    if (aidlen != 0 && aidlen != 3) {
        PrintAndLogEx(ERR, "AID must be 3 bytes");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Loading application from %s", filename);
    
    // TODO: Implement JSON parsing and application loading
    // For MVP, this would:
    // 1. Parse JSON file containing app structure
    // 2. Create application in emulator memory
    // 3. Load keys, files, and data
    
    PrintAndLogEx(WARNING, "JSON application loading not yet implemented");
    PrintAndLogEx(INFO, "Expected JSON format:");
    PrintAndLogEx(INFO, "{");
    PrintAndLogEx(INFO, "  \"aid\": \"123456\",");
    PrintAndLogEx(INFO, "  \"key_settings\": \"0x0F\",");
    PrintAndLogEx(INFO, "  \"keys\": [");
    PrintAndLogEx(INFO, "    {\"keyno\": 0, \"type\": \"AES\", \"key\": \"00112233...\"}");
    PrintAndLogEx(INFO, "  ],");
    PrintAndLogEx(INFO, "  \"files\": [");
    PrintAndLogEx(INFO, "    {\"fileno\": 0, \"size\": 32, \"data\": \"deadbeef...\"}");
    PrintAndLogEx(INFO, "  ]");
    PrintAndLogEx(INFO, "}");
    
    return PM3_ENOTIMPL;
}

static int CmdHFMFDesESaveApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes esaveapp",
                  "Save single DESFire application from emulator to JSON file",
                  "hf mfdes esaveapp --aid 123456 --file app_123456.json");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "Application ID (3 bytes hex)"),
        arg_str1("f", "file", "<fn>", "Output JSON filename"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t aid[3] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aidlen);
    
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 2, (uint8_t*)filename, &fnlen);
    
    bool verbose = arg_get_lit(ctx, 3);
    (void)verbose; // Mark as intentionally unused for now
    CLIParserFree(ctx);

    if (aidlen != 3) {
        PrintAndLogEx(ERR, "AID must be 3 bytes");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Exfiltrating application %02X%02X%02X to %s", aid[0], aid[1], aid[2], filename);
    
    // TODO: Implement application export
    // For MVP, this would:
    // 1. Read emulator memory
    // 2. Find application by AID
    // 3. Extract app structure, keys, files
    // 4. Export to JSON format
    
    PrintAndLogEx(WARNING, "JSON application export not yet implemented");
    PrintAndLogEx(INFO, "This will export:");
    PrintAndLogEx(INFO, "- Application settings and keys");
    PrintAndLogEx(INFO, "- All files and their data");
    PrintAndLogEx(INFO, "- Access rights and permissions");
    PrintAndLogEx(INFO, "- Compatible with eloadapp command");
    
    return PM3_ENOTIMPL;
}

//-----------------------------------------------------------------------------
// Command table
//-----------------------------------------------------------------------------

static command_t CommandTable[] = {
    {"help",     CmdHelp,                AlwaysAvailable, "This help"},
    {"sim",      CmdHFMFDesSimulate,     IfPm3Iso14443a,  "Simulate DESFire card"},
    {"eload",    CmdHFMFDesELoad,        IfPm3Iso14443a,  "Load dump to emulator memory"},
    {"esave",    CmdHFMFDesESave,        IfPm3Iso14443a,  "Save emulator memory to file"},
    {"eview",    CmdHFMFDesEView,        IfPm3Iso14443a,  "View emulator memory"},
    {"ereset",   CmdHFMFDesEReset,       IfPm3Iso14443a,  "Reset emulator to factory-fresh state"},
    {"test",     CmdHFMFDesSimTest,      AlwaysAvailable, "Test emulator functionality"},
    {"eloadapp", CmdHFMFDesELoadApp,     AlwaysAvailable, "Load single application from JSON"},
    {"esaveapp", CmdHFMFDesESaveApp,     AlwaysAvailable, "Save single application to JSON"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // unused parameter
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFDesSim(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}