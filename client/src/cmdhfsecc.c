
#include "cmdhfsecc.h"

#include <string.h>
#include "cmdparser.h"          // command_t
#include "cliparser.h"          // CLIParser*
#include "comms.h"              // SendCommandNG, WaitForResponseTimeout, clearCommandBuffer
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // kbd_enter_pressed, hex_to_bytes
#include "cmdhf14a.h"           // IfPm3Iso14443a
#include "pm3_cmd.h"            // CMD_HF_ISO14443A_SIMULATE, CMD_HF_ISO14443A_SNIFF, CMD_BREAK_LOOP, FLAG_SET_UID_IN_DATA
#include "jansson.h"            // json_load_file, json_object_get, json_string_value, json_decref
#include "fileutils.h"          // searchFile, RESOURCES_SUBDIR

// ---------------------------------------------------------------------------
// Payload structs shared with armsrc/secc.h
// Must stay in sync with hid_apdu_entry_t / hid_sim_payload_t.
// ---------------------------------------------------------------------------

#define HID_APDU_MAX_ENTRIES 8
#define HID_APDU_MAX_CMD     20
#define HID_APDU_MAX_RESP    32

typedef struct {
    uint8_t apdu[HID_APDU_MAX_CMD];
    uint8_t apdu_len;
    uint8_t resp[HID_APDU_MAX_RESP];
    uint8_t resp_len;
} PACKED hid_apdu_entry_t;

typedef struct {
    uint8_t  tagtype;
    uint16_t flags;
    uint8_t  uid[10];
    uint8_t  exitAfter;
    uint8_t  atqa[2];          // big-endian: [0]=high byte, [1]=low byte
    uint8_t  sak;
    uint8_t  scp02_key[16];    // SCP02 master key (from JSON "SCP02Key")
    uint8_t  ats[20];          // ATS bytes without CRC (from JSON "ATS")
    uint8_t  ats_len;          // actual number of valid bytes in ats[]
    uint8_t  apdu_count;
    hid_apdu_entry_t apdu_table[HID_APDU_MAX_ENTRIES];
} PACKED hid_sim_payload_t;

static int CmdHelp(const char *Cmd);

// ---------------------------------------------------------------------------
// hf secc sim
// ---------------------------------------------------------------------------

static int CmdHFHIDConfigSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf secc sim",
                  "Simulate a HID iCLASS SE Config Card (JCOP / GlobalPlatform SCP02).\n"
                  "Responds to SELECT AID (0013/0017), A0 D4, INITIALIZE UPDATE, and EXTERNAL AUTH.\n"
                  "Load card parameters (UID, AID, SCP02Key) from a JSON file.",
                  "hf secc sim -f hidconfig_sample\n"
                  "hf secc sim -f hidconfig_sample -n 5    -> stop after 5 reader interactions");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "JSON file with UID, AID, SCP02Key (without .json extension)"),
        arg_int0("n", "num",  "<dec>", "Exit after <n> reader interactions. 0 = infinite"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char filename[FILE_PATH_SIZE] = {0};
    int filenamelen = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filenamelen);
    uint8_t exitAfterNReads = (uint8_t)arg_get_int_def(ctx, 2, 0);
    CLIParserFree(ctx);

    // Load JSON from client/resources/
    char *filepath = NULL;
    if (searchFile(&filepath, RESOURCES_SUBDIR, filename, ".json", false) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "JSON file '%s.json' not found in resources directory", filename);
        return PM3_EFILE;
    }

    json_error_t jerr;
    json_t *root = json_load_file(filepath, 0, &jerr);
    free(filepath);
    if (root == NULL) {
        PrintAndLogEx(ERR, "Failed to load JSON file '%s.json': %s", filename, jerr.text);
        return PM3_EFILE;
    }

    // Parse UID
    uint8_t uid[10] = {0};
    int uidlen = 0;
    json_t *juid = json_object_get(root, "UID");
    if (json_is_string(juid) == false) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'UID' field");
        json_decref(root);
        return PM3_EINVARG;
    }
    uidlen = hex_to_bytes(json_string_value(juid), uid, sizeof(uid));
    if (uidlen != 4 && uidlen != 7 && uidlen != 10) {
        PrintAndLogEx(ERR, "UID must be 4, 7, or 10 bytes (got %d)", uidlen);
        json_decref(root);
        return PM3_EINVARG;
    }

    // Parse AID (informational only)
    char aid_str[32] = {0};
    json_t *jaid = json_object_get(root, "AID");
    if (json_is_string(jaid))
        snprintf(aid_str, sizeof(aid_str), "%s", json_string_value(jaid));

    // Parse SCP02Key (16 bytes)
    uint8_t scp02_key[16] = {0};
    json_t *jkey = json_object_get(root, "SCP02Key");
    if (json_is_string(jkey) == false) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'SCP02Key' field");
        json_decref(root);
        return PM3_EINVARG;
    }
    if (hex_to_bytes(json_string_value(jkey), scp02_key, sizeof(scp02_key)) != 16) {
        PrintAndLogEx(ERR, "SCP02Key must be exactly 16 bytes (32 hex chars)");
        json_decref(root);
        return PM3_EINVARG;
    }

    // Parse ATS (1-20 bytes, without CRC)
    uint8_t ats[20] = {0};
    int ats_len = 0;
    json_t *jats = json_object_get(root, "ATS");
    if (json_is_string(jats) == false) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'ATS' field");
        json_decref(root);
        return PM3_EINVARG;
    }
    ats_len = hex_to_bytes(json_string_value(jats), ats, sizeof(ats));
    if (ats_len <= 0 || ats_len > 20) {
        PrintAndLogEx(ERR, "ATS must be 1-20 bytes (got %d)", ats_len);
        json_decref(root);
        return PM3_EINVARG;
    }

    // Parse optional APDUResponses array
    hid_apdu_entry_t apdu_table[HID_APDU_MAX_ENTRIES];
    uint8_t apdu_count = 0;
    memset(apdu_table, 0, sizeof(apdu_table));

    json_t *jresps = json_object_get(root, "APDUResponses");
    if (json_is_array(jresps)) {
        size_t n = json_array_size(jresps);
        for (size_t i = 0; i < n && apdu_count < HID_APDU_MAX_ENTRIES; i++) {
            json_t *entry = json_array_get(jresps, i);
            json_t *japdu = json_object_get(entry, "APDU");
            json_t *jresp = json_object_get(entry, "Response");
            if (!json_is_string(japdu) || !json_is_string(jresp))
                continue;
            int alen = hex_to_bytes(json_string_value(japdu),
                                    apdu_table[apdu_count].apdu, HID_APDU_MAX_CMD);
            int rlen = hex_to_bytes(json_string_value(jresp),
                                    apdu_table[apdu_count].resp, HID_APDU_MAX_RESP);
            if (alen <= 0 || rlen <= 0) {
                PrintAndLogEx(WARNING, "APDUResponses[%zu]: invalid hex, skipping", i);
                continue;
            }
            apdu_table[apdu_count].apdu_len = (uint8_t)alen;
            apdu_table[apdu_count].resp_len = (uint8_t)rlen;
            PrintAndLogEx(INFO, "APDU override [%u]: %s -> %s",
                          apdu_count, json_string_value(japdu), json_string_value(jresp));
            apdu_count++;
        }
    }

    json_decref(root);

    uint16_t flags = 0;
    FLAG_SET_UID_IN_DATA(flags, uidlen);

    char uid_str[21] = {0};
    for (int i = 0; i < uidlen; i++)
        snprintf(uid_str + i * 2, sizeof(uid_str) - i * 2, "%02X", uid[i]);

    PrintAndLogEx(INFO, "HID Config Card sim:"
                  " UID " _YELLOW_("%s")
                  " AID " _YELLOW_("%s")
                  " ATS len " _YELLOW_("%d")
                  " APDU overrides " _YELLOW_("%u"),
                  uid_str, aid_str, ats_len, apdu_count);
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");

    hid_sim_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.tagtype    = 4;        // ISO14443-4 base type; ATQA/SAK/ATS overridden by ARM
    payload.flags      = flags;
    payload.exitAfter  = exitAfterNReads;
    payload.atqa[0]    = 0x02;    // HID Config Card ATQA high byte
    payload.atqa[1]    = 0x00;    // HID Config Card ATQA low byte
    payload.sak        = 0x38;    // HID Config Card SAK
    payload.ats_len    = (uint8_t)ats_len;
    payload.apdu_count = apdu_count;
    memcpy(payload.uid, uid, uidlen);
    memcpy(payload.scp02_key, scp02_key, sizeof(scp02_key));
    memcpy(payload.ats, ats, ats_len);
    memcpy(payload.apdu_table, apdu_table, apdu_count * sizeof(hid_apdu_entry_t));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_HIDCONFIG_SIM, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp = {0};
    while (true) {
        if (WaitForResponseTimeout(CMD_HF_HIDCONFIG_SIM, &resp, 1500)) {
            if (resp.status != PM3_SUCCESS)
                break;
        }
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            break;
        }
    }
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// hf secc sniff
// ---------------------------------------------------------------------------

static int CmdHFHIDConfigSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf secc sniff",
                  "Sniff the communication between a HID Config Card reader and card.\n"
                  "Use `hf 14a list` to view collected data.",
                  "hf secc sniff\n"
                  "hf secc sniff -j     -> jam A0 D4 00 00 00, respond 00 00 90 00\n"
                  "hf secc sniff -c -r  -> trigger on card or reader data");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", "card",        "triggered by first data from card"),
        arg_lit0("r", "reader",      "triggered by first 7-bit request from reader (REQ, WUP)"),
        arg_lit0("i", "interactive", "console will not be returned until sniff finishes or is aborted"),
        arg_lit0("j", "jam",         "jam APDU A0 D4 00 00 00, respond with 00 00 90 00"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t param = 0;

    if (arg_get_lit(ctx, 1))
        param |= 0x01;

    if (arg_get_lit(ctx, 2))
        param |= 0x02;

    bool interactive = arg_get_lit(ctx, 3);
    bool jam = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (jam) {
        param |= 0x04;
        PrintAndLogEx(INFO, "Sniff with jam of APDU " _YELLOW_("A0 D4 00 00 00") " -> " _YELLOW_("00 00 90 00"));
    }

    uint16_t sniff_cmd = jam ? CMD_HF_HIDCONFIG_SNIFF : CMD_HF_ISO14443A_SNIFF;

    clearCommandBuffer();
    SendCommandNG(sniff_cmd, (uint8_t *)&param, sizeof(uint8_t));

    if (interactive) {
        PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort sniffing");

        PacketResponseNG resp;
        bool keypress = kbd_enter_pressed();
        while (keypress == false) {
            keypress = kbd_enter_pressed();
            if (WaitForResponseTimeout(sniff_cmd, &resp, 500))
                break;
        }

        if (keypress) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            WaitForResponse(sniff_cmd, &resp);
        }

        PrintAndLogEx(INFO, "Done!");
        PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 14a list") "` to view captured tracelog");
        PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("trace save -h") "` to save tracelog for later analysing");
    } else {
        PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to abort sniffing");
    }
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// Command table
// ---------------------------------------------------------------------------

static command_t CommandTable[];

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"--------", CmdHelp,                AlwaysAvailable,  "----------- " _CYAN_("HID Config Card") " -----------"},
    {"help",     CmdHelp,                AlwaysAvailable,  "This help"},
    {"sim",      CmdHFHIDConfigSim,      IfPm3Iso14443a,   "Simulate HID iCLASS SE Config Card"},
    {"sniff",    CmdHFHIDConfigSniff,    IfPm3Iso14443a,   "Sniff reader<->card, jam A0 D4 APDU"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFHIDConfig(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
