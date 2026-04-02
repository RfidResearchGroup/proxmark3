
#include "cmdhfsecc.h"

#include <string.h>
#include "cmdparser.h"          // command_t
#include "cliparser.h"          // CLIParser*
#include "comms.h"              // SendCommandNG, WaitForResponseTimeout, clearCommandBuffer
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // kbd_enter_pressed, hex_to_bytes, sprint_hex_inrow
#include "cmdhf14a.h"           // IfPm3Iso14443a
#include "pm3_cmd.h"            // CMD_HF_ISO14443A_SIMULATE, CMD_HF_ISO14443A_SNIFF, CMD_BREAK_LOOP, FLAG_SET_UID_IN_DATA
#include "jansson.h"            // json_object_get, json_is_array, json_string_value, json_decref
#include "fileutils.h"          // loadFileJSONroot, JsonLoadBufAsHex

// ---------------------------------------------------------------------------
// Payload structs shared with armsrc/secc.h
// Must stay in sync with hid_apdu_entry_t / hid_sim_payload_t.
// ---------------------------------------------------------------------------

#define HID_APDU_MAX_ENTRIES 8
#define HID_APDU_MAX_CMD     20
#define HID_APDU_MAX_RESP    32
#define HID_APDU_MASK_LEN    3    // ceil(HID_APDU_MAX_CMD / 8)

typedef struct {
    uint8_t apdu[HID_APDU_MAX_CMD];
    uint8_t apdu_len;
    uint8_t apdu_mask[HID_APDU_MASK_LEN];
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

// Must stay in sync with hid_sniff_payload_t in armsrc/secc.h.
#define HID_JAM_MAX_APDU  32
#define HID_JAM_MAX_RESP  32

typedef struct {
    uint8_t param;
    uint8_t apdu[HID_JAM_MAX_APDU];    // APDU to jam (0-length = default A0 D4 00 00 00)
    uint8_t apdu_len;
    uint8_t resp[HID_JAM_MAX_RESP];    // jam response payload (0-length = default 00 00 90 00)
    uint8_t resp_len;
} PACKED hid_sniff_payload_t;

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
    json_t *root = NULL;
    if (loadFileJSONroot(filename, (void **)&root, false) != PM3_SUCCESS)
        return PM3_EFILE;

    // Parse UID
    uint8_t uid[10] = {0};
    size_t uidlen_sz = 0;
    if (JsonLoadBufAsHex(root, "$.UID", uid, sizeof(uid), &uidlen_sz) != 0) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'UID' field");
        json_decref(root);
        return PM3_EINVARG;
    }
    int uidlen = (int)uidlen_sz;
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
    size_t scp02_len = 0;
    if (JsonLoadBufAsHex(root, "$.SCP02Key", scp02_key, sizeof(scp02_key), &scp02_len) != 0 || scp02_len != 16) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'SCP02Key' field (must be 16 bytes)");
        json_decref(root);
        return PM3_EINVARG;
    }

    // Parse ATS (1-20 bytes, without CRC)
    uint8_t ats[20] = {0};
    size_t ats_len_sz = 0;
    if (JsonLoadBufAsHex(root, "$.ATS", ats, sizeof(ats), &ats_len_sz) != 0 || ats_len_sz == 0) {
        PrintAndLogEx(ERR, "JSON missing or invalid 'ATS' field (must be 1-20 bytes)");
        json_decref(root);
        return PM3_EINVARG;
    }
    int ats_len = (int)ats_len_sz;

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

            // Parse APDU hex string with optional "**" wildcard bytes.
            // mask bit i=1 → exact match; bit i=0 → wildcard.
            const char *apdu_str = json_string_value(japdu);
            int alen = 0;
            bool apdu_ok = true;
            memset(apdu_table[apdu_count].apdu_mask, 0xFF, HID_APDU_MASK_LEN);
            while (*apdu_str && alen < HID_APDU_MAX_CMD) {
                char hi = apdu_str[0];
                char lo = apdu_str[1];
                if (lo == '\0') { apdu_ok = false; break; }
                apdu_str += 2;
                if (hi == '*' && lo == '*') {
                    apdu_table[apdu_count].apdu[alen] = 0x00;  // ** wildcard
                    apdu_table[apdu_count].apdu_mask[alen / 8] &= ~(1u << (alen % 8));
                } else if (hi == '#' && lo == '#') {
                    apdu_table[apdu_count].apdu[alen] = 0x01;  // ## length-prefix skip
                    apdu_table[apdu_count].apdu_mask[alen / 8] &= ~(1u << (alen % 8));
                } else {
                    uint8_t val = 0;
                    for (int nb = 0; nb < 2; nb++) {
                        char c = (nb == 0) ? hi : lo;
                        uint8_t nib;
                        if (c >= '0' && c <= '9')      nib = c - '0';
                        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
                        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
                        else { apdu_ok = false; break; }
                        val = (val << 4) | nib;
                    }
                    if (!apdu_ok) break;
                    apdu_table[apdu_count].apdu[alen] = val;
                }
                alen++;
            }

            int rlen = hex_to_bytes(json_string_value(jresp),
                                    apdu_table[apdu_count].resp, HID_APDU_MAX_RESP);
            if (!apdu_ok || alen <= 0 || rlen <= 0) {
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

    PrintAndLogEx(INFO, "HID Config Card sim:"
                  " UID " _YELLOW_("%s")
                  " AID " _YELLOW_("%s")
                  " ATS len " _YELLOW_("%d")
                  " APDU overrides " _YELLOW_("%u"),
                  sprint_hex_inrow(uid, uidlen), aid_str, ats_len, apdu_count);
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
    bool keypress = kbd_enter_pressed();
    while (keypress == false) {
        keypress = kbd_enter_pressed();
        // Any response means the device finished (button press or exitAfter reached).
        if (WaitForResponseTimeout(CMD_HF_HIDCONFIG_SIM, &resp, 1500))
            break;
    }
    if (keypress) {
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        WaitForResponse(CMD_HF_HIDCONFIG_SIM, &resp);
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
                  "Use `hf seos list` to view collected data.\n"
                  "With -j and no -d, jams responses to APDU A0 D4 00 00 00.\n"
                  "With -j -d <hex> jams responses to the specified APDU.\n"
                  "Use -r <hex> to override the jam response payload (default: 00009000).",
                  "hf secc sniff\n"
                  "hf secc sniff -j                        -> jam A0 D4 00 00 00, respond 00 00 90 00\n"
                  "hf secc sniff -j -d A0D4000000          -> same, APDU specified explicitly\n"
                  "hf secc sniff -j -d A0D4000000 -r 9000  -> jam A0D4000000, respond 90 00\n"
                  "hf secc sniff -c -i                      -> trigger on card data, interactive");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", "card",        "triggered by first data from card"),
        arg_lit0("r", "reader",      "triggered by first 7-bit request from reader (REQ, WUP)"),
        arg_lit0("i", "interactive", "console will not be returned until sniff finishes or is aborted"),
        arg_lit0("j", "jam",         "jam responses to a specific APDU (see -d/-a)"),
        arg_str0("d", "apdu",  "<hex>", "APDU bytes to jam (default: A0D4000000)"),
        arg_str0("a", "resp",  "<hex>", "response payload when jamming (default: 00009000)"),
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

    uint8_t apdu_buf[HID_JAM_MAX_APDU] = {0};
    int apdu_buf_len = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 5), apdu_buf, sizeof(apdu_buf), &apdu_buf_len)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t resp_buf[HID_JAM_MAX_RESP] = {0};
    int resp_buf_len = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 6), resp_buf, sizeof(resp_buf), &resp_buf_len)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool has_apdu = (apdu_buf_len > 0);
    bool has_resp = (resp_buf_len > 0);

    CLIParserFree(ctx);

    // -d and -r only make sense with -j
    if ((has_apdu || has_resp) && !jam) {
        PrintAndLogEx(ERR, "-d and -r require -j (jam mode)");
        return PM3_EINVARG;
    }

    if (jam) {
        param |= 0x04;
        // sprint_hex_inrow uses a single static buffer; copy the APDU string before
        // calling it again for the response.
        char apdu_str[HID_JAM_MAX_APDU * 2 + 1];
        strncpy(apdu_str,
                has_apdu ? sprint_hex_inrow(apdu_buf, apdu_buf_len) : "A0D4000000",
                sizeof(apdu_str) - 1);
        apdu_str[sizeof(apdu_str) - 1] = '\0';
        PrintAndLogEx(INFO, "Sniff with jam of APDU " _YELLOW_("%s") " -> " _YELLOW_("%s"),
                      apdu_str,
                      has_resp ? sprint_hex_inrow(resp_buf, resp_buf_len) : "00009000");
    }

    uint16_t sniff_cmd = jam ? CMD_HF_HIDCONFIG_SNIFF : CMD_HF_ISO14443A_SNIFF;

    if (jam) {
        hid_sniff_payload_t payload;
        memset(&payload, 0, sizeof(payload));
        payload.param = param;
        if (has_apdu) {
            memcpy(payload.apdu, apdu_buf, apdu_buf_len);
            payload.apdu_len = (uint8_t)apdu_buf_len;
        }
        if (has_resp) {
            memcpy(payload.resp, resp_buf, resp_buf_len);
            payload.resp_len = (uint8_t)resp_buf_len;
        }
        clearCommandBuffer();
        SendCommandNG(sniff_cmd, (uint8_t *)&payload, sizeof(payload));
    } else {
        clearCommandBuffer();
        SendCommandNG(sniff_cmd, (uint8_t *)&param, sizeof(uint8_t));
    }

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
        PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf seos list") "` to view captured tracelog");
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
