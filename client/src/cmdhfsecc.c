
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

// Must stay in sync with armsrc/secc.h. Sized so hid_sim_payload_t fits in
// PM3_CMD_DATA_SIZE (512); adjust ENTRIES carefully if any field is added.
#define HID_APDU_MAX_ENTRIES 7
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
    uint8_t  kdd[10];          // 10-byte Key Diversification Data (from JSON "KDD"); all-zero = no diversification
    uint8_t  kvn;              // Key Version Number (from JSON "KVN", default 0x01)
    uint8_t  ats[20];          // ATS bytes without CRC (from JSON "ATS")
    uint8_t  ats_len;          // actual number of valid bytes in ats[]
    uint8_t  default_resp[HID_APDU_MAX_RESP]; // fallback reply for unmatched APDUs (from JSON "DefaultResponse")
    uint8_t  default_resp_len; // 0 = none configured
    uint8_t  apdu_count;
    hid_apdu_entry_t apdu_table[HID_APDU_MAX_ENTRIES];
} PACKED hid_sim_payload_t;

// Hard guard: SendCommandNG silently drops any payload over PM3_CMD_DATA_SIZE.
_Static_assert(sizeof(hid_sim_payload_t) <= PM3_CMD_DATA_SIZE,
               "hid_sim_payload_t exceeds PM3_CMD_DATA_SIZE; shrink HID_APDU_MAX_ENTRIES or HID_APDU_MAX_RESP");

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

// ---------------------------------------------------------------------------
// hf secc cardinfo - BER-TLV / OID helpers (file-scope only)
// ---------------------------------------------------------------------------

// Find the value of the first matching single-byte-tag TLV in buf[0..len).
// Returns a pointer to the value bytes and sets *vlen, or NULL on failure.
static const uint8_t *secc_tlv_find(const uint8_t *buf, size_t len, uint8_t tag, size_t *vlen) {
    size_t i = 0;
    while (i < len) {
        uint8_t t = buf[i++];
        if (i >= len) break;
        uint8_t lb = buf[i++];
        size_t l;
        if (lb == 0x81) {
            if (i >= len) break;
            l = buf[i++];
        } else if (lb == 0x82) {
            if (i + 2 > len) break;
            l = ((size_t)buf[i] << 8) | buf[i + 1];
            i += 2;
        } else {
            l = lb;
        }
        if (i + l > len) break;
        if (t == tag) {
            *vlen = l;
            return buf + i;
        }
        i += l;
    }
    return NULL;
}

// Decode BER-encoded OID bytes into individual 32-bit arcs.
// Returns the number of arcs decoded (first two arcs are always decoded together).
static int secc_decode_oid(const uint8_t *p, size_t len, uint32_t *arcs, int max_arcs) {
    if (len == 0 || max_arcs < 2) return 0;
    arcs[0] = (uint32_t)(p[0] / 40);
    arcs[1] = (uint32_t)(p[0] % 40);
    int n = 2;
    uint32_t acc = 0;
    for (size_t i = 1; i < len; i++) {
        acc = (acc << 7) | (uint32_t)(p[i] & 0x7F);
        if (!(p[i] & 0x80)) {
            if (n < max_arcs)
                arcs[n++] = acc;
            acc = 0;
        }
    }
    return n;
}

// Find the inner tag 0x06 (OID) within ctxbuf and decode its arcs.
static int secc_get_inner_oid(const uint8_t *ctxbuf, size_t ctxlen, uint32_t *arcs, int max_arcs) {
    size_t oid_len = 0;
    const uint8_t *oid = secc_tlv_find(ctxbuf, ctxlen, 0x06, &oid_len);
    if (!oid || oid_len == 0) return 0;
    return secc_decode_oid(oid, oid_len, arcs, max_arcs);
}

// ---------------------------------------------------------------------------
// hf secc cardinfo
// ---------------------------------------------------------------------------

static int CmdHFHIDConfigCardInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf secc info",
                  "Read and decode Card Recognition Data from a GlobalPlatform card.\n"
                  "Sends GET DATA (80 CA 00 66 00) and parses the Card Recognition\n"
                  "Template (tag 73) to identify platform, SCP type, and chip family.",
                  "hf secc info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // GET DATA: tag 0x0066 = Card Data (Card Recognition Template)
    const uint8_t apdu[] = {0x80, 0xCA, 0x00, 0x66, 0x00};
    uint8_t resp[256];
    int resplen = 0;

    int res = ExchangeAPDU14a(apdu, (int)sizeof(apdu), true, false, resp, (int)sizeof(resp), &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to exchange APDU with card");
        return res;
    }
    if (resplen < 2) {
        PrintAndLogEx(ERR, "Response too short (%d byte(s))", resplen);
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resplen - 2];
    uint8_t sw2 = resp[resplen - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        PrintAndLogEx(ERR, "Card returned error SW %02X%02X", sw1, sw2);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Raw ... " _YELLOW_("%s"), sprint_hex_inrow(resp, resplen));

    // Strip SW bytes before TLV parsing
    size_t datalen = (size_t)resplen - 2;
    const uint8_t *data = resp;

    // Outer tag 0x66: Card Data
    size_t tag66_len = 0;
    const uint8_t *tag66 = secc_tlv_find(data, datalen, 0x66, &tag66_len);
    if (!tag66) {
        PrintAndLogEx(ERR, "Tag 66 (Card Data) not found in response");
        return PM3_ESOFT;
    }

    // Inner tag 0x73: Card Recognition Data
    size_t tag73_len = 0;
    const uint8_t *tag73 = secc_tlv_find(tag66, tag66_len, 0x73, &tag73_len);
    if (!tag73) {
        PrintAndLogEx(ERR, "Tag 73 (Card Recognition Data) not found");
        return PM3_ESOFT;
    }

    uint32_t arcs[16];
    int n;
    char platform[80]      = "Unknown";
    char cardspec[80]      = "Unknown";
    char scp_str[80]       = "Unknown";
    char keystr[80]        = "Unknown";
    char challenge_str[80] = "Unknown";
    char rmac_str[80]      = "Unknown";
    char chipfamily[128]   = "Unknown";

    // tag 0x60: Card Management Type and Version
    // OID 1.2.840.114283.2.X.Y.Z -> GlobalPlatform X.Y.Z
    size_t t60_len = 0;
    const uint8_t *t60 = secc_tlv_find(tag73, tag73_len, 0x60, &t60_len);
    if (t60) {
        n = secc_get_inner_oid(t60, t60_len, arcs, 16);
        if (n >= 7 && arcs[0] == 1 && arcs[1] == 2 && arcs[2] == 840 &&
                arcs[3] == 114283 && arcs[4] == 2) {
            if (n >= 8)
                snprintf(cardspec, sizeof(cardspec), "GlobalPlatform %u.%u.%u.%u",
                         arcs[4], arcs[5], arcs[6], arcs[7]);
            else
                snprintf(cardspec, sizeof(cardspec), "GlobalPlatform %u.%u.%u",
                         arcs[4], arcs[5], arcs[6]);
        }
    }

    // tag 0x64: Secure Channel Protocol
    // OID 1.2.840.114283.4.SCP.i -> SCPxx, i=0xii
    // SCP02 i-parameter bits (GP Card Spec):
    //   bit 0 (0x01): 1 = 3 Secure Channel Keys, 0 = 1 key
    //   bit 4 (0x10): 1 = pseudo-random card challenge, 0 = sequential counter
    //   bit 6 (0x40): 1 = R-MAC supported, 0 = not supported
    size_t t64_len = 0;
    const uint8_t *t64 = secc_tlv_find(tag73, tag73_len, 0x64, &t64_len);
    if (t64) {
        n = secc_get_inner_oid(t64, t64_len, arcs, 16);
        if (n >= 7 && arcs[0] == 1 && arcs[1] == 2 && arcs[2] == 840 &&
                arcs[3] == 114283 && arcs[4] == 4) {
            uint32_t scp_type = arcs[5];
            uint32_t i_param  = arcs[6];
            snprintf(scp_str, sizeof(scp_str), "SCP%02u, i=0x%02X", scp_type, i_param);
            snprintf(keystr, sizeof(keystr), "%s",
                     (i_param & 0x01) ? "3 independent session keys" : "1 shared key");
            snprintf(challenge_str, sizeof(challenge_str), "%s",
                     (i_param & 0x10) ? "Pseudo-random (RNG)" : "Sequential counter");
            snprintf(rmac_str, sizeof(rmac_str), "%s",
                     (i_param & 0x40) ? "Supported but optional" : "Not supported");
        }
    }

    // tag 0x65: Card Configuration Details
    // OID 1.3.656.x.x -> NXP JCOP (proprietary arc under ISO identified-org)
    size_t t65_len = 0;
    const uint8_t *t65 = secc_tlv_find(tag73, tag73_len, 0x65, &t65_len);
    if (t65) {
        n = secc_get_inner_oid(t65, t65_len, arcs, 16);
        if (n >= 3 && arcs[0] == 1 && arcs[1] == 3 && arcs[2] == 656)
            snprintf(chipfamily, sizeof(chipfamily),
                     "NXP JCOP (tag 65 OID points to NXP/G+D tree)");
        else if (n >= 2)
            snprintf(chipfamily, sizeof(chipfamily), "Unknown (OID %u.%u...)",
                     arcs[0], arcs[1]);
    }

    // tag 0x66 (inner): Card/Chip Details
    // OID 1.3.6.1.4.1.42.2.110.1.X -> Java Card Classic 2.X (Sun/Oracle OID space)
    size_t t66i_len = 0;
    const uint8_t *t66i = secc_tlv_find(tag73, tag73_len, 0x66, &t66i_len);
    if (t66i) {
        n = secc_get_inner_oid(t66i, t66i_len, arcs, 16);
        if (n >= 11 && arcs[0] == 1  && arcs[1] == 3   && arcs[2] == 6 &&
                arcs[3] == 1  && arcs[4] == 4   && arcs[5] == 1 &&
                arcs[6] == 42 && arcs[7] == 2   && arcs[8] == 110 && arcs[9] == 1) {
            snprintf(platform, sizeof(platform), "Java Card Classic 2.%u", arcs[10]);
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card Recognition Data") " ---");
    PrintAndLogEx(INFO, "  %-20s  %s", "Property", "Value");
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Platform",       platform);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Card Spec",      cardspec);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Secure Channel", scp_str);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Key structure",  keystr);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Card challenge", challenge_str);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "R-MAC",          rmac_str);
    PrintAndLogEx(INFO, "  %-20s  " _YELLOW_("%s"), "Chip family",    chipfamily);
    PrintAndLogEx(NORMAL, "");

    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

// ---------------------------------------------------------------------------
// hf secc sim
// ---------------------------------------------------------------------------

static int CmdHFHIDConfigSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf secc sim",
                  "Simulate a HID iCLASS SE Config Card (JCOP / GlobalPlatform SCP02).\n"
                  "APDUs are matched against the JSON APDUResponses table; INITIALIZE UPDATE\n"
                  "and EXTERNAL AUTH are handled by the built-in SCP02 crypto. Anything else\n"
                  "falls through to the JSON DefaultResponse (or 9000 if none is set).",
                  "hf secc sim -f hidconfig_sample\n"
                  "hf secc sim -f hidconfig_sample -n 5    -> stop after 5 reader interactions");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "JSON file with UID, AID, SCP02Key, optional KDD/KVN (no .json ext)"),
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

    // Parse optional KDD (10 bytes). If present, ARM diversifies SCP02Key
    // per-card via VISA-2 on each handshake. If absent, all-zero is sent and
    // ARM uses SCP02Key directly (legacy "no diversification" mode).
    uint8_t kdd[10] = {0};
    if (json_object_get(root, "KDD") != NULL) {
        size_t kdd_len = 0;
        if (JsonLoadBufAsHex(root, "$.KDD", kdd, sizeof(kdd), &kdd_len) != 0 || kdd_len != 10) {
            PrintAndLogEx(ERR, "JSON 'KDD' field invalid (must be 10 bytes)");
            json_decref(root);
            return PM3_EINVARG;
        }
    }

    // Parse optional KVN (Key Version Number, 1 byte). Default 0x01 matches
    // the GP factory key set on most JCOP-based config cards.
    uint8_t kvn = 0x01;
    if (json_object_get(root, "KVN") != NULL) {
        uint8_t kvn_buf[1] = {0};
        size_t kvn_len = 0;
        if (JsonLoadBufAsHex(root, "$.KVN", kvn_buf, sizeof(kvn_buf), &kvn_len) != 0 || kvn_len != 1) {
            PrintAndLogEx(ERR, "JSON 'KVN' field invalid (must be 1 byte)");
            json_decref(root);
            return PM3_EINVARG;
        }
        kvn = kvn_buf[0];
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

    // Parse optional DefaultResponse: fallback reply for any APDU not matched
    // by the APDUResponses table or by hardcoded handlers. If absent, the
    // simulator will fall back to the legacy "90 00" reply.
    uint8_t default_resp[HID_APDU_MAX_RESP] = {0};
    size_t default_resp_len_sz = 0;
    bool has_default_resp = false;
    if (json_object_get(root, "DefaultResponse") != NULL) {
        if (JsonLoadBufAsHex(root, "$.DefaultResponse", default_resp,
                             sizeof(default_resp), &default_resp_len_sz) != 0
                || default_resp_len_sz == 0) {
            PrintAndLogEx(ERR, "JSON 'DefaultResponse' field invalid (must be 1-%d hex bytes)",
                          HID_APDU_MAX_RESP);
            json_decref(root);
            return PM3_EINVARG;
        }
        has_default_resp = true;
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

    // sprint_hex_inrow uses a single static buffer; snapshot the UID string
    // before calling it again for the default response.
    char uid_str[2 * sizeof(uid) + 1];
    strncpy(uid_str, sprint_hex_inrow(uid, uidlen), sizeof(uid_str) - 1);
    uid_str[sizeof(uid_str) - 1] = '\0';
    PrintAndLogEx(INFO, "HID Config Card sim:"
                  " UID " _YELLOW_("%s")
                  " AID " _YELLOW_("%s")
                  " ATS len " _YELLOW_("%d")
                  " APDU overrides " _YELLOW_("%u")
                  " default resp " _YELLOW_("%s"),
                  uid_str, aid_str, ats_len, apdu_count,
                  has_default_resp ? sprint_hex_inrow(default_resp, default_resp_len_sz) : "9000 (builtin)");
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
    payload.kvn        = kvn;
    payload.default_resp_len = has_default_resp ? (uint8_t)default_resp_len_sz : 0;
    payload.apdu_count = apdu_count;
    memcpy(payload.uid, uid, uidlen);
    memcpy(payload.scp02_key, scp02_key, sizeof(scp02_key));
    memcpy(payload.kdd, kdd, sizeof(kdd));
    memcpy(payload.ats, ats, ats_len);
    if (has_default_resp)
        memcpy(payload.default_resp, default_resp, default_resp_len_sz);
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
    {"--------",  CmdHelp,                  AlwaysAvailable,  "----------- " _CYAN_("HID Config Card") " -----------"},
    {"help",      CmdHelp,                  AlwaysAvailable,  "This help"},
    {"info",      CmdHFHIDConfigCardInfo,   IfPm3Iso14443a,   "Read and decode Card Recognition Data (GP tag 0066)"},
    {"sim",       CmdHFHIDConfigSim,        IfPm3Iso14443a,   "Simulate HID iCLASS SE Config Card"},
    {"sniff",     CmdHFHIDConfigSniff,      IfPm3Iso14443a,   "Sniff reader<->card, jam A0 D4 APDU"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFHIDConfig(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
