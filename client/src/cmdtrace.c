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
// Trace commands
//-----------------------------------------------------------------------------
#include "cmdtrace.h"

#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "commonutil.h"         // ARRAYLEN
#include "mifare/mifaredefault.h"          // mifare default key array
#include "comms.h"              // for sending cmds to device. GetFromBigBuf
#include "fileutils.h"          // for saveFile
#include "cmdlfhitag.h"         // annotate hitag
#include "pm3_cmd.h"            // tracelog_hdr_t
#include "cliparser.h"          // args..

static int CmdHelp(const char *Cmd);

// trace pointer
static uint8_t *gs_trace;
static uint16_t gs_traceLen = 0;

static bool is_last_record(uint16_t tracepos, uint16_t traceLen) {
    return ((tracepos + TRACELOG_HDR_LEN) >= traceLen);
}

static bool next_record_is_response(uint16_t tracepos, uint8_t *trace) {
    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + tracepos);
    return (hdr->isResponse);
}

static bool merge_topaz_reader_frames(uint32_t timestamp, uint32_t *duration, uint16_t *tracepos, uint16_t traceLen,
                                      uint8_t *trace, uint8_t *frame, uint8_t *topaz_reader_command, uint16_t *data_len) {

#define MAX_TOPAZ_READER_CMD_LEN 16

    uint32_t last_timestamp = timestamp + *duration;

    if ((*data_len != 1) || (frame[0] == TOPAZ_WUPA) || (frame[0] == TOPAZ_REQA)) return false;

    memcpy(topaz_reader_command, frame, *data_len);

    while (!is_last_record(*tracepos, traceLen) && !next_record_is_response(*tracepos, trace)) {

        tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + *tracepos);

        *tracepos += TRACELOG_HDR_LEN + hdr->data_len;

        if ((hdr->data_len == 1) && (*data_len + hdr->data_len <= MAX_TOPAZ_READER_CMD_LEN)) {
            memcpy(topaz_reader_command + *data_len, hdr->frame, hdr->data_len);
            *data_len += hdr->data_len;
            last_timestamp = hdr->timestamp + hdr->duration;
        } else {
            // rewind and exit
            *tracepos = *tracepos - hdr->data_len - TRACELOG_HDR_LEN;
            break;
        }
        *tracepos += TRACELOG_PARITY_LEN(hdr);
    }

    *duration = last_timestamp - timestamp;

    return true;
}
static uint8_t calc_pos(const uint8_t *d) {
    // PCB [CID] [NAD] [INF] CRC CRC
    uint8_t pos = 1;
    if ((d[0] & 0x08) == 0x08)  // cid byte following
        pos++;

    if ((d[0] & 0x04) == 0x04)  // nad byte following
        pos++;

    return pos;
}

static uint8_t extract_uid[10] = {0};
static uint8_t extract_uidlen = 0;
static uint8_t extract_epurse[8] = {0};

#define SKIP_TO_NEXT(a)  (TRACELOG_HDR_LEN + (a)->data_len + TRACELOG_PARITY_LEN((a)))

static uint16_t extractChall_ev2(uint16_t tracepos, uint8_t *trace, uint8_t cmdpos, uint8_t long_jmp) {
    tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
    if (next_hdr->data_len != 21) {
        return 0;
    }

    tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

    PrintAndLogEx(INFO, "1499999999 %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, 16));

    next_hdr = (tracelog_hdr_t *)(trace + tracepos);
    tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

    if (next_hdr->frame[cmdpos] == MFDES_ADDITIONAL_FRAME) {
        PrintAndLogEx(NORMAL, "%s", sprint_hex_inrow(next_hdr->frame + cmdpos + long_jmp, 32));
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return tracepos;
}

static uint16_t extractChallenges(uint16_t tracepos, uint16_t traceLen, uint8_t *trace) {

    // sanity check
    if (is_last_record(tracepos, traceLen)) {
        return traceLen;
    }

    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + tracepos);
    uint16_t data_len = hdr->data_len;
    uint8_t *frame = hdr->frame;

    // sanity check tracking position is less then available trace size
    if (tracepos + TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr) > traceLen) {
        PrintAndLogEx(DEBUG, "trace pos offset %"PRIu64 " larger than reported tracelen %u",
                      tracepos + TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr),
                      traceLen
                     );
        return traceLen;
    }

    // set trace position
    tracepos += SKIP_TO_NEXT(hdr);

    // sanity check data frame length
    if (data_len == 0) {
        return tracepos;
    }

    // extract MFC
    switch (frame[0]) {
        case MIFARE_AUTH_KEYA: {
            if (data_len > 3) {
            }
            break;
        }
        case MIFARE_AUTH_KEYB: {
            if (data_len > 3) {
            }
            break;
        }
    }

    // extract MFU-C
    switch (frame[0]) {
        case MIFARE_ULC_AUTH_1: {
            if (data_len != 4) {
                break;
            }

            // time to skip to next
            tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
            tracepos += SKIP_TO_NEXT(next_hdr);
            if (next_hdr->data_len != 11) {
                break;
            }

            if (next_hdr->frame[0] != MIFARE_ULC_AUTH_2) {
                break;
            }

            PrintAndLogEx(INFO, "MFU-C AUTH");
            PrintAndLogEx(INFO, "3DES %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, 8));

            next_hdr = (tracelog_hdr_t *)(trace + tracepos);
            tracepos += SKIP_TO_NEXT(next_hdr);

            if (next_hdr->frame[0] == MIFARE_ULC_AUTH_2 && next_hdr->data_len == 19) {
                PrintAndLogEx(NORMAL, "%s", sprint_hex_inrow(next_hdr->frame + 1, 16));
            }

            return tracepos;
        }
    }

    // extract iCLASS
    // --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b

    if (hdr->isResponse == false)  {

        uint8_t c = frame[0] & 0x0F;
        switch (c) {
            case ICLASS_CMD_SELECT: {

                tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += SKIP_TO_NEXT(next_hdr);
                if (next_hdr->data_len != 10) {
                    break;
                }
                memcpy(extract_uid, next_hdr->frame, 8);
                extract_uidlen = 8;
                break;
            }
            case ICLASS_CMD_READCHECK: {

                // get epurse
                if (frame[1] == 2 && data_len == 2) {
                    tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                    tracepos += SKIP_TO_NEXT(next_hdr);
                    if (next_hdr->data_len < 8) {
                        break;
                    }
                    memcpy(extract_epurse, next_hdr->frame, 8);
                }
                break;
            }
            case ICLASS_CMD_CHECK: {
                // get macs
                if (data_len == 9) {
                    if (extract_uidlen == 8) {
                        PrintAndLogEx(INFO, "hf iclass lookup --csn %s " NOLF, sprint_hex_inrow(extract_uid, extract_uidlen));
                        PrintAndLogEx(NORMAL, "--epurse %s " NOLF, sprint_hex_inrow(extract_epurse, 8));
                        PrintAndLogEx(NORMAL, "--macs %s " NOLF, sprint_hex_inrow(frame + 1, 8));
                        PrintAndLogEx(NORMAL, "-f iclass_default_keys.dic");
                        return tracepos;
                    }
                }
                break;
            }
        }
    }

    // extract UID
    switch (frame[0]) {
        case ISO14443A_CMD_ANTICOLL_OR_SELECT: {
            // 93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
            // 93 50 = Bit oriented anti-collision (usage: 9350+ up to 5bytes, 9350 answer - up to 5bytes UID+BCC)
            // 93 70 = Select (usage: 9370+5bytes 9370 answer - answer: 1byte SAK)
            if (frame[1] == 0x70) {
                if (frame[2] == 0x88) {
                    memcpy(extract_uid, frame + 3, 3);
                    extract_uidlen = 3;
                } else {
                    memcpy(extract_uid, frame + 2, 4);
                    extract_uidlen = 4;
                    PrintAndLogEx(INFO, "UID... " _YELLOW_("%s"), sprint_hex_inrow(extract_uid, extract_uidlen));
                }
            }
            break;
        }
        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2: {
            // 95 20 = Anticollision of cascade level2
            // 95 50 = Bit oriented anti-collision level2
            // 95 70 = Select of cascade level2
            if (frame[1] == 0x70) {
                if (frame[2] == 0x88) {
                    memcpy(extract_uid + extract_uidlen, frame + 3, 3);
                    extract_uidlen += 3;
                } else {
                    memcpy(extract_uid + extract_uidlen, frame + 2, 4);
                    extract_uidlen += 4;
                    PrintAndLogEx(INFO, "UID... " _YELLOW_("%s"), sprint_hex_inrow(extract_uid, extract_uidlen));
                }
            }
            break;
        }
        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3: {
            // 97 20 = Anticollision of cascade level3
            // 97 50 = Bit oriented anti-collision level3
            // 97 70 = Select of cascade level3
            if (frame[1] == 0x70) {
                memcpy(extract_uid + extract_uidlen, frame + 2, 4);
                extract_uidlen += 4;
                PrintAndLogEx(INFO, "UID... " _YELLOW_("%s"), sprint_hex_inrow(extract_uid, extract_uidlen));
            }
            break;
        }
    }

    // extract DESFIRE
    if ((frame[0] & 0xC0) != 0x00) {
        return tracepos;
    }

    if (hdr->isResponse) {
        return tracepos;
    }

    // PCB [CID] [NAD] [INF] CRC CRC
    uint8_t pos = calc_pos(frame);
    uint8_t long_jmp = (data_len > 6) ? 4 : 1;

    for (uint8_t i = 0; i < 2; i++, pos++) {

        switch (frame[pos]) {

            case MFDES_AUTHENTICATE: {

                // Assume wrapped or unwrapped
                PrintAndLogEx(INFO, "AUTH NATIVE (keyNo %d)", frame[pos + long_jmp]);
                if (next_record_is_response(tracepos, trace) == false) {
                    break;
                }

                tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                if (next_hdr->data_len < 7) {
                    break;
                }
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

                PrintAndLogEx(INFO, "DES 1499999999 %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, 8));

                next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

                if (next_hdr->frame[pos] == MFDES_ADDITIONAL_FRAME) {
                    PrintAndLogEx(NORMAL, "%s", sprint_hex_inrow(next_hdr->frame + pos + long_jmp, 16));
                } else {
                    PrintAndLogEx(NORMAL, "");
                }
                return tracepos;   // AUTHENTICATE_NATIVE
            }
            case MFDES_AUTHENTICATE_ISO: {
                // Assume wrapped or unwrapped
                PrintAndLogEx(INFO, "AUTH ISO (keyNo %d)", frame[pos + long_jmp]);
                if (next_record_is_response(tracepos, trace) == false) {
                    break;
                }

                tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);
                if (next_hdr->data_len < 7) {
                    break;
                }

                uint8_t tdea = 8;
                if (next_hdr->data_len > 20) {
                    tdea = 16;
                    PrintAndLogEx(INFO, "3TDEA 1499999999 %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, tdea));
                } else {
                    PrintAndLogEx(INFO, "2TDEA 1499999999 %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, tdea));
                }

                next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

                if (next_hdr->frame[pos] == MFDES_ADDITIONAL_FRAME) {
                    PrintAndLogEx(NORMAL, "%s", sprint_hex_inrow(next_hdr->frame + pos + long_jmp, (tdea << 1)));
                } else {
                    PrintAndLogEx(NORMAL, "");
                }
                return tracepos;  // AUTHENTICATE_STANDARD
            }
            case MFDES_AUTHENTICATE_AES: {
                // Assume wrapped or unwrapped
                PrintAndLogEx(INFO, "AUTH AES (keyNo %d)", frame[pos + long_jmp]);
                if (next_record_is_response(tracepos, trace)) {
                    break;
                }

                tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);
                if (next_hdr->data_len < 7) {
                    break;
                }

                PrintAndLogEx(INFO, "AES 1499999999 %s " NOLF, sprint_hex_inrow(next_hdr->frame + 1, 8));

                next_hdr = (tracelog_hdr_t *)(trace + tracepos);
                tracepos += TRACELOG_HDR_LEN + next_hdr->data_len + TRACELOG_PARITY_LEN(next_hdr);

                if (next_hdr->frame[pos] == MFDES_ADDITIONAL_FRAME) {
                    PrintAndLogEx(NORMAL, "%s", sprint_hex_inrow(next_hdr->frame + pos + long_jmp, 16));
                } else {
                    PrintAndLogEx(NORMAL, "");
                }
                return tracepos;
            }
            case MFDES_AUTHENTICATE_EV2F: {
                PrintAndLogEx(INFO, "AUTH EV2 First");
                uint16_t tmp = extractChall_ev2(tracepos, trace, pos, long_jmp);
                if (tmp == 0)
                    break;
                else
                    return tmp;

            }
            case MFDES_AUTHENTICATE_EV2NF: {
                PrintAndLogEx(INFO, "AUTH EV2 Non First");
                uint16_t tmp = extractChall_ev2(tracepos, trace, pos, long_jmp);
                if (tmp == 0)
                    break;
                else
                    return tmp;
            }
        }
    }

    return tracepos;
}

static uint16_t printHexLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol) {
    // sanity check
    if (is_last_record(tracepos, traceLen)) return traceLen;

    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + tracepos);

    if (TRACELOG_HDR_LEN + hdr->data_len + TRACELOG_PARITY_LEN(hdr) > traceLen) {
        return traceLen;
    }

    //set trace position
    tracepos += TRACELOG_HDR_LEN + hdr->data_len + TRACELOG_PARITY_LEN(hdr);

    if (hdr->data_len == 0) {
        PrintAndLogEx(NORMAL, "<empty trace - possible error>");
        return tracepos;
    }

    uint16_t ret;

    switch (protocol) {
        case ISO_14443A: {
            /* https://www.kaiser.cx/pcap-iso14443.html defines a pseudo header:
             * version (currently 0x00), event (Rdr: 0xfe, Tag: 0xff), length (2 bytes)
             * to convert to pcap(ng) via text2pcap or to import into Wireshark
             * we use format timestamp, newline, offset (0x000000), pseudo header, data
             * `text2pcap -t "%S." -l 264 -n <input-text-file> <output-pcapng-file>`
             */
            int line_len = (hdr->data_len * 3) + 1;
            char line[line_len];
            char *ptr = line;

            for (int i = 0; i < hdr->data_len ; i++) {
                ptr += snprintf(ptr, line_len, "%02x ", hdr->frame[i]);
                line_len -= 3;
                if (line_len <= 0) {
                    break;
                }
            }

            char data_len_str[5];
            char temp_str1[3] = {0};
            char temp_str2[3] = {0};

            snprintf(data_len_str, sizeof(data_len_str), "%04x", hdr->data_len);
            memmove(temp_str1, data_len_str, 2);
            memmove(temp_str2, data_len_str + 2, 2);

            PrintAndLogEx(NORMAL, "0.%010u", hdr->timestamp);
            PrintAndLogEx(NORMAL, "000000 00 %s %s %s %s",
                          (hdr->isResponse ? "ff" : "fe"),
                          temp_str1,
                          temp_str2,
                          line);
            ret = tracepos;
            break;
        }
        default:
            PrintAndLogEx(NORMAL, "Currently only 14a supported");
            ret = traceLen;
            break;
    }

    return ret;
}

static uint16_t printTraceLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol, bool showWaitCycles, bool markCRCBytes, uint32_t *prev_eot, bool use_us,
                               const uint64_t *mfDicKeys, uint32_t mfDicKeysCount) {
    // sanity check
    if (is_last_record(tracepos, traceLen)) {
        PrintAndLogEx(DEBUG, "last record triggered.  t-pos: %u  t-len %u", tracepos, traceLen);
        return traceLen;
    }

    uint32_t end_of_transmission_timestamp = 0;
    uint8_t topaz_reader_command[9];
    char explanation[40] = {0};
    tracelog_hdr_t *first_hdr = (tracelog_hdr_t *)(trace);
    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + tracepos);

    uint32_t duration = hdr->duration;
    uint16_t data_len = hdr->data_len;

    if (tracepos + TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr) > traceLen) {
        PrintAndLogEx(DEBUG, "trace pos offset %"PRIu64 " larger than reported tracelen %u",
                      tracepos + TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr),
                      traceLen
                     );
        return traceLen;
    }

    // adjust for different time scales
    if (protocol == ICLASS || protocol == ISO_15693) {
        duration *= 32;
    }

    uint8_t *frame = hdr->frame;
    uint8_t *parityBytes = hdr->frame + data_len;

    tracepos += TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr);

    if (protocol == TOPAZ && !hdr->isResponse) {
        // topaz reader commands come in 1 or 9 separate frames with 7 or 8 Bits each.
        // merge them:
        if (merge_topaz_reader_frames(hdr->timestamp, &duration, &tracepos, traceLen, trace, frame, topaz_reader_command, &data_len)) {
            frame = topaz_reader_command;
        }
    }

    //Check the CRC status
    uint8_t crcStatus = 2;

    if (data_len > 2) {
        switch (protocol) {
            case ICLASS:
                crcStatus = iclass_CRC_check(hdr->isResponse, frame, data_len);
                break;
            case ISO_14443B:
            case TOPAZ:
                crcStatus = iso14443B_CRC_check(frame, data_len);
                break;
            case FELICA:
                crcStatus = !felica_CRC_check(frame + 2, data_len - 4);
                break;
            case PROTO_MIFARE:
            case PROTO_MFPLUS:
                crcStatus = mifare_CRC_check(hdr->isResponse, frame, data_len);
                break;
            case ISO_14443A:
            case MFDES:
            case LTO:
            case SEOS:
                crcStatus = iso14443A_CRC_check(hdr->isResponse, frame, data_len);
                break;
            case ISO_7816_4:
                crcStatus = iso14443A_CRC_check(hdr->isResponse, frame, data_len) == 1 ? 3 : 0;
                crcStatus = iso14443B_CRC_check(frame, data_len) == 1 ? 4 : crcStatus;
                break;
            case THINFILM:
                frame[data_len - 1] ^= frame[data_len - 2];
                frame[data_len - 2] ^= frame[data_len - 1];
                frame[data_len - 1] ^= frame[data_len - 2];
                crcStatus = iso14443A_CRC_check(true, frame, data_len);
                frame[data_len - 1] ^= frame[data_len - 2];
                frame[data_len - 2] ^= frame[data_len - 1];
                frame[data_len - 1] ^= frame[data_len - 2];
                break;
            case ISO_15693:
                crcStatus = iso15693_CRC_check(frame, data_len);
                break;
            case PROTO_HITAG1:
            case PROTO_HITAGS:
                crcStatus = hitag1_CRC_check(frame, (data_len * 8) - ((8 - parityBytes[0]) % 8));
            case PROTO_CRYPTORF:
            case PROTO_HITAG2:
            default:
                break;
        }
    }
    //0 CRC-command, CRC not ok
    //1 CRC-command, CRC ok
    //2 Not crc-command

    // Draw the data column
#define TRACE_MAX_LINES      36
    // number of hex bytes to be printed per row  (16 data + 2 crc)
#define TRACE_MAX_HEX_BYTES  18

    char line[TRACE_MAX_LINES][160] = {{0}};

    if (data_len == 0) {
        if (protocol == ICLASS && duration == 2048) {
            snprintf(line[0], sizeof(line[0]), "<SOF>");
        } else if (protocol == ISO_15693 && duration == 512) {
            snprintf(line[0], sizeof(line[0]), "<EOF>");
        } else {
            snprintf(line[0], sizeof(line[0]), "<empty trace - possible error>");
        }
    }

    uint8_t partialbytebuff = 0;
    uint8_t offset = 0;
    for (int j = 0; j < data_len && (j / TRACE_MAX_HEX_BYTES) < TRACE_MAX_HEX_BYTES; j++) {
        uint8_t parityBits = parityBytes[j >> 3];
        if (protocol != LEGIC
                && protocol != ISO_14443B
                && protocol != ISO_15693
                && protocol != ICLASS
                && protocol != ISO_7816_4
                && protocol != PROTO_HITAG1
                && protocol != PROTO_HITAG2
                && protocol != PROTO_HITAGS
                && protocol != THINFILM
                && protocol != FELICA
                && protocol != LTO
                && protocol != PROTO_CRYPTORF
                && (hdr->isResponse || protocol == ISO_14443A || protocol == PROTO_MIFARE || protocol == PROTO_MFPLUS || protocol == SEOS)
                && (oddparity8(frame[j]) != ((parityBits >> (7 - (j & 0x0007))) & 0x01))) {

            snprintf(line[j / 18] + ((j % 18) * 4), 120, "%02x! ", frame[j]);

        } else if (protocol == ICLASS  && hdr->isResponse == false) {

            uint8_t parity = 0;
            for (int i = 0; i < 6; i++) {
                parity ^= ((frame[0] >> i) & 1);
            }

            if (parity == ((frame[0] >> 7) & 1)) {
                snprintf(line[j / 18] + ((j % 18) * 4), 120, "%02x  ", frame[j]);
            } else {
                snprintf(line[j / 18] + ((j % 18) * 4), 120, "%02x! ", frame[j]);
            }

        } else if (((protocol == PROTO_HITAG1) || (protocol == PROTO_HITAG2) || (protocol == PROTO_HITAGS)) && (parityBytes[0] > 0)) {
            // handle partial bytes
            uint8_t nbits = parityBytes[0];
            if (j == 0) {
                partialbytebuff = frame[0] << nbits;
                snprintf(line[0], 120, "%02x(%i) ", frame[0] >> (8 - nbits), nbits);
                offset = 2;
            } else {
                uint8_t byte = partialbytebuff | (frame[j] >> (8 - nbits));
                partialbytebuff = frame[j] << nbits;
                snprintf(line[j / 18] + ((j % 18) * 4) + offset, 120, "%02x  ", byte);
            }
        } else {
            snprintf(line[j / 18] + ((j % 18) * 4), 120, "%02x  ", frame[j]);
        }

    }

    if (markCRCBytes && data_len > 2) {
        // CRC-command
        if (((protocol == PROTO_HITAG1) || (protocol == PROTO_HITAGS)) && (data_len > 1)) {
            // Note that UID REQUEST response has no CRC, but we don't know
            // if the response we see is a UID
            char *pos1 = line[(data_len - 1) / 18] + (((data_len - 1) % 18) * 4) + offset - 1;
            (*pos1) = '[';
            char *pos2 = line[(data_len) / 18] + (((data_len) % 18) * 4) + offset - 2;
            (*pos2) = ']';
            (*(pos2 + 1)) = '\0';
        } else {

            if (crcStatus == 0 || crcStatus == 1) {

                char *pos1 = line[(data_len - 2) / TRACE_MAX_HEX_BYTES];
                pos1 += (((data_len - 2) % TRACE_MAX_HEX_BYTES) * 4) - 1;

                (*(pos1 + 6 + 1)) = '\0';

                char *cb_str = str_dup(pos1 + 1);

                if (g_session.supports_colors) {
                    if (crcStatus == 0) {
                        snprintf(pos1, 24, AEND " " _RED_("%s"), cb_str);
                    } else {
                        snprintf(pos1, 24, AEND " " _GREEN_("%s"), cb_str);
                    }
                } else {
                    snprintf(pos1, 9, "[%s]", cb_str);
                }

                // odd case of second crc byte is alone in a new line
                if (strlen(cb_str) < 5) {

                    free(cb_str);

                    pos1 = line[((data_len - 2) / TRACE_MAX_HEX_BYTES) + 1];
                    cb_str = str_dup(pos1);

                    if (g_session.supports_colors) {
                        if (crcStatus == 0) {
                            snprintf(pos1, 24, _RED_("%s"), cb_str);
                        } else {
                            snprintf(pos1, 24, _GREEN_("%s"), cb_str);
                        }
                    } else {
                        snprintf(pos1, 9, "[%s]", cb_str);
                    }
                }

                free(cb_str);
            }
        }
    }

    // Draw the CRC column
    const char *crcstrings[] = { _RED_(" !! "), _GREEN_(" ok "), "    ", _GREEN_("A ok"), _GREEN_("B ok") };
    const char *crc = crcstrings[crcStatus];

    // mark short bytes (less than 8 Bit + Parity)
    if (protocol == ISO_14443A ||
            protocol == PROTO_MIFARE ||
            protocol == PROTO_MFPLUS ||
            protocol == THINFILM) {

        // approximated with 128 * (9 * data_len);
        uint16_t bitime = 1056 + 32;

        if (duration < bitime) {

            uint8_t m = 7;
            while (m > 0) {
                bitime -= 128;
                if (duration > bitime) {
                    break;
                }
                m--;
            }

            if (data_len) {
                line[(data_len - 1) / 16][((data_len - 1) % 16) * 4 + 2] = '(';
                line[(data_len - 1) / 16][((data_len - 1) % 16) * 4 + 3] = m + 0x30;
                line[(data_len - 1) / 16][((data_len - 1) % 16) * 4 + 4] = ')';
            }
        }
    }


    uint32_t previous_end_of_transmission_timestamp = 0;
    if (prev_eot) {
        if (*prev_eot) {
            previous_end_of_transmission_timestamp = *prev_eot;
        } else {
            previous_end_of_transmission_timestamp = hdr->timestamp;
        }
    }

    end_of_transmission_timestamp = hdr->timestamp + duration;

    if (prev_eot)
        *prev_eot = end_of_transmission_timestamp;

    // Always annotate these protocols both reader/tag messages
    switch (protocol) {
        case ISO_14443A:
        case ISO_7816_4:
            annotateIso14443a(explanation, sizeof(explanation), frame, data_len, hdr->isResponse);
            break;
        case PROTO_MIFARE:
        case PROTO_MFPLUS:
            annotateMifare(explanation, sizeof(explanation), frame, data_len, parityBytes, TRACELOG_PARITY_LEN(hdr), hdr->isResponse);
            break;
        case PROTO_HITAG1:
            annotateHitag1(explanation, sizeof(explanation), frame, data_len, hdr->isResponse);
            break;
        case PROTO_HITAG2:
            annotateHitag2(explanation, sizeof(explanation), frame, data_len, hdr->isResponse);
            break;
        case PROTO_HITAGS:
            annotateHitagS(explanation, sizeof(explanation), frame, data_len, hdr->isResponse);
            break;
        case ICLASS:
            annotateIclass(explanation, sizeof(explanation), frame, data_len, hdr->isResponse);
            break;
        default:
            break;
    }

    if (hdr->isResponse == false) {
        switch (protocol) {
            case LEGIC:
                annotateLegic(explanation, sizeof(explanation), frame, data_len);
                break;
            case MFDES:
                annotateMfDesfire(explanation, sizeof(explanation), frame, data_len);
                break;
            case PROTO_MFPLUS:
                annotateMfPlus(explanation, sizeof(explanation), frame, data_len);
                break;
            case ISO_14443B:
                annotateIso14443b(explanation, sizeof(explanation), frame, data_len);
                break;
            case TOPAZ:
                annotateTopaz(explanation, sizeof(explanation), frame, data_len);
                break;
            case ISO_7816_4:
                annotateIso7816(explanation, sizeof(explanation), frame, data_len);
                break;
            case ISO_15693:
                annotateIso15693(explanation, sizeof(explanation), frame, data_len);
                break;
            case FELICA:
                annotateFelica(explanation, sizeof(explanation), frame, data_len);
                break;
            case LTO:
                annotateLTO(explanation, sizeof(explanation), frame, data_len);
                break;
            case PROTO_CRYPTORF:
                annotateCryptoRF(explanation, sizeof(explanation), frame, data_len);
                break;
            case SEOS:
                annotateSeos(explanation, sizeof(explanation), frame, data_len);
                break;
            default:
                break;
        }
    }

    int str_padder = 72;
    int num_lines = MIN((data_len - 1) / TRACE_MAX_HEX_BYTES + 1, TRACE_MAX_HEX_BYTES);

    for (int j = 0; j < num_lines ; j++) {

        bool last_line = (j == num_lines - 1);
        str_padder = 72;

        if (j == 0) {

            uint32_t time1 = hdr->timestamp - first_hdr->timestamp;
            uint32_t time2 = end_of_transmission_timestamp - first_hdr->timestamp;
            if (prev_eot) {
                time1 = hdr->timestamp - previous_end_of_transmission_timestamp;
                time2 = duration;
            }

            // ansi codes addes extra chars that needs to be taken in consideration.
            if (last_line && (memcmp(crc, "\x20\x20\x20\x20", 4) != 0) && g_session.supports_colors && markCRCBytes) {
                str_padder = 85;
            }

            if (hdr->isResponse) {
                // tag row
                if (use_us) {
                    PrintAndLogEx(NORMAL, " %10.1f | %10.1f | Tag |%-*s | %s| %s",
                                  (float)time1 / 13.56,
                                  (float)time2 / 13.56,
                                  str_padder,
                                  line[j],
                                  (last_line) ? crc : "    ",
                                  (last_line) ? explanation : ""
                                 );
                } else {
                    PrintAndLogEx(NORMAL, " %10u | %10u | Tag |%-*s | %s| %s",
                                  time1,
                                  time2,
                                  str_padder,
                                  line[j],
                                  (last_line) ? crc : "    ",
                                  (last_line) ? explanation : ""
                                 );
                }
            } else {
                // reader row
                if (use_us) {
                    PrintAndLogEx(NORMAL,
                                  _YELLOW_(" %10.1f") " | " _YELLOW_("%10.1f") " | " _YELLOW_("Rdr") " |" _YELLOW_("%-*s")" | " _YELLOW_("%s") "| " _YELLOW_("%s"),
                                  (float)time1 / 13.56,
                                  (float)time2 / 13.56,
                                  str_padder,
                                  line[j],
                                  (last_line) ? crc : "    ",
                                  (last_line) ? explanation : ""
                                 );
                } else {
                    PrintAndLogEx(NORMAL,
                                  _YELLOW_(" %10u") " | " _YELLOW_("%10u") " | " _YELLOW_("Rdr") " |" _YELLOW_("%-*s")" | " _YELLOW_("%s") "| " _YELLOW_("%s"),
                                  time1,
                                  time2,
                                  str_padder,
                                  line[j],
                                  (last_line) ? crc : "    ",
                                  (last_line) ? explanation : ""
                                 );
                }
            }

        } else {


            if (last_line && (memcmp(crc, "\x20\x20\x20\x20", 4) != 0) && g_session.supports_colors && markCRCBytes) {
                str_padder = 85;
                // odd case of multiline,  and last single byte on empty row has been colorised...
                if (strlen(line[j]) < 14) {
                    str_padder = 81;
                }
            }

            if (hdr->isResponse) {
                PrintAndLogEx(NORMAL, "            |            |     |%-*s | %s| %s",
                              str_padder,
                              line[j],
                              last_line ? crc : "    ",
                              last_line ? explanation : ""
                             );
            } else {
                PrintAndLogEx(NORMAL, "            |            |     |" _YELLOW_("%-*s")" | " _YELLOW_("%s") "| " _YELLOW_("%s"),
                              str_padder,
                              line[j],
                              last_line ? crc : "    ",
                              last_line ? explanation : ""
                             );
            }

        }
    }

    if (protocol == PROTO_MIFARE || protocol == PROTO_MFPLUS) {
        uint8_t mfData[32] = {0};
        size_t mfDataLen = 0;
        if (DecodeMifareData(frame, data_len, parityBytes, hdr->isResponse, mfData, &mfDataLen, mfDicKeys, mfDicKeysCount)) {
            memset(explanation, 0x00, sizeof(explanation));
            annotateIso14443a(explanation, sizeof(explanation), mfData, mfDataLen, hdr->isResponse);
            uint8_t crcc = iso14443A_CRC_check(hdr->isResponse, mfData, mfDataLen);

            //iceman: colorise crc bytes here will need a refactor of code from above.
            if (hdr->isResponse) {
                PrintAndLogEx(NORMAL, "            |            |  *  |%-*s | %-4s| %s",
                              str_padder,
                              sprint_hex_inrow_spaces(mfData, mfDataLen, 2),
                              (crcc == 0 ? _RED_(" !! ") : (crcc == 1 ? _GREEN_(" ok ") : "    ")),
                              explanation);
            } else {
                PrintAndLogEx(NORMAL, "            |            |  *  |" _YELLOW_("%-*s")" | " _YELLOW_("%s") "| " _YELLOW_("%s"),
                              str_padder,
                              sprint_hex_inrow_spaces(mfData, mfDataLen, 2),
                              (crcc == 0 ? _RED_(" !! ") : (crcc == 1 ? _GREEN_(" ok ") : "    ")),
                              explanation);
            }
        }
    }

    if (is_last_record(tracepos, traceLen)) {
        return traceLen;
    }

    if (showWaitCycles && hdr->isResponse == false && next_record_is_response(tracepos, trace)) {

        tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);

        uint32_t time1 = end_of_transmission_timestamp - first_hdr->timestamp;
        uint32_t time2 = next_hdr->timestamp - first_hdr->timestamp;
        if (prev_eot) {
            time1 = 0;
            time2 = next_hdr->timestamp - end_of_transmission_timestamp;
        }

        if (use_us) {
            PrintAndLogEx(NORMAL, " %10.1f | %10.1f | %s |fdt (Frame Delay Time): " _YELLOW_("%.1f"),
                          (float)time1 / 13.56,
                          (float)time2 / 13.56,
                          "   ",
                          (float)(next_hdr->timestamp - end_of_transmission_timestamp) / 13.56);
        } else {
            PrintAndLogEx(NORMAL, " %10u | %10u | %s |fdt (Frame Delay Time): " _YELLOW_("%d"),
                          time1,
                          time2,
                          "   ",
                          (next_hdr->timestamp - end_of_transmission_timestamp));
        }
    }

    return tracepos;
}

static int download_trace(void) {

    if (IfPm3Present() == false) {
        PrintAndLogEx(FAILED, "You requested a trace upload in offline mode, consider using parameter '-1' for working from Tracebuffer");
        return PM3_EINVARG;
    }

    // reserve some space.
    if (gs_trace)
        free(gs_trace);

    gs_traceLen = 0;

    gs_trace = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (gs_trace == NULL) {
        PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading tracelog data from device");

    // Query for the size of the trace,  downloading PM3_CMD_DATA_SIZE
    PacketResponseNG resp;
    if (!GetFromDevice(BIG_BUF, gs_trace, PM3_CMD_DATA_SIZE, 0, NULL, 0, &resp, 4000, true)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        free(gs_trace);
        gs_trace = NULL;
        return PM3_ETIMEOUT;
    }

    gs_traceLen = resp.oldarg[2];

    // if tracelog buffer was larger and we need to download more.
    if (gs_traceLen > PM3_CMD_DATA_SIZE) {

        free(gs_trace);
        gs_trace = calloc(gs_traceLen, sizeof(uint8_t));
        if (gs_trace == NULL) {
            PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
            return PM3_EMALLOC;
        }

        if (!GetFromDevice(BIG_BUF, gs_trace, gs_traceLen, 0, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            free(gs_trace);
            gs_trace = NULL;
            return PM3_ETIMEOUT;
        }
    }
    return PM3_SUCCESS;
}

// sanity check. Don't use proxmark if it is offline and you didn't specify useTraceBuffer
/*
static int SanityOfflineCheck( bool useTraceBuffer ){
    if ( !useTraceBuffer && offline) {
        PrintAndLogEx(NORMAL, "Your proxmark3 device is offline. Specify [1] to use TraceBuffer data instead");
        return 0;
    }
    return 1;
}
*/

static int CmdTraceExtract(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "trace extract",
                  "Extracts protocol authentication challenges from trace buffer\n",
                  "trace extract\n"
                  "trace extract -1\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "buffer", "use data from trace buffer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_buffer = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    clearCommandBuffer();

    if (use_buffer == false) {
        download_trace();
    } else if (gs_traceLen == 0) {
        PrintAndLogEx(FAILED, "You requested a trace list in offline mode but there is no trace.");
        PrintAndLogEx(FAILED, "Consider using " _YELLOW_("`trace load`") " or removing parameter " _YELLOW_("`-1`"));
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Recorded activity (trace len = " _YELLOW_("%u") " bytes)", gs_traceLen);
    if (gs_traceLen == 0) {
        return PM3_SUCCESS;
    }

    uint16_t tracepos = 0;

    while (tracepos < gs_traceLen) {
        tracepos = extractChallenges(tracepos, gs_traceLen, gs_trace);

        if (kbd_enter_pressed())
            break;
    }

    return PM3_SUCCESS;
}

static int CmdTraceLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "trace load",
                  "Load protocol data from binary file to trace buffer\n"
                  "File extension is <.trace>",
                  "trace load -f mytracefile    -> w/o file extension"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify trace file to load"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (gs_trace) {
        free(gs_trace);
        gs_trace = NULL;
    }

    size_t len = 0;
    if (loadFile_safe(filename, ".trace", (void **)&gs_trace, &len) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Could not open file " _YELLOW_("%s"), filename);
        return PM3_EIO;
    }

    gs_traceLen = (long)len;

    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = " _YELLOW_("%u") " bytes)", gs_traceLen);
    PrintAndLogEx(HINT, "try " _YELLOW_("`trace list -1 -t ...`") " to view trace.  Remember the " _YELLOW_("`-1`") " param");
    return PM3_SUCCESS;
}

static int CmdTraceSave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "trace save",
                  "Save protocol data from trace buffer to binary file\n"
                  "File extension is <.trace>",
                  "trace save -f mytracefile    -> w/o file extension"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify trace file to save"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (gs_traceLen == 0) {
        download_trace();
        if (gs_traceLen == 0) {
            PrintAndLogEx(WARNING, "trace is empty, nothing to save");
            return PM3_SUCCESS;
        }
    }

    saveFile(filename, ".trace", gs_trace, gs_traceLen);
    return PM3_SUCCESS;
}

int CmdTraceListAlias(const char *Cmd, const char *alias, const char *protocol) {
    CLIParserContext *ctx;
    char desc[500] = {0};
    snprintf(desc, sizeof(desc) - 1,
             "Alias of `trace list -t %s` with selected protocol data to annotate trace buffer\n"
             "You can load a trace from file (see `trace load -h`) or it be downloaded from device by default\n"
             "It accepts all other arguments of `trace list`. Note that some might not be relevant for this specific protocol",
             protocol);
    char example[200] = {0};
    snprintf(example, sizeof(example) - 1,
             "%s list --frame      -> show frame delay times\n"
             "%s list -1           -> use trace buffer ",
             alias, alias);
    char fullalias[100] = {0};
    snprintf(fullalias, sizeof(fullalias) - 1, "%s list", alias);
    CLIParserInit(&ctx, fullalias, desc, example);

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "buffer", "use data from trace buffer"),
        arg_lit0(NULL, "frame", "show frame delay times"),
        arg_lit0("c", NULL, "mark CRC bytes"),
        arg_lit0("r", NULL, "show relative times (gap and duration)"),
        arg_lit0("u", NULL, "display times in microseconds instead of clock cycles"),
        arg_lit0("x", NULL, "show hexdump to convert to pcap(ng)\n"
                 "                                   or to import into Wireshark using encapsulation type \"ISO 14443\""),
        arg_str0("f", "file", "<fn>", "filename of dictionary"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    char args[128] = {0};
    snprintf(args, sizeof(args), "-t %s ", protocol);
    strncat(args, Cmd, sizeof(args) - strlen(args) - 1);
    return CmdTraceList(args);
}

int CmdTraceList(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "trace list",
                  "Annotate trace buffer with selected protocol data\n"
                  "You can load a trace from file (see `trace load -h`) or it be downloaded from device by default\n",
                  "trace list -t raw      -> just show raw data without annotations\n"
                  "\n"
                  "trace list -t 14a      -> interpret as " _YELLOW_("ISO14443-A") "\n"
                  "trace list -t 14b      -> interpret as " _YELLOW_("ISO14443-B") "\n"
                  "trace list -t 15       -> interpret as " _YELLOW_("ISO15693") "\n"
                  "trace list -t 7816     -> interpret as " _YELLOW_("ISO7816-4") "\n"
                  "trace list -t cryptorf -> interpret as " _YELLOW_("CryptoRF") "\n\n"
                  "trace list -t des      -> interpret as " _YELLOW_("MIFARE DESFire") "\n"
                  "trace list -t felica   -> interpret as " _YELLOW_("ISO18092 / FeliCa") "\n"
                  "trace list -t hitag1   -> interpret as " _YELLOW_("Hitag1") "\n"
                  "trace list -t hitag2   -> interpret as " _YELLOW_("Hitag2") "\n"
                  "trace list -t hitags   -> interpret as " _YELLOW_("HitagS") "\n"
                  "trace list -t iclass   -> interpret as " _YELLOW_("iCLASS") "\n"
                  "trace list -t legic    -> interpret as " _YELLOW_("LEGIC") "\n"
                  "trace list -t lto      -> interpret as " _YELLOW_("LTO-CM") "\n"
                  "trace list -t mf       -> interpret as " _YELLOW_("MIFARE Classic") " and decrypt crypto1 stream\n"
                  "trace list -t seos     -> interpret as " _YELLOW_("SEOS") "\n"
                  "trace list -t thinfilm -> interpret as " _YELLOW_("Thinfilm") "\n"
                  "trace list -t topaz    -> interpret as " _YELLOW_("Topaz") "\n"
                  "trace list -t mfp      -> interpret as " _YELLOW_("MIFARE Plus") "\n"
                  "\n"
                  "trace list -t mf -f mfc_default_keys.dic     -> use default dictionary file\n"
                  "trace list -t 14a --frame                    -> show frame delay times\n"
                  "trace list -t 14a -1                         -> use trace buffer "
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "buffer", "use data from trace buffer"),
        arg_lit0(NULL, "frame", "show frame delay times"),
        arg_lit0("c", NULL, "mark CRC bytes"),
        arg_lit0("r", NULL, "show relative times (gap and duration)"),
        arg_lit0("u", NULL, "display times in microseconds instead of clock cycles"),
        arg_lit0("x", NULL, "show hexdump to convert to pcap(ng)\n"
                 "                                   or to import into Wireshark using encapsulation type \"ISO 14443\""),
        arg_str0("t", "type", NULL, "protocol to annotate the trace"),
        arg_str0("f", "file", "<fn>", "filename of dictionary"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_buffer = arg_get_lit(ctx, 1);
    bool show_wait_cycles = arg_get_lit(ctx, 2);
    bool mark_crc = arg_get_lit(ctx, 3);
    bool use_relative = arg_get_lit(ctx, 4);
    bool use_us = arg_get_lit(ctx, 5);
    bool show_hex = arg_get_lit(ctx, 6);

    int tlen = 0;
    char type[10] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 7), (uint8_t *)type, sizeof(type), &tlen);
    str_lower(type);

    int diclen = 0;
    char dictionary[FILE_PATH_SIZE + 2] = {0};
    if (CLIParamStrToBuf(arg_get_str(ctx, 8), (uint8_t *)dictionary, FILE_PATH_SIZE, &diclen)) {
        PrintAndLogEx(FAILED, "Dictionary file name too long or invalid.");
        diclen = 0;
    }

    CLIParserFree(ctx);

    clearCommandBuffer();

    // no crc, no annotations
    uint8_t protocol = -1;

    // validate type of output
    if (strcmp(type, "14a") == 0)      protocol = ISO_14443A;
    else if (strcmp(type, "14b") == 0)      protocol = ISO_14443B;
    else if (strcmp(type, "15") == 0)       protocol = ISO_15693;
    else if (strcmp(type, "7816") == 0)     protocol = ISO_7816_4;
    else if (strcmp(type, "cryptorf") == 0) protocol = PROTO_CRYPTORF;
    else if (strcmp(type, "des") == 0)      protocol = MFDES;
    else if (strcmp(type, "felica") == 0)   protocol = FELICA;
    else if (strcmp(type, "hitag1") == 0)   protocol = PROTO_HITAG1;
    else if (strcmp(type, "hitag2") == 0)   protocol = PROTO_HITAG2;
    else if (strcmp(type, "hitags") == 0)   protocol = PROTO_HITAGS;
    else if (strcmp(type, "iclass") == 0)   protocol = ICLASS;
    else if (strcmp(type, "legic") == 0)    protocol = LEGIC;
    else if (strcmp(type, "lto") == 0)      protocol = LTO;
    else if (strcmp(type, "mf") == 0)       protocol = PROTO_MIFARE;
    else if (strcmp(type, "raw") == 0)      protocol = -1;
    else if (strcmp(type, "seos") == 0)     protocol = SEOS;
    else if (strcmp(type, "thinfilm") == 0) protocol = THINFILM;
    else if (strcmp(type, "topaz") == 0)    protocol = TOPAZ;
    else if (strcmp(type, "mfp") == 0)      protocol = PROTO_MFPLUS;
    else if (strcmp(type, "") == 0)         protocol = -1;
    else {
        PrintAndLogEx(FAILED, "Unknown protocol \"%s\"", type);
        return PM3_EINVARG;
    }

    if (use_buffer == false) {
        download_trace();
    } else if (gs_traceLen == 0) {
        PrintAndLogEx(FAILED, "You requested a trace list in offline mode but there is no trace.");
        PrintAndLogEx(FAILED, "Consider using " _YELLOW_("`trace load`") " or removing parameter " _YELLOW_("`-1`"));
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Recorded activity (trace len = " _YELLOW_("%u") " bytes)", gs_traceLen);
    if (gs_traceLen == 0) {
        return PM3_SUCCESS;
    }

    uint16_t tracepos = 0;

    /*
    if (protocol == FELICA) {
        printFelica(gs_traceLen, gs_trace);
    } */

    if (show_hex) {
        while (tracepos < gs_traceLen) {
            tracepos = printHexLine(tracepos, gs_traceLen, gs_trace, protocol);
        }
    } else {

        if (use_relative) {
            PrintAndLogEx(INFO, _YELLOW_("gap") " = time between transfers. " _YELLOW_("duration") " = duration of data transfer. " _YELLOW_("src") " = source of transfer");
        } else {
            PrintAndLogEx(INFO, _YELLOW_("start") " = start of start frame " _YELLOW_("end") " = end of frame. " _YELLOW_("src") " = source of transfer");
        }

        if (protocol == ISO_14443A || protocol == PROTO_MIFARE || protocol == MFDES || protocol == PROTO_MFPLUS || protocol == TOPAZ || protocol == LTO) {
            if (use_us)
                PrintAndLogEx(INFO, _YELLOW_("ISO14443A") " - all times are in microseconds");
            else
                PrintAndLogEx(INFO, _YELLOW_("ISO14443A") " - all times are in carrier periods (1/13.56MHz)");
        }

        if (protocol == THINFILM) {
            if (use_us)
                PrintAndLogEx(INFO, _YELLOW_("Thinfilm") " - all times are in microseconds");
            else
                PrintAndLogEx(INFO, _YELLOW_("Thinfilm") " - all times are in carrier periods (1/13.56MHz)");
        }

        if (protocol == ICLASS || protocol == ISO_15693) {
            if (use_us)
                PrintAndLogEx(INFO, _YELLOW_("ISO15693 / iCLASS") " - all times are in microseconds");
            else
                PrintAndLogEx(INFO, _YELLOW_("ISO15693 / iCLASS") " - all times are in carrier periods (1/13.56MHz)");
        }

        if (protocol == LEGIC)
            PrintAndLogEx(INFO, _YELLOW_("LEGIC") " - Reader Mode: Timings are in ticks (1us == 1.5ticks)\n"
                          "        Tag Mode: Timings are in sub carrier periods (1/212 kHz == 4.7us)");

        if (protocol == ISO_14443B || protocol == PROTO_CRYPTORF) {
            if (use_us)
                PrintAndLogEx(INFO, _YELLOW_("ISO14443B") " - all times are in microseconds");
            else
                PrintAndLogEx(INFO, _YELLOW_("ISO14443B") " - all times are in carrier periods (1/13.56MHz)");
        }

        if (protocol == ISO_7816_4)
            PrintAndLogEx(INFO, _YELLOW_("ISO7816-4 / Smartcard") " - Timings N/A");

        if (protocol == PROTO_HITAG1 || protocol == PROTO_HITAG2 || protocol == PROTO_HITAGS)
            PrintAndLogEx(INFO, _YELLOW_("Hitag1 / Hitag2 / HitagS") " - Timings in ETU (8us)");

        if (protocol == FELICA) {
            if (use_us)
                PrintAndLogEx(INFO, _YELLOW_("ISO18092 / FeliCa") " - all times are in microseconds");
            else
                PrintAndLogEx(INFO, _YELLOW_("ISO18092 / FeliCa") " - all times are in carrier periods (1/13.56MHz)");
        }


        const uint64_t *dicKeys = NULL;
        uint32_t dicKeysCount = 0;
        bool dictionaryLoad = false;

        if (protocol == PROTO_MIFARE || protocol == PROTO_MFPLUS) {
            if (diclen > 0) {
                uint8_t *keyBlock = NULL;
                int res = loadFileDICTIONARY_safe(dictionary, (void **) &keyBlock, 6, &dicKeysCount);
                if (res != PM3_SUCCESS || dicKeysCount == 0 || keyBlock == NULL) {
                    PrintAndLogEx(FAILED, "An error occurred while loading the dictionary! (we will use the default keys now)");
                } else {
                    dicKeys = calloc(dicKeysCount, sizeof(uint64_t));
                    for (int i = 0; i < dicKeysCount; i++) {
                        uint64_t key = bytes_to_num(keyBlock + i * 6, 6);
                        memcpy((uint8_t *) &dicKeys[i], &key, sizeof(uint64_t));
                    }
                    dictionaryLoad = true;
                }
                if (keyBlock != NULL) {
                    free(keyBlock);
                }
            }
            if (dicKeys == NULL) {
                dicKeys = g_mifare_default_keys;
                dicKeysCount = ARRAYLEN(g_mifare_default_keys);
            }
        }

        PrintAndLogEx(NORMAL, "");
        if (use_relative) {
            PrintAndLogEx(NORMAL, "        Gap |   Duration | Src | Data (! denotes parity error, ' denotes short bytes)                    | CRC | Annotation");
        } else {
            PrintAndLogEx(NORMAL, "      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation");
        }
        PrintAndLogEx(NORMAL, "------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------");

        // clean authentication data used with the mifare classic decrypt fct
        if (protocol == ISO_14443A || protocol == PROTO_MIFARE || protocol == PROTO_MFPLUS)
            ClearAuthData();

        uint32_t previous_EOT = 0;
        uint32_t *prev_EOT = NULL;
        if (use_relative) {
            prev_EOT = &previous_EOT;
        }

        while (tracepos < gs_traceLen) {
            tracepos = printTraceLine(tracepos, gs_traceLen, gs_trace, protocol, show_wait_cycles, mark_crc, prev_EOT, use_us, dicKeys, dicKeysCount);

            if (kbd_enter_pressed())
                break;
        }

        if (dictionaryLoad)
            free((void *) dicKeys);
    }

    if (show_hex)
        PrintAndLogEx(HINT, "syntax to use: " _YELLOW_("`text2pcap -t \"%%S.\" -l 264 -n <input-text-file> <output-pcapng-file>`"));

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
    {"extract", CmdTraceExtract,  AlwaysAvailable, "Extract authentication challenges found in trace"},
    {"list",    CmdTraceList,     AlwaysAvailable, "List protocol data in trace buffer"},
    {"load",    CmdTraceLoad,     AlwaysAvailable, "Load trace from file"},
    {"save",    CmdTraceSave,     AlwaysAvailable, "Save trace buffer to file"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdTrace(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
