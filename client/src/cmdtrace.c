//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Trace commands
//-----------------------------------------------------------------------------
#include "cmdtrace.h"

#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "comms.h"              // for sending cmds to device. GetFromBigBuf
#include "fileutils.h"          // for saveFile
#include "cmdlfhitag.h"         // annotate hitag
#include "pm3_cmd.h"            // tracelog_hdr_t

static int CmdHelp(const char *Cmd);

// trace pointer
static uint8_t *g_trace;
static long g_traceLen = 0;

static int usage_trace_list(void) {
    PrintAndLogEx(NORMAL, "List protocol data in trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace list <protocol> [f][c| <0|1>");
    PrintAndLogEx(NORMAL, "    f      - show frame delay times as well");
    PrintAndLogEx(NORMAL, "    c      - mark CRC bytes");
    PrintAndLogEx(NORMAL, "    x      - show hexdump to convert to pcap(ng) or to import into Wireshark using encapsulation type \"ISO 14443\"");
    PrintAndLogEx(NORMAL, "             syntax to use: `text2pcap -t \"%%S.\" -l 264 -n <input-text-file> <output-pcapng-file>`");
    PrintAndLogEx(NORMAL, "    <0|1>  - use data from Tracebuffer, if not set, try to collect a trace from Proxmark3 device.");
    PrintAndLogEx(NORMAL, "Supported <protocol> values:");
    PrintAndLogEx(NORMAL, "    raw      - just show raw data without annotations");
    PrintAndLogEx(NORMAL, "    14a      - interpret data as iso14443a communications");
    PrintAndLogEx(NORMAL, "    thinfilm - interpret data as Thinfilm communications");
    PrintAndLogEx(NORMAL, "    topaz    - interpret data as Topaz communications");
    PrintAndLogEx(NORMAL, "    mf       - interpret data as iso14443a communications and decrypt crypto1 stream");
    PrintAndLogEx(NORMAL, "    des      - interpret data as DESFire communications");
    PrintAndLogEx(NORMAL, "    14b      - interpret data as iso14443b communications");
    PrintAndLogEx(NORMAL, "    7816     - interpret data as iso7816-4 communications");
    PrintAndLogEx(NORMAL, "    15       - interpret data as iso15693 communications");
    PrintAndLogEx(NORMAL, "    iclass   - interpret data as iclass communications");
    PrintAndLogEx(NORMAL, "    legic    - interpret data as LEGIC communications");
    PrintAndLogEx(NORMAL, "    felica   - interpret data as ISO18092 / FeliCa communications");
    PrintAndLogEx(NORMAL, "    hitag1   - interpret data as Hitag1 communications");
    PrintAndLogEx(NORMAL, "    hitag2   - interpret data as Hitag2 communications");
    PrintAndLogEx(NORMAL, "    hitags   - interpret data as HitagS communications");
    PrintAndLogEx(NORMAL, "    lto      - interpret data as LTO-CM communications");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace list 14a f");
    PrintAndLogEx(NORMAL, "        trace list iclass");
    return PM3_SUCCESS;
}
static int usage_trace_load(void) {
    PrintAndLogEx(NORMAL, "Load protocol data from file to trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace load <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace load mytracefile.bin");
    return PM3_SUCCESS;
}
static int usage_trace_save(void) {
    PrintAndLogEx(NORMAL, "Save protocol data from trace buffer to file.");
    PrintAndLogEx(NORMAL, "Usage:  trace save <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace save mytracefile.bin");
    return PM3_SUCCESS;
}

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
            char line[(hdr->data_len * 3) + 1];
            char *ptr = &line[0];

            for (int i = 0; i < hdr->data_len ; i++) {
                ptr += sprintf(ptr, "%02x ", hdr->frame[i]);
            }

            char data_len_str[5];
            char temp_str1[3] = {0};
            char temp_str2[3] = {0};
            
            sprintf(data_len_str, "%04x", hdr->data_len);
            strncat(temp_str1, data_len_str, 2);
            temp_str1[2] = '\0';
            strncat(temp_str2, data_len_str + 2, 2);
            temp_str2[2] = '\0';

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

static uint16_t printTraceLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol, bool showWaitCycles, bool markCRCBytes) {
    // sanity check
    if (is_last_record(tracepos, traceLen)) return traceLen;

    uint32_t duration;
    uint16_t data_len;
    uint32_t EndOfTransmissionTimestamp;
    uint8_t topaz_reader_command[9];
    char explanation[40] = {0};
    uint8_t mfData[32] = {0};
    size_t mfDataLen = 0;
    tracelog_hdr_t *first_hdr = (tracelog_hdr_t *)(trace);
    tracelog_hdr_t *hdr = (tracelog_hdr_t *)(trace + tracepos);

    duration = hdr->duration;
    data_len = hdr->data_len;

    if (tracepos + TRACELOG_HDR_LEN + data_len + TRACELOG_PARITY_LEN(hdr) > traceLen) {
        return traceLen;
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
            case FELICA:
                crcStatus = !felica_CRC_check(frame + 2, data_len - 4);
                break;
            case PROTO_MIFARE:
                crcStatus = mifare_CRC_check(hdr->isResponse, frame, data_len);
                break;
            case ISO_14443A:
            case MFDES:
            case LTO:
                crcStatus = iso14443A_CRC_check(hdr->isResponse, frame, data_len);
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
            case ISO_7816_4:
            case PROTO_HITAG1:
            case PROTO_HITAG2:
            case PROTO_HITAGS:
            default:
                break;
        }
    }
    //0 CRC-command, CRC not ok
    //1 CRC-command, CRC ok
    //2 Not crc-command

     //--- Draw the data column
    char line[18][120] = {{0}};

   if (data_len == 0) {
        sprintf(line[0], "<empty trace - possible error>");
        return tracepos;
    }

    for (int j = 0; j < data_len && j / 18 < 18; j++) {

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
                && (hdr->isResponse || protocol == ISO_14443A)
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

        } else {
            snprintf(line[j / 18] + ((j % 18) * 4), 120, "%02x  ", frame[j]);
        }

    }

    if (markCRCBytes) {
        //CRC-command
        if (crcStatus == 0 || crcStatus == 1) {
            char *pos1 = line[(data_len - 2) / 18] + (((data_len - 2) % 18) * 4);
            (*pos1) = '[';
            char *pos2 = line[(data_len) / 18] + (((data_len) % 18) * 4);
            sprintf(pos2, "%c", ']');
        }
    }

    // Draw the CRC column
    const char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

    EndOfTransmissionTimestamp = hdr->timestamp + duration;

    // Always annotate LEGIC read/tag
    if (protocol == LEGIC)
        annotateLegic(explanation, sizeof(explanation), frame, data_len);

    if (protocol == PROTO_MIFARE)
        annotateMifare(explanation, sizeof(explanation), frame, data_len, parityBytes, TRACELOG_PARITY_LEN(hdr), hdr->isResponse);

    if (protocol == FELICA)
        annotateFelica(explanation, sizeof(explanation), frame, data_len);

    if (!hdr->isResponse) {
        switch (protocol) {
            case ICLASS:
                annotateIclass(explanation, sizeof(explanation), frame, data_len);
                break;
            case ISO_14443A:
                annotateIso14443a(explanation, sizeof(explanation), frame, data_len);
                break;
            case MFDES:
                annotateMfDesfire(explanation, sizeof(explanation), frame, data_len);
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
            case PROTO_HITAG1:
                annotateHitag1(explanation, sizeof(explanation), frame, data_len);
                break;
            case PROTO_HITAG2:
                annotateHitag2(explanation, sizeof(explanation), frame, data_len);
                break;
            case PROTO_HITAGS:
                annotateHitagS(explanation, sizeof(explanation), frame, data_len);
                break;
            default:
                break;
        }
    }

    int num_lines = MIN((data_len - 1) / 18 + 1, 18);
    for (int j = 0; j < num_lines ; j++) {
        if (j == 0) {
            PrintAndLogEx(NORMAL, " %10u | %10u | %s |%-72s | %s| %s",
                          (hdr->timestamp - first_hdr->timestamp),
                          (EndOfTransmissionTimestamp - first_hdr->timestamp),
                          (hdr->isResponse ? "Tag" : "Rdr"),
                          line[j],
                          (j == num_lines - 1) ? crc : "    ",
                          (j == num_lines - 1) ? explanation : "");
        } else {
            PrintAndLogEx(NORMAL, "            |            |     |%-72s | %s| %s",
                          line[j],
                          (j == num_lines - 1) ? crc : "    ",
                          (j == num_lines - 1) ? explanation : "");
        }
    }

    if (DecodeMifareData(frame, data_len, parityBytes, hdr->isResponse, mfData, &mfDataLen)) {
        memset(explanation, 0x00, sizeof(explanation));
        if (!hdr->isResponse) {
            annotateIso14443a(explanation, sizeof(explanation), mfData, mfDataLen);
        }
        uint8_t crcc = iso14443A_CRC_check(hdr->isResponse, mfData, mfDataLen);
        PrintAndLogEx(NORMAL, "            |            |  *  |%-72s | %-4s| %s",
                      sprint_hex_inrow_spaces(mfData, mfDataLen, 2),
                      (crcc == 0 ? "!crc" : (crcc == 1 ? " ok " : "    ")),
                      explanation);
    }

    if (is_last_record(tracepos, traceLen)) return traceLen;

    if (showWaitCycles && !hdr->isResponse && next_record_is_response(tracepos, trace)) {
        
        tracelog_hdr_t *next_hdr = (tracelog_hdr_t *)(trace + tracepos);
         
        PrintAndLogEx(NORMAL, " %10u | %10u | %s |fdt (Frame Delay Time): %d",
                      (EndOfTransmissionTimestamp - first_hdr->timestamp),
                      (next_hdr->timestamp - first_hdr->timestamp),
                      "   ",
                      (next_hdr->timestamp - EndOfTransmissionTimestamp));
    }

    return tracepos;
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

static int CmdTraceLoad(const char *Cmd) {

    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_load();

    param_getstr(Cmd, 0, filename, sizeof(filename));

    if (g_trace)
        free(g_trace);

    size_t len = 0;
    if (loadFile_safe(filename, ".trace", (void**)&g_trace, &len) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Could not open file " _YELLOW_("%s"), filename);
        return PM3_EIO;
    }
    
    g_traceLen = (long)len;
    
    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = " _YELLOW_("%lu") " bytes) loaded from " _YELLOW_("%s"), g_traceLen, filename);
    return PM3_SUCCESS;
}

static int CmdTraceSave(const char *Cmd) {

    if (g_traceLen == 0) {
        PrintAndLogEx(WARNING, "trace is empty, nothing to save");
        return PM3_SUCCESS;
    }

    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_save();

    param_getstr(Cmd, 0, filename, sizeof(filename));
    saveFile(filename, ".bin", g_trace, g_traceLen);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
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

int CmdTraceList(const char *Cmd) {

    clearCommandBuffer();

    bool showWaitCycles = false;
    bool markCRCBytes = false;
    bool showHex = false;
    bool isOnline = true;
    bool errors = false;
    uint8_t protocol = 0;
    char type[10] = {0};

    //int tlen = param_getstr(Cmd,0,type);
    //char param1 = param_getchar(Cmd, 1);
    //char param2 = param_getchar(Cmd, 2);

    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {

        int slen = param_getstr(Cmd, cmdp, type, sizeof(type));
        if (slen == 1) {

            switch (tolower(param_getchar(Cmd, cmdp))) {
                case 'h':
                    return usage_trace_list();
                case 'f':
                    showWaitCycles = true;
                    cmdp++;
                    break;
                case 'c':
                    markCRCBytes = true;
                    cmdp++;
                    break;
                case 'x':
                    showHex = true;
                    cmdp++;
                    break;
                case '0':
                    isOnline = true;
                    cmdp++;
                    break;
                case '1':
                    isOnline = false;
                    cmdp++;
                    break;
                default:
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                    errors = true;
                    break;
            }

        } else {

            str_lower(type);

            // validate type of output
            if (strcmp(type,      "iclass") == 0)   protocol = ICLASS;
            else if (strcmp(type, "14a") == 0)      protocol = ISO_14443A;
            else if (strcmp(type, "14b") == 0)      protocol = ISO_14443B;
            else if (strcmp(type, "topaz") == 0)    protocol = TOPAZ;
            else if (strcmp(type, "7816") == 0)     protocol = ISO_7816_4;
            else if (strcmp(type, "des") == 0)      protocol = MFDES;
            else if (strcmp(type, "legic") == 0)    protocol = LEGIC;
            else if (strcmp(type, "15") == 0)       protocol = ISO_15693;
            else if (strcmp(type, "felica") == 0)   protocol = FELICA;
            else if (strcmp(type, "mf") == 0)       protocol = PROTO_MIFARE;
            else if (strcmp(type, "hitag1") == 0)   protocol = PROTO_HITAG1;
            else if (strcmp(type, "hitag2") == 0)    protocol = PROTO_HITAG2;
            else if (strcmp(type, "hitags") == 0)    protocol = PROTO_HITAGS;
            else if (strcmp(type, "thinfilm") == 0) protocol = THINFILM;
            else if (strcmp(type, "lto") == 0)      protocol = LTO;
            else if (strcmp(type, "raw") == 0)      protocol = -1; //No crc, no annotations
            else errors = true;

            cmdp++;
        }
    }

    //if (!SanityOfflineCheck(isOnline)) return 1;

    //Validations
    if (errors) return usage_trace_list();

    if (isOnline) {

        if (!IfPm3Present()) {
            PrintAndLogEx(FAILED, "You requested a trace upload in offline mode, consider using parameter '1' for working from Tracebuffer");
            return PM3_EINVARG;
        }
        // reserve some space.
        if (g_trace)
            free(g_trace);

        g_traceLen = 0;

        g_trace = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
        if (g_trace == NULL) {
            PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
            return PM3_EMALLOC;
        }

        PrintAndLogEx(INFO, "downloading tracelog from device");

        // Query for the size of the trace,  downloading PM3_CMD_DATA_SIZE
        PacketResponseNG response;
        if (!GetFromDevice(BIG_BUF, g_trace, PM3_CMD_DATA_SIZE, 0, NULL, 0, &response, 4000, true)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            free(g_trace);
            return PM3_ETIMEOUT;
        }

        g_traceLen = response.oldarg[2];

        // if tracelog buffer was larger and we need to download more.
        if (g_traceLen > PM3_CMD_DATA_SIZE) {

            free(g_trace);
            g_trace = calloc(g_traceLen, sizeof(uint8_t));
            if (g_trace == NULL) {
                PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
                return PM3_EMALLOC;
            }

            if (!GetFromDevice(BIG_BUF, g_trace, g_traceLen, 0, NULL, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "command execution time out");
                free(g_trace);
                return PM3_ETIMEOUT;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "Recorded activity (trace len = " _YELLOW_("%lu") " bytes)", g_traceLen);
    if (g_traceLen == 0) {
        return PM3_SUCCESS;
    }

    uint16_t tracepos = 0;

    /*
    if (protocol == FELICA) {
        printFelica(g_traceLen, g_trace);
    } */

    if (showHex) {
        while (tracepos < g_traceLen) {
            tracepos = printHexLine(tracepos, g_traceLen, g_trace, protocol);
        }
    } else {
        PrintAndLogEx(INFO, _YELLOW_("Start") " = Start of Start Bit, " _YELLOW_("End") " = End of last modulation. " _YELLOW_("Src") " = Source of Transfer");
        if (protocol == ISO_14443A || protocol == PROTO_MIFARE || protocol == MFDES || protocol == TOPAZ || protocol == LTO)
            PrintAndLogEx(INFO, "ISO14443A - All times are in carrier periods (1/13.56MHz)");
        if (protocol == THINFILM)
            PrintAndLogEx(INFO, "Thinfilm - All times are in carrier periods (1/13.56MHz)");
        if (protocol == ICLASS)
            PrintAndLogEx(INFO, "iClass - Timings are not as accurate");
        if (protocol == LEGIC)
            PrintAndLogEx(INFO, "LEGIC - Reader Mode: Timings are in ticks (1us == 1.5ticks)\n"
                          "        Tag Mode: Timings are in sub carrier periods (1/212 kHz == 4.7us)");
        if (protocol == ISO_14443B)
            PrintAndLogEx(INFO, "ISO14443B"); // Timings ?
        if (protocol == ISO_15693)
            PrintAndLogEx(INFO, "ISO15693 - Timings are not as accurate");
        if (protocol == ISO_7816_4)
            PrintAndLogEx(INFO, "ISO7816-4 / Smartcard - Timings N/A yet");
        if (protocol == PROTO_HITAG1 || protocol == PROTO_HITAG2 || protocol == PROTO_HITAGS)
            PrintAndLogEx(INFO, "Hitag1 / Hitag2 / HitagS - Timings in ETU (8us)");
        if (protocol == FELICA)
            PrintAndLogEx(INFO, "ISO18092 / FeliCa - Timings are not as accurate");

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation");
        PrintAndLogEx(NORMAL, "------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------");

        ClearAuthData();
        while (tracepos < g_traceLen) {
            tracepos = printTraceLine(tracepos, g_traceLen, g_trace, protocol, showWaitCycles, markCRCBytes);

            if (kbd_enter_pressed())
                break;
        }
    }
    return PM3_SUCCESS;
}

