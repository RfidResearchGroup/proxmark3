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

static int CmdHelp(const char *Cmd);

// trace pointer
static uint8_t *trace;
long traceLen = 0;

static int usage_trace_list() {
    PrintAndLogEx(NORMAL, "List protocol data in trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace list <protocol> [f][c| <0|1>");
    PrintAndLogEx(NORMAL, "    f      - show frame delay times as well");
    PrintAndLogEx(NORMAL, "    c      - mark CRC bytes");
    PrintAndLogEx(NORMAL, "    x      - show hexdump to convert to pcap(ng) or to import into Wireshark using encapsulation type \"ISO 14443\"");
    PrintAndLogEx(NORMAL, "             syntax to use: `text2pcap -t \"%%S.\" -l 264 -n <input-text-file> <output-pcapng-file>`");
    PrintAndLogEx(NORMAL, "    <0|1>  - use data from Tracebuffer, if not set, try reading data from tag.");
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
    PrintAndLogEx(NORMAL, "    hitag    - interpret data as Hitag2 / HitagS communications");
    PrintAndLogEx(NORMAL, "    lto      - interpret data as LTO-CM communications");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace list 14a f");
    PrintAndLogEx(NORMAL, "        trace list iclass");
    return PM3_SUCCESS;
}
static int usage_trace_load() {
    PrintAndLogEx(NORMAL, "Load protocol data from file to trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace load <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace load mytracefile.bin");
    return PM3_SUCCESS;
}
static int usage_trace_save() {
    PrintAndLogEx(NORMAL, "Save protocol data from trace buffer to file.");
    PrintAndLogEx(NORMAL, "Usage:  trace save <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace save mytracefile.bin");
    return PM3_SUCCESS;
}

static bool is_last_record(uint16_t tracepos, uint8_t *trace, uint16_t traceLen) {
    return (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) >= traceLen);
}

static bool next_record_is_response(uint16_t tracepos, uint8_t *trace) {
    uint16_t next_records_datalen = *((uint16_t *)(trace + tracepos + sizeof(uint32_t) + sizeof(uint16_t)));
    return ((next_records_datalen & 0x8000) == 0x8000);
}

static bool merge_topaz_reader_frames(uint32_t timestamp, uint32_t *duration, uint16_t *tracepos, uint16_t traceLen,
                                      uint8_t *trace, uint8_t *frame, uint8_t *topaz_reader_command, uint16_t *data_len) {

#define MAX_TOPAZ_READER_CMD_LEN 16

    uint32_t last_timestamp = timestamp + *duration;

    if ((*data_len != 1) || (frame[0] == TOPAZ_WUPA) || (frame[0] == TOPAZ_REQA)) return false;

    memcpy(topaz_reader_command, frame, *data_len);

    while (!is_last_record(*tracepos, trace, traceLen) && !next_record_is_response(*tracepos, trace)) {
        uint32_t next_timestamp = *((uint32_t *)(trace + *tracepos));
        *tracepos += sizeof(uint32_t);
        uint16_t next_duration = *((uint16_t *)(trace + *tracepos));
        *tracepos += sizeof(uint16_t);
        uint16_t next_data_len = *((uint16_t *)(trace + *tracepos)) & 0x7FFF;
        *tracepos += sizeof(uint16_t);
        uint8_t *next_frame = (trace + *tracepos);
        *tracepos += next_data_len;
        if ((next_data_len == 1) && (*data_len + next_data_len <= MAX_TOPAZ_READER_CMD_LEN)) {
            memcpy(topaz_reader_command + *data_len, next_frame, next_data_len);
            *data_len += next_data_len;
            last_timestamp = next_timestamp + next_duration;
        } else {
            // rewind and exit
            *tracepos = *tracepos - next_data_len - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t);
            break;
        }
        uint16_t next_parity_len = (next_data_len - 1) / 8 + 1;
        *tracepos += next_parity_len;
    }

    *duration = last_timestamp - timestamp;

    return true;
}

static uint16_t printHexLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol) {
    // sanity check
    if (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) > traceLen) return traceLen;

    bool isResponse;
    uint16_t data_len, parity_len;
    uint32_t timestamp;

    timestamp = *((uint32_t *)(trace + tracepos));
    tracepos += 4;


    // currently we don't use duration, so we skip it
    tracepos += 2;

    data_len = *((uint16_t *)(trace + tracepos));
    tracepos += 2;

    if (data_len & 0x8000) {
        data_len &= 0x7fff;
        isResponse = true;
    } else {
        isResponse = false;
    }
    parity_len = (data_len - 1) / 8 + 1;

    if (tracepos + data_len + parity_len > traceLen) {
        return traceLen;
    }
    uint8_t *frame = trace + tracepos;
    tracepos += data_len;
    //currently we don't use parity bytes, so we skip it
    tracepos += parity_len;

    if (data_len == 0) {
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
            char line[(data_len * 3) + 1];
            char *ptr = &line[0];

            for (int j = 0; j < data_len ; j++) {
                ptr += sprintf(ptr, "%02x", frame[j]);
                ptr += sprintf(ptr, " ");
            }

            char data_len_str[5];
            char temp_str1[3] = {0};
            char temp_str2[3] = {0};

            sprintf(data_len_str, "%04x", data_len);
            strncat(temp_str1, data_len_str, 2);
            temp_str1[2] = '\0';
            strncat(temp_str2, data_len_str + 2, 2);
            temp_str2[2] = '\0';

            PrintAndLogEx(NORMAL, "0.%010u", timestamp);
            PrintAndLogEx(NORMAL, "000000 00 %s %s %s %s",
                          (isResponse ? "ff" : "fe"),
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
    if (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) > traceLen) return traceLen;

    bool isResponse;
    uint16_t data_len, parity_len;
    uint32_t duration, timestamp, first_timestamp, EndOfTransmissionTimestamp;
    uint8_t topaz_reader_command[9];
    char explanation[30] = {0};
    uint8_t mfData[32] = {0};
    size_t mfDataLen = 0;


    first_timestamp = *((uint32_t *)(trace));
    timestamp = *((uint32_t *)(trace + tracepos));
    tracepos += 4;

    duration = *((uint16_t *)(trace + tracepos));
    tracepos += 2;

    data_len = *((uint16_t *)(trace + tracepos));
    tracepos += 2;

    if (data_len & 0x8000) {
        data_len &= 0x7fff;
        isResponse = true;
    } else {
        isResponse = false;
    }
    parity_len = (data_len - 1) / 8 + 1;

    if (tracepos + data_len + parity_len > traceLen) {
        return traceLen;
    }
    uint8_t *frame = trace + tracepos;
    tracepos += data_len;
    uint8_t *parityBytes = trace + tracepos;
    tracepos += parity_len;

    if (protocol == TOPAZ && !isResponse) {
        // topaz reader commands come in 1 or 9 separate frames with 7 or 8 Bits each.
        // merge them:
        if (merge_topaz_reader_frames(timestamp, &duration, &tracepos, traceLen, trace, frame, topaz_reader_command, &data_len)) {
            frame = topaz_reader_command;
        }
    }

    //Check the CRC status
    uint8_t crcStatus = 2;

    if (data_len > 2) {
        switch (protocol) {
            case ICLASS:
                crcStatus = iclass_CRC_check(isResponse, frame, data_len);
                break;
            case ISO_14443B:
            case TOPAZ:
            case FELICA:
                crcStatus = !felica_CRC_check(frame + 2, data_len - 4);
                break;
            case PROTO_MIFARE:
                crcStatus = mifare_CRC_check(isResponse, frame, data_len);
                break;
            case ISO_14443A:
            case MFDES:
            case LTO:
                crcStatus = iso14443A_CRC_check(isResponse, frame, data_len);
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
            case PROTO_HITAG:
            default:
                break;
        }
    }
    //0 CRC-command, CRC not ok
    //1 CRC-command, CRC ok
    //2 Not crc-command

    //--- Draw the data column
    char line[18][110] = {{0}};

    for (int j = 0; j < data_len && j / 18 < 18; j++) {

        uint8_t parityBits = parityBytes[j >> 3];
        if (protocol != LEGIC
                && protocol != ISO_14443B
                && protocol != ISO_15693
                && protocol != ICLASS
                && protocol != ISO_7816_4
                && protocol != PROTO_HITAG
                && protocol != THINFILM
                && protocol != FELICA
                && protocol != LTO
                && (isResponse || protocol == ISO_14443A)
                && (oddparity8(frame[j]) != ((parityBits >> (7 - (j & 0x0007))) & 0x01))) {

            snprintf(line[j / 18] + ((j % 18) * 4), 110, "%02x! ", frame[j]);
        } else if (protocol == ICLASS  && isResponse == false) {
            uint8_t parity = 0;
            for (int i = 0; i < 6; i++) {
                parity ^= ((frame[0] >> i) & 1);
            }
            if (parity == ((frame[0] >> 7) & 1)) {
                snprintf(line[j / 18] + ((j % 18) * 4), 110, "%02x  ", frame[j]);
            } else {
                snprintf(line[j / 18] + ((j % 18) * 4), 110, "%02x! ", frame[j]);
            }

        } else {
            snprintf(line[j / 18] + ((j % 18) * 4), 110, "%02x  ", frame[j]);
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

    if (data_len == 0) {
        sprintf(line[0], "<empty trace - possible error>");
        return tracepos;
    }

    // Draw the CRC column
    const char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

    EndOfTransmissionTimestamp = timestamp + duration;

    // Always annotate LEGIC read/tag
    if (protocol == LEGIC)
        annotateLegic(explanation, sizeof(explanation), frame, data_len);

    if (protocol == PROTO_MIFARE)
        annotateMifare(explanation, sizeof(explanation), frame, data_len, parityBytes, parity_len, isResponse);

    if (protocol == FELICA)
        annotateFelica(explanation, sizeof(explanation), frame, data_len);

    if (!isResponse) {
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
            default:
                break;
        }
    }

    int num_lines = MIN((data_len - 1) / 18 + 1, 18);
    for (int j = 0; j < num_lines ; j++) {
        if (j == 0) {
            PrintAndLogEx(NORMAL, " %10u | %10u | %s |%-72s | %s| %s",
                          (timestamp - first_timestamp),
                          (EndOfTransmissionTimestamp - first_timestamp),
                          (isResponse ? "Tag" : "Rdr"),
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

    if (DecodeMifareData(frame, data_len, parityBytes, isResponse, mfData, &mfDataLen)) {
        memset(explanation, 0x00, sizeof(explanation));
        if (!isResponse) {
            annotateIso14443a(explanation, sizeof(explanation), mfData, mfDataLen);
        }
        uint8_t crcc = iso14443A_CRC_check(isResponse, mfData, mfDataLen);
        PrintAndLogEx(NORMAL, "            |            |  *  |%-72s | %-4s| %s",
                      sprint_hex_inrow_spaces(mfData, mfDataLen, 2),
                      (crcc == 0 ? "!crc" : (crcc == 1 ? " ok " : "    ")),
                      explanation);
    }

    if (is_last_record(tracepos, trace, traceLen)) return traceLen;

    if (showWaitCycles && !isResponse && next_record_is_response(tracepos, trace)) {
        uint32_t next_timestamp = *((uint32_t *)(trace + tracepos));
        PrintAndLogEx(NORMAL, " %10u | %10u | %s |fdt (Frame Delay Time): %d",
                      (EndOfTransmissionTimestamp - first_timestamp),
                      (next_timestamp - first_timestamp),
                      "   ",
                      (next_timestamp - EndOfTransmissionTimestamp));
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

    FILE *f = NULL;
    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_load();

    param_getstr(Cmd, 0, filename, sizeof(filename));

    if ((f = fopen(filename, "rb")) == NULL) {
        PrintAndLogEx(FAILED, "Could not open file " _YELLOW_("%s"), filename);
        return PM3_EIO;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        return PM3_EIO;
    }
    if (fsize < 4) {
        PrintAndLogEx(FAILED, "error, file is too small");
        fclose(f);
        return PM3_ESOFT;
    }

    if (trace)
        free(trace);

    trace = calloc(fsize, sizeof(uint8_t));
    if (!trace) {
        PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
        fclose(f);
        return PM3_EMALLOC;
    }

    size_t bytes_read = fread(trace, 1, fsize, f);
    traceLen = bytes_read;
    fclose(f);
    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = %lu bytes) loaded from file %s", traceLen, filename);
    return PM3_SUCCESS;
}

static int CmdTraceSave(const char *Cmd) {

    if (traceLen == 0) {
        PrintAndLogEx(WARNING, "trace is empty, nothing to save");
        return PM3_SUCCESS;
    }

    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_save();

    param_getstr(Cmd, 0, filename, sizeof(filename));
    saveFile(filename, ".bin", trace, traceLen);
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
            else if (strcmp(type, "hitag") == 0)    protocol = PROTO_HITAG;
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

    uint16_t tracepos = 0;

    // reserv some space.
    if (!trace) {
        trace = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
        if (trace == NULL) {
            PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
            return PM3_EMALLOC;
        }
    }

    if (isOnline) {
        // Query for the size of the trace,  downloading PM3_CMD_DATA_SIZE
        PacketResponseNG response;
        if (!GetFromDevice(BIG_BUF, trace, PM3_CMD_DATA_SIZE, 0, NULL, 0, &response, 4000, true)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        traceLen = response.oldarg[2];
        if (traceLen > PM3_CMD_DATA_SIZE) {
            uint8_t *p = realloc(trace, traceLen);
            if (p == NULL) {
                PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
                free(trace);
                return PM3_EMALLOC;
            }
            trace = p;
            if (!GetFromDevice(BIG_BUF, trace, traceLen, 0, NULL, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "command execution time out");
                free(trace);
                return PM3_ETIMEOUT;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = %lu bytes)", traceLen);
    PrintAndLogEx(INFO, "");

    /*
    if (protocol == FELICA) {
        printFelica(traceLen, trace);
    } */

    if (showHex) {
        while (tracepos < traceLen) {
            tracepos = printHexLine(tracepos, traceLen, trace, protocol);
        }
    } else {
        PrintAndLogEx(NORMAL, "Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
        if (protocol == ISO_14443A || protocol == PROTO_MIFARE || protocol == MFDES || protocol == TOPAZ || protocol == LTO)
            PrintAndLogEx(NORMAL, "ISO14443A - All times are in carrier periods (1/13.56MHz)");
        if (protocol == THINFILM)
            PrintAndLogEx(NORMAL, "Thinfilm - All times are in carrier periods (1/13.56MHz)");
        if (protocol == ICLASS)
            PrintAndLogEx(NORMAL, "iClass - Timings are not as accurate");
        if (protocol == LEGIC)
            PrintAndLogEx(NORMAL, "LEGIC - Reader Mode: Timings are in ticks (1us == 1.5ticks)\n"
                          "        Tag Mode: Timings are in sub carrier periods (1/212 kHz == 4.7us)");
        if (protocol == ISO_14443B)
            PrintAndLogEx(NORMAL, "ISO14443B"); // Timings ?
        if (protocol == ISO_15693)
            PrintAndLogEx(NORMAL, "ISO15693 - Timings are not as accurate");
        if (protocol == ISO_7816_4)
            PrintAndLogEx(NORMAL, "ISO7816-4 / Smartcard - Timings N/A yet");
        if (protocol == PROTO_HITAG)
            PrintAndLogEx(NORMAL, "Hitag2 / HitagS - Timings in ETU (8us)");
        if (protocol == FELICA)
            PrintAndLogEx(NORMAL, "ISO18092 / FeliCa - Timings are not as accurate");

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation");
        PrintAndLogEx(NORMAL, "------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------");

        ClearAuthData();
        while (tracepos < traceLen) {
            tracepos = printTraceLine(tracepos, traceLen, trace, protocol, showWaitCycles, markCRCBytes);

            if (kbd_enter_pressed())
                break;
        }
    }
    return PM3_SUCCESS;
}

