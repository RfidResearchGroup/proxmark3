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

static int CmdHelp(const char *Cmd);

// trace pointer
static uint8_t *trace;
long traceLen = 0;

int usage_trace_list() {
    PrintAndLogEx(NORMAL, "List protocol data in trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace list <protocol> [f][c| <0|1>");
    PrintAndLogEx(NORMAL, "    f      - show frame delay times as well");
    PrintAndLogEx(NORMAL, "    c      - mark CRC bytes");
    PrintAndLogEx(NORMAL, "    <0|1>  - use data from Tracebuffer, if not set, try reading data from tag.");
    PrintAndLogEx(NORMAL, "Supported <protocol> values:");
    PrintAndLogEx(NORMAL, "    raw    - just show raw data without annotations");
    PrintAndLogEx(NORMAL, "    14a    - interpret data as iso14443a communications");
    PrintAndLogEx(NORMAL, "    mf     - interpret data as iso14443a communications and decrypt crypto1 stream");
    PrintAndLogEx(NORMAL, "    14b    - interpret data as iso14443b communications");
    PrintAndLogEx(NORMAL, "    15     - interpret data as iso15693 communications");
    PrintAndLogEx(NORMAL, "    des    - interpret data as DESFire communications");
#ifdef WITH_EMV
    PrintAndLogEx(NORMAL, "    emv    - interpret data as EMV / communications");
#endif
    PrintAndLogEx(NORMAL, "    iclass - interpret data as iclass communications");
    PrintAndLogEx(NORMAL, "    topaz  - interpret data as topaz communications");
    PrintAndLogEx(NORMAL, "    7816   - interpret data as iso7816-4 communications");
    PrintAndLogEx(NORMAL, "    legic  - interpret data as LEGIC communications");
    PrintAndLogEx(NORMAL, "    felica - interpret data as ISO18092 / FeliCa communications");
    PrintAndLogEx(NORMAL, "    hitag  - interpret data as Hitag2 / HitagS communications");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace list 14a f");
    PrintAndLogEx(NORMAL, "        trace list iclass");
    return 0;
}
int usage_trace_load() {
    PrintAndLogEx(NORMAL, "Load protocol data from file to trace buffer.");
    PrintAndLogEx(NORMAL, "Usage:  trace load <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace load mytracefile.bin");
    return 0;
}
int usage_trace_save() {
    PrintAndLogEx(NORMAL, "Save protocol data from trace buffer to file.");
    PrintAndLogEx(NORMAL, "Usage:  trace save <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        trace save mytracefile.bin");
    return 0;
}

bool is_last_record(uint16_t tracepos, uint8_t *trace, uint16_t traceLen) {
    return (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) >= traceLen);
}

bool next_record_is_response(uint16_t tracepos, uint8_t *trace) {
    uint16_t next_records_datalen = *((uint16_t *)(trace + tracepos + sizeof(uint32_t) + sizeof(uint16_t)));
    return (next_records_datalen & 0x8000);
}

bool merge_topaz_reader_frames(uint32_t timestamp, uint32_t *duration, uint16_t *tracepos, uint16_t traceLen,
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

uint16_t printTraceLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol, bool showWaitCycles, bool markCRCBytes) {
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
                crcStatus = iso14443B_CRC_check(frame, data_len);
                break;
            case PROTO_MIFARE:
                crcStatus = mifare_CRC_check(isResponse, frame, data_len);
                break;
            case ISO_14443A:
            case MFDES:
                crcStatus = iso14443A_CRC_check(isResponse, frame, data_len);
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
                && protocol != ISO_7816_4
                && protocol != PROTO_HITAG
                && (isResponse || protocol == ISO_14443A)
                && (oddparity8(frame[j]) != ((parityBits >> (7 - (j & 0x0007))) & 0x01))) {

            snprintf(line[j / 18] + ((j % 18) * 4), 110, "%02x! ", frame[j]);
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
    char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

    EndOfTransmissionTimestamp = timestamp + duration;

    // Always annotate LEGIC read/tag
    if (protocol == LEGIC)
        annotateLegic(explanation, sizeof(explanation), frame, data_len);

    if (protocol == PROTO_MIFARE)
        annotateMifare(explanation, sizeof(explanation), frame, data_len, parityBytes, parity_len, isResponse);

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
    };

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

void printFelica(uint16_t traceLen, uint8_t *trace) {

    PrintAndLogEx(NORMAL, "ISO18092 / FeliCa - Timings are not as accurate");
    PrintAndLogEx(NORMAL, "    Gap | Src | Data                            | CRC      | Annotation        |");
    PrintAndLogEx(NORMAL, "--------|-----|---------------------------------|----------|-------------------|");
    uint16_t tracepos = 0;

    while (tracepos < traceLen) {

        if (tracepos + 3 >= traceLen) break;


        uint16_t gap = *((uint16_t *)(trace + tracepos));
        uint8_t crc_ok = trace[tracepos + 2];
        tracepos += 3;

        if (tracepos + 3 >= traceLen) break;

        uint16_t len = trace[tracepos + 2];

        //I am stripping SYNC
        tracepos += 3; //skip SYNC

        if (tracepos + len + 1 >= traceLen) break;

        uint8_t cmd = trace[tracepos];
        uint8_t isResponse = cmd & 1;

        char line[32][110] = {{0}};
        for (int j = 0; j < len + 1 && j / 8 < 32; j++) {
            snprintf(line[j / 8] + ((j % 8) * 4), 110, " %02x ", trace[tracepos + j]);
        }
        char expbuf[50];
        switch (cmd) {
            case FELICA_POLL_REQ:
                snprintf(expbuf, 49, "Poll Req");
                break;
            case FELICA_POLL_ACK:
                snprintf(expbuf, 49, "Poll Resp");
                break;

            case FELICA_REQSRV_REQ:
                snprintf(expbuf, 49, "Request Srvc Req");
                break;
            case FELICA_REQSRV_ACK:
                snprintf(expbuf, 49, "Request Srv Resp");
                break;

            case FELICA_RDBLK_REQ:
                snprintf(expbuf, 49, "Read block(s) Req");
                break;
            case FELICA_RDBLK_ACK:
                snprintf(expbuf, 49, "Read block(s) Resp");
                break;

            case FELICA_WRTBLK_REQ:
                snprintf(expbuf, 49, "Write block(s) Req");
                break;
            case FELICA_WRTBLK_ACK:
                snprintf(expbuf, 49, "Write block(s) Resp");
                break;
            case FELICA_SRCHSYSCODE_REQ:
                snprintf(expbuf, 49, "Search syscode Req");
                break;
            case FELICA_SRCHSYSCODE_ACK:
                snprintf(expbuf, 49, "Search syscode Resp");
                break;

            case FELICA_REQSYSCODE_REQ:
                snprintf(expbuf, 49, "Request syscode Req");
                break;
            case FELICA_REQSYSCODE_ACK:
                snprintf(expbuf, 49, "Request syscode Resp");
                break;

            case FELICA_AUTH1_REQ:
                snprintf(expbuf, 49, "Auth1 Req");
                break;
            case FELICA_AUTH1_ACK:
                snprintf(expbuf, 49, "Auth1 Resp");
                break;

            case FELICA_AUTH2_REQ:
                snprintf(expbuf, 49, "Auth2 Req");
                break;
            case FELICA_AUTH2_ACK:
                snprintf(expbuf, 49, "Auth2 Resp");
                break;

            case FELICA_RDSEC_REQ:
                snprintf(expbuf, 49, "Secure read Req");
                break;
            case FELICA_RDSEC_ACK:
                snprintf(expbuf, 49, "Secure read Resp");
                break;

            case FELICA_WRTSEC_REQ:
                snprintf(expbuf, 49, "Secure write Req");
                break;
            case FELICA_WRTSEC_ACK:
                snprintf(expbuf, 49, "Secure write Resp");
                break;

            case FELICA_REQSRV2_REQ:
                snprintf(expbuf, 49, "Request Srvc v2 Req");
                break;
            case FELICA_REQSRV2_ACK:
                snprintf(expbuf, 49, "Request Srvc v2 Resp");
                break;

            case FELICA_GETSTATUS_REQ:
                snprintf(expbuf, 49, "Get status Req");
                break;
            case FELICA_GETSTATUS_ACK:
                snprintf(expbuf, 49, "Get status Resp");
                break;

            case FELICA_OSVER_REQ:
                snprintf(expbuf, 49, "Get OS Version Req");
                break;
            case FELICA_OSVER_ACK:
                snprintf(expbuf, 49, "Get OS Version Resp");
                break;

            case FELICA_RESET_MODE_REQ:
                snprintf(expbuf, 49, "Reset mode Req");
                break;
            case FELICA_RESET_MODE_ACK:
                snprintf(expbuf, 49, "Reset mode Resp");
                break;

            case FELICA_AUTH1V2_REQ:
                snprintf(expbuf, 49, "Auth1 v2 Req");
                break;
            case FELICA_AUTH1V2_ACK:
                snprintf(expbuf, 49, "Auth1 v2 Resp");
                break;

            case FELICA_AUTH2V2_REQ:
                snprintf(expbuf, 49, "Auth2 v2 Req");
                break;
            case FELICA_AUTH2V2_ACK:
                snprintf(expbuf, 49, "Auth2 v2 Resp");
                break;

            case FELICA_RDSECV2_REQ:
                snprintf(expbuf, 49, "Secure read v2 Req");
                break;
            case FELICA_RDSECV2_ACK:
                snprintf(expbuf, 49, "Secure read v2 Resp");
                break;
            case FELICA_WRTSECV2_REQ:
                snprintf(expbuf, 49, "Secure write v2 Req");
                break;
            case FELICA_WRTSECV2_ACK:
                snprintf(expbuf, 49, "Secure write v2 Resp");
                break;

            case FELICA_UPDATE_RNDID_REQ:
                snprintf(expbuf, 49, "Update IDr Req");
                break;
            case FELICA_UPDATE_RNDID_ACK:
                snprintf(expbuf, 49, "Update IDr Resp");
                break;
            default:
                snprintf(expbuf, 49, "Unknown");
                break;
        }

        int num_lines = MIN((len) / 16 + 1, 16);
        for (int j = 0; j < num_lines ; j++) {
            if (j == 0) {
                PrintAndLogEx(NORMAL, "%7d | %s |%-32s |%02x %02x %s| %s",
                              gap,
                              (isResponse ? "Tag" : "Rdr"),
                              line[j],
                              trace[tracepos + len],
                              trace[tracepos + len + 1],
                              (crc_ok) ? "OK" : "NG",
                              expbuf);
            } else {
                PrintAndLogEx(NORMAL, "        |     |%-32s |        |    ", line[j]);
            }
        }
        tracepos += len + 1;
    }
    PrintAndLogEx(NORMAL, "");
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

int CmdTraceList(const char *Cmd) {

    clearCommandBuffer();

    bool showWaitCycles = false;
    bool markCRCBytes = false;
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
            if (strcmp(type,     "iclass") == 0)    protocol = ICLASS;
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
    if (!trace)
        trace = calloc(USB_CMD_DATA_SIZE, sizeof(uint8_t));

    if (isOnline) {
        // Query for the size of the trace,  downloading USB_CMD_DATA_SIZE
        UsbCommand response;
        if (!GetFromDevice(BIG_BUF, trace, USB_CMD_DATA_SIZE, 0, &response, 4000, true)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return 1;
        }

        traceLen = response.arg[2];
        if (traceLen > USB_CMD_DATA_SIZE) {
            uint8_t *p = realloc(trace, traceLen);
            if (p == NULL) {
                PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
                free(trace);
                return 2;
            }
            trace = p;
            if (!GetFromDevice(BIG_BUF, trace, traceLen, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "command execution time out");
                free(trace);
                return 3;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = %d bytes)", traceLen);
    PrintAndLogEx(INFO, "");
    if (protocol == FELICA) {
        printFelica(traceLen, trace);
    } else {
        PrintAndLogEx(NORMAL, "Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
        if (protocol == ISO_14443A || protocol == PROTO_MIFARE)
            PrintAndLogEx(NORMAL, "iso14443a - All times are in carrier periods (1/13.56Mhz)");
        if (protocol == ICLASS)
            PrintAndLogEx(NORMAL, "iClass - Timings are not as accurate");
        if (protocol == LEGIC)
            PrintAndLogEx(NORMAL, "LEGIC - Reader Mode: Timings are in ticks (1us == 1.5ticks)\n"
                          "        Tag Mode: Timings are in sub carrier periods (1/212 kHz == 4.7us)");
        if (protocol == ISO_15693)
            PrintAndLogEx(NORMAL, "ISO15693 - Timings are not as accurate");
        if (protocol == ISO_7816_4)
            PrintAndLogEx(NORMAL, "ISO7816-4 / Smartcard - Timings N/A yet");
        if (protocol == PROTO_HITAG)
            PrintAndLogEx(NORMAL, "Hitag2 / HitagS - Timings in ETU (8us)");

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation");
        PrintAndLogEx(NORMAL, "------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------");

        ClearAuthData();
        while (tracepos < traceLen) {
            tracepos = printTraceLine(tracepos, traceLen, trace, protocol, showWaitCycles, markCRCBytes);
        }
    }
    return 0;
}

int CmdTraceLoad(const char *Cmd) {

    FILE *f = NULL;
    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_load();

    param_getstr(Cmd, 0, filename, sizeof(filename));

    if ((f = fopen(filename, "rb")) == NULL) {
        PrintAndLogEx(FAILED, "Could not open file %s", filename);
        return 0;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        return 3;
    }
    if (fsize < 4) {
        PrintAndLogEx(FAILED, "error, file is too small");
        fclose(f);
        return 4;
    }

    if (trace)
        free(trace);

    trace = calloc(fsize, sizeof(uint8_t));
    if (!trace) {
        PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
        fclose(f);
        return 2;
    }

    size_t bytes_read = fread(trace, 1, fsize, f);
    traceLen = bytes_read;
    fclose(f);
    PrintAndLogEx(SUCCESS, "Recorded Activity (TraceLen = %d bytes) loaded from file %s", traceLen, filename);
    return 0;
}

int CmdTraceSave(const char *Cmd) {

    if (traceLen == 0) {
        PrintAndLogEx(WARNING, "trace is empty, nothing to save");
        return 0;
    }

    char filename[FILE_PATH_SIZE];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_trace_save();

    param_getstr(Cmd, 0, filename, sizeof(filename));
    saveFile(filename, "bin", trace, traceLen);
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,          1, "This help"},
    {"list",    CmdTraceList,     1, "List protocol data in trace buffer"},
    {"load",    CmdTraceLoad,     1, "Load trace from file"},
    {"save",    CmdTraceSave,     1, "Save trace buffer to file"},
    {NULL, NULL, 0, NULL}
};

int CmdTrace(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
