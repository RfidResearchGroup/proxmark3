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
// utilities
//-----------------------------------------------------------------------------

// ensure gmtime_r is available even with -std=c99; must be included before
#if !defined(_WIN32) && !defined(__APPLE__)
#define _POSIX_C_SOURCE 200112L
#endif

#include "util.h"

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h> // Mingw

#include "ui.h"     // PrintAndLog

#define UTIL_BUFFER_SIZE_SPRINT 8196
// global client debug variable
uint8_t g_debugMode = 0;
// global client disable logging variable
uint8_t g_printAndLog = PRINTANDLOG_PRINT | PRINTANDLOG_LOG;
// global client tell if a pending prompt is present
bool g_pendingPrompt = false;
// global CPU core count override
int g_numCPUs = 0;

#ifdef _WIN32
#include <windows.h>
#endif

#define MAX_BIN_BREAK_LENGTH   (3072 + 384 + 1)

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>

int kbd_enter_pressed(void) {
    int flags;
    if ((flags = fcntl(STDIN_FILENO, F_GETFL, 0)) < 0) {
        PrintAndLogEx(ERR, "fcntl failed in kbd_enter_pressed");
        return -1;
    }
    //non-blocking
    flags |= O_NONBLOCK;
    if (fcntl(STDIN_FILENO, F_SETFL, flags) < 0) {
        PrintAndLogEx(ERR, "fcntl failed in kbd_enter_pressed");
        return -1;
    }
    int c;
    int ret = 0;
    do { //get all available chars
        c = getchar();
        ret |= c == '\n';
    } while (c != EOF);
    //blocking
    flags &= ~O_NONBLOCK;
    if (fcntl(STDIN_FILENO, F_SETFL, flags) < 0) {
        PrintAndLogEx(ERR, "fcntl failed in kbd_enter_pressed");
        return -1;
    }
    return ret;
}

#else

#include <conio.h>
int kbd_enter_pressed(void) {
    int ret = 0;
    while (kbhit()) {
        ret |= getch() == '\r';
    }
    return ret;
}
#endif

static char b2s(uint8_t v, bool uppercase) {
    // clear higher bits
    v &= 0xF;

    switch (v) {
        case 0xA :
            return (uppercase ? 'A' : 'a') ;
        case 0xB :
            return (uppercase ? 'B' : 'b') ;
        case 0xC :
            return (uppercase ? 'C' : 'c') ;
        case 0xD :
            return (uppercase ? 'D' : 'd') ;
        case 0xE :
            return (uppercase ? 'E' : 'e') ;
        case 0xF :
            return (uppercase ? 'F' : 'f') ;
        default:
            return (char)(v + 0x30);
    }
}

// create filename on hex uid.
// param *fn   -  pointer to filename char array
// param *uid  -  pointer to uid byte array
// param *ext  -  ".log"
// param uidlen - length of uid array.
void FillFileNameByUID(char *filenamePrefix, const uint8_t *uid, const char *ext, const int uidlen) {
    if (filenamePrefix == NULL || uid == NULL || ext == NULL) {
        return;
    }

    int len = strlen(filenamePrefix);

    for (int j = 0; j < uidlen; j++) {
        // This is technically not the safest option, but there is no way to make this work without changing the function signature
        // Possibly todo for future PR, but given UID lenghts are defined by program and not variable, should not be an issue
        snprintf(filenamePrefix + len + j * 2, 3, "%02X", uid[j]);
    }

    strcat(filenamePrefix, ext);
}

// fill buffer from structure [{uint8_t data, size_t length},...]
int FillBuffer(uint8_t *data, size_t maxDataLength, size_t *dataLength, ...) {
    *dataLength = 0;
    va_list valist;
    va_start(valist, dataLength);

    uint8_t *vdata = NULL;

    do {
        vdata = va_arg(valist, uint8_t *);
        if (!vdata)
            break;

        size_t vlength = va_arg(valist, size_t);
        if (*dataLength + vlength >  maxDataLength) {
            va_end(valist);
            return 1;
        }

        memcpy(&data[*dataLength], vdata, vlength);
        *dataLength += vlength;

    } while (vdata);

    va_end(valist);

    return 0;
}

bool CheckStringIsHEXValue(const char *value) {
    for (size_t i = 0; i < strlen(value); i++)
        if (!isxdigit(value[i]))
            return false;

    if (strlen(value) % 2)
        return false;

    return true;
}

void ascii_to_buffer(uint8_t *buf, const uint8_t *hex_data, const size_t hex_len,
                     const size_t hex_max_len, const size_t min_str_len) {

    if (buf == NULL) return;

    char *tmp_base = (char *)buf;
    char *tmp = tmp_base;

    size_t max_len = (hex_len > hex_max_len) ? hex_max_len : hex_len;

    size_t i = 0;
    for (i = 0; i < max_len; ++i, tmp++) {
        char c = hex_data[i];
        *tmp = ((c < 32) || (c == 127)) ? '.' : c;
    }

    size_t m = (min_str_len > i) ? min_str_len : 0;
    if (m > hex_max_len)
        m = hex_max_len;

    for (; i < m; i++, tmp++)
        *tmp = ' ';

    // remove last space
    *tmp = '\0';
}

void hex_to_buffer(uint8_t *buf, const uint8_t *hex_data, const size_t hex_len, const size_t hex_max_len,
                   const size_t min_str_len, const size_t spaces_between, bool uppercase) {

    // sanity check
    if (buf == NULL || hex_len < 1)
        return;

    // 1. hex string length.
    // 2. byte array to be converted to string
    //

    size_t max_byte_len = (hex_len > hex_max_len) ? hex_max_len : hex_len;
    size_t max_str_len = (max_byte_len * (2 + spaces_between)) + 1;
    char *tmp_base = (char *)buf;
    char *tmp = tmp_base;

    size_t i;
    for (i = 0; (i < max_byte_len) && (max_str_len > strlen(tmp_base)) ; ++i) {

        *(tmp++) = b2s((hex_data[i] >> 4), uppercase);
        *(tmp++) = b2s(hex_data[i], uppercase);

        for (size_t j = 0; j < spaces_between; j++)
            *(tmp++) = ' ';
    }

    i *= (2 + spaces_between);

    size_t m = (min_str_len > i) ? min_str_len : 0;
    if (m > hex_max_len)
        m = hex_max_len;

    while (m--)
        *(tmp++) = ' ';

    // remove last space
    *tmp = '\0';

}

// printing and converting functions
void print_hex(const uint8_t *data, const size_t len) {
    if (data == NULL || len == 0) return;

    for (size_t i = 0; i < len; i++)
        PrintAndLogEx(NORMAL, "%02x " NOLF, data[i]);

    PrintAndLogEx(NORMAL, "");
}

void print_hex_break(const uint8_t *data, const size_t len, uint8_t breaks) {
    if (data == NULL || len == 0 || breaks == 0) return;

    uint16_t rownum = 0;
    int i;
    for (i = 0; i < len; i += breaks, rownum++) {
        if (len - i < breaks) { // incomplete block, will be treated out of the loop
            break;
        }
        PrintAndLogEx(INFO, "%02u | %s", rownum, sprint_hex_ascii(data + i, breaks));
    }

    // the last odd bytes
    uint8_t mod = len % breaks;

    if (mod) {
        char buf[UTIL_BUFFER_SIZE_SPRINT + 3] = {0};
        hex_to_buffer((uint8_t *)buf, data + i, mod, (sizeof(buf) - 1), 0, 1, true);

        // add the spaces...
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%*s", ((breaks - mod) * 3), " ");
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "| %s", sprint_ascii(data + i, mod));
        PrintAndLogEx(INFO, "%02u | %s", rownum, buf);
    }
}

void print_hex_noascii_break(const uint8_t *data, const size_t len, uint8_t breaks) {
    if (data == NULL || len == 0 || breaks == 0) return;

    int i;
    for (i = 0; i < len; i += breaks) {
        if (len - i < breaks) { // incomplete block, will be treated out of the loop
            break;
        }
        PrintAndLogEx(INFO, "%s", sprint_hex_inrow_spaces(data + i, breaks, 0));
    }

    // the last odd bytes
    uint8_t mod = len % breaks;

    if (mod) {
        char buf[UTIL_BUFFER_SIZE_SPRINT + 3] = {0};
        hex_to_buffer((uint8_t *)buf, data + i, mod, (sizeof(buf) - 1), 0, 0, true);

        // add the spaces...
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%*s", ((breaks - mod) * 3), " ");
        PrintAndLogEx(INFO, "%s", buf);
    }
}

static void print_buffer_ex(const uint8_t *data, const size_t len, int level, uint8_t breaks) {

    // sanity checks
    if ((data == NULL) || (len < 1))
        return;

    char buf[UTIL_BUFFER_SIZE_SPRINT + 3] = {0};
    int i;
    for (i = 0; i < len; i += breaks) {

        memset(buf, 0x00, sizeof(buf));

        if (len - i < breaks) { // incomplete block, will be treated out of the loop
            break;
        }

        // (16 * 3) + (16) +  + 1
        snprintf(buf, sizeof(buf), "%*s%02x: ", (level * 4), " ", i);

        hex_to_buffer((uint8_t *)(buf + strlen(buf)), data + i, breaks, (sizeof(buf) - strlen(buf) - 1), 0, 1, true);

        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "| %s", sprint_ascii(data + i, breaks));

        PrintAndLogEx(INFO, "%s", buf);
    }

    // the last odd bytes
    uint8_t mod = len % breaks;

    if (mod) {
        snprintf(buf, sizeof(buf), "%*s%02x: ", (level * 4), " ", i);
        hex_to_buffer((uint8_t *)(buf + strlen(buf)), data + i, mod, (sizeof(buf) - strlen(buf) - 1), 0, 1, true);

        // add the spaces...
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%*s", ((breaks - mod) * 3), " ");

        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "| %s", sprint_ascii(data + i, mod));
        PrintAndLogEx(INFO, "%s", buf);
    }
}

void print_buffer(const uint8_t *data, const size_t len, int level) {
    print_buffer_ex(data, len, level, 16);
}

void print_buffer_with_offset(const uint8_t *data, const size_t len, int offset, bool print_header) {
    if (print_header) {
        PrintAndLogEx(INFO, " Offset  | Data                                            | Ascii");
        PrintAndLogEx(INFO, "----------------------------------------------------------------------------");
    }

    for (uint32_t i = 0; i < len; i += 16) {
        uint32_t l = len - i;
        PrintAndLogEx(INFO, "%3d/0x%02X | %s" NOLF, offset + i, offset + i, sprint_hex(&data[i], l > 16 ? 16 : l));
        if (l < 16)
            PrintAndLogEx(NORMAL, "%*s" NOLF, 3 * (16 - l), " ");
        PrintAndLogEx(NORMAL, "| %s", sprint_ascii(&data[i], l > 16 ? 16 : l));
    }
}

void print_blocks(uint32_t *data, size_t len) {
    PrintAndLogEx(SUCCESS, "Blk | Data ");
    PrintAndLogEx(SUCCESS, "----+------------");

    if (!data) {
        PrintAndLogEx(ERR, "..empty data");
    } else {
        for (size_t i = 0; i < len; i++)
            PrintAndLogEx(SUCCESS, " %02zd | %08X", i, data[i]);
    }
}

char *sprint_hex(const uint8_t *data, const size_t len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, 0, 1, true);
    return buf;
}

char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, min_str_len, 0, true);
    return buf;
}

char *sprint_hex_inrow(const uint8_t *data, const size_t len) {
    return sprint_hex_inrow_ex(data, len, 0);
}

char *sprint_hex_inrow_spaces(const uint8_t *data, const size_t len, size_t spaces_between) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, 0, spaces_between, true);
    return buf;
}

char *sprint_bytebits_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks) {

    // make sure we don't go beyond our char array memory
    size_t rowlen = (len > MAX_BIN_BREAK_LENGTH) ? MAX_BIN_BREAK_LENGTH : len;

    // 3072 + end of line characters if broken at 8 bits
    static char buf[MAX_BIN_BREAK_LENGTH] = {0};
    memset(buf, 0, sizeof(buf));

    char *tmp = buf;

    // loop through the out_index to make sure we don't go too far
    for (int i = 0; i < rowlen; i++) {

        char c = data[i];
        // manchester wrong bit marker
        if (c == 7) {
            c = '.';
        } else if (c < 2) {
            c += '0';
        } else {
            PrintAndLogEx(ERR, "Invalid data passed to sprint_bytebits_bin_break()");
            return buf;
        }

        *(tmp++) = c;

        // check if a line break is needed and we have room to print it in our array
        if (breaks > 1) {
            if (((i + 1) % breaks) == 0) {

                *(tmp++) = '\n';
            }
        }
    }
    return buf;
}
/*
void sprint_bin_break_ex(uint8_t *src, size_t srclen, char *dest , uint8_t breaks) {
    if ( src == NULL ) return;
    if ( srclen < 1 ) return;

    // make sure we don't go beyond our char array memory
    size_t in_index = 0, out_index = 0;
    int rowlen;
    if (breaks==0)
        rowlen = ( len > MAX_BIN_BREAK_LENGTH ) ? MAX_BIN_BREAK_LENGTH : len;
    else
        rowlen = ( len+(len/breaks) > MAX_BIN_BREAK_LENGTH ) ? MAX_BIN_BREAK_LENGTH : len+(len/breaks);

    PrintAndLogEx(NORMAL, "(sprint_bin_break) rowlen %d", rowlen);

    // 3072 + end of line characters if broken at 8 bits
    dest = (char *)calloc(MAX_BIN_BREAK_LENGTH, sizeof(uint8_t));
    if (dest == NULL) return;

    //clear memory
    memset(dest, 0x00, sizeof(dest));

    // loop through the out_index to make sure we don't go too far
    for (out_index=0; out_index < rowlen-1; out_index++) {
        // set character
        sprintf(dest++, "%u", src[in_index]);
        // check if a line break is needed and we have room to print it in our array
        if ( (breaks > 0) && !((in_index+1) % breaks) && (out_index+1 != rowlen) ) {
            // increment and print line break
            out_index++;
            sprintf(dest++, "%s","\n");
        }
        in_index++;
    }
    // last char.
    sprintf(dest++, "%u", src[in_index]);
}
*/

char *sprint_bytebits_bin(const uint8_t *data, const size_t len) {
    return sprint_bytebits_bin_break(data, len, 0);
}

char *sprint_bin(const uint8_t *data, const size_t len) {
    size_t binlen = (len * 8 > MAX_BIN_BREAK_LENGTH) ? MAX_BIN_BREAK_LENGTH : len * 8;
    static uint8_t buf[MAX_BIN_BREAK_LENGTH] = {0};
    bytes_to_bytebits(data, binlen / 8, buf);
    return sprint_bytebits_bin_break(buf, binlen, 0);
}

char *sprint_hex_ascii(const uint8_t *data, const size_t len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT + 20] = {0};
    memset(buf, 0x00, sizeof(buf));

    char *tmp = buf;
    size_t max_len = (len > 1010) ? 1010 : len;

    int ret = snprintf(buf, sizeof(buf) - 1, "%s| ", sprint_hex(data, max_len));
    if (ret < 0) {
        goto out;
    }

    size_t i = 0;
    size_t pos = (max_len * 3) + 2;

    while (i < max_len) {
        char c = data[i];
        tmp[pos + i]  = ((c < 32) || (c == 127)) ? '.' : c;
        ++i;
    }
out:
    return buf;
}

char *sprint_ascii_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    memset(buf, 0x00, sizeof(buf));

    char *tmp = buf;
    size_t max_len = (len > 1010) ? 1010 : len;
    size_t i = 0;

    while (i < max_len) {
        char c = data[i];
        tmp[i] = ((c < 32) || (c == 127)) ? '.' : c;
        ++i;
    }

    size_t m = min_str_len > i ? min_str_len : 0;
    for (; i < m; ++i)
        tmp[i] = ' ';

    return buf;
}
char *sprint_ascii(const uint8_t *data, const size_t len) {
    return sprint_ascii_ex(data, len, 0);
}

int hex_to_bytes(const char *hexValue, uint8_t *bytesValue, size_t maxBytesValueLen) {
    char buf[4] = {0};
    int indx = 0;
    int bytesValueLen = 0;
    while (hexValue[indx]) {
        if (hexValue[indx] == '\t' || hexValue[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(hexValue[indx])) {
            buf[strlen(buf)] = hexValue[indx];
        } else {
            // if we have symbols other than spaces and hex
            return -1;
        }

        if (maxBytesValueLen && bytesValueLen >= maxBytesValueLen) {
            // if we don't have space in buffer and have symbols to translate
            return -2;
        }

        if (strlen(buf) >= 2) {
            uint32_t temp = 0;
            sscanf(buf, "%x", &temp);
            bytesValue[bytesValueLen] = (uint8_t)(temp & 0xff);
            memset(buf, 0, sizeof(buf));
            bytesValueLen++;
        }

        indx++;
    }

    if (strlen(buf) > 0)
        //error when not completed hex bytes
        return -3;

    return bytesValueLen;
}

// takes a number (uint64_t) and creates a binarray in dest.
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = n & 1;
        n >>= 1;
    }
}

// least significant bit (lsb) first
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest) {
    for (size_t i = 0 ; i < len ; ++i) {
        dest[i] =  n & 1;
        n >>= 1;
    }
}

void bytes_to_bytebits(const void *src, const size_t srclen, void *dest) {

    uint8_t *s = (uint8_t *)src;
    uint8_t *d = (uint8_t *)dest;

    uint32_t i = srclen * 8;
    size_t j = srclen;
    while (j--) {
        uint8_t b = s[j];
        d[--i] = (b >> 0) & 1;
        d[--i] = (b >> 1) & 1;
        d[--i] = (b >> 2) & 1;
        d[--i] = (b >> 3) & 1;
        d[--i] = (b >> 4) & 1;
        d[--i] = (b >> 5) & 1;
        d[--i] = (b >> 6) & 1;
        d[--i] = (b >> 7) & 1;
    }
}

// aa,bb,cc,dd,ee,ff,gg,hh, ii,jj,kk,ll,mm,nn,oo,pp
// to
// hh,gg,ff,ee,dd,cc,bb,aa, pp,oo,nn,mm,ll,kk,jj,ii
// up to 64 bytes or 512 bits
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize) {
    static uint8_t buf[64] = {0};
    memset(buf, 0x00, 64);
    uint8_t *tmp = buf;
    for (uint8_t block = 0; block < (uint8_t)(len / blockSize); block++) {
        for (size_t i = 0; i < blockSize; i++) {
            tmp[i + (blockSize * block)] = src[(blockSize - 1 - i) + (blockSize * block)];
        }
    }
    return buf;
}

// takes a uint8_t src array, for len items and reverses the byte order in blocksizes (8,16,32,64),
// returns: the dest array contains the reordered src array.
void SwapEndian64ex(const uint8_t *src, const size_t len, const uint8_t blockSize, uint8_t *dest) {
    for (uint8_t block = 0; block < (uint8_t)(len / blockSize); block++) {
        for (size_t i = 0; i < blockSize; i++) {
            dest[i + (blockSize * block)] = src[(blockSize - 1 - i) + (blockSize * block)];
        }
    }
}

//  -------------------------------------------------------------------------
//  string parameters lib
//  -------------------------------------------------------------------------

//  -------------------------------------------------------------------------
//  line     - param line
//  bg, en   - symbol numbers in param line of beginning and ending parameter
//  paramnum - param number (from 0)
//  -------------------------------------------------------------------------
int param_getptr(const char *line, int *bg, int *en, int paramnum) {
    int i;
    int len = strlen(line);

    *bg = 0;
    *en = 0;

    // skip spaces
    while (line[*bg] == ' ' || line[*bg] == '\t')(*bg)++;
    if (*bg >= len) {
        return 1;
    }

    for (i = 0; i < paramnum; i++) {
        while (line[*bg] != ' ' && line[*bg] != '\t' && line[*bg] != '\0')(*bg)++;
        while (line[*bg] == ' ' || line[*bg] == '\t')(*bg)++;

        if (line[*bg] == '\0') return 1;
    }

    *en = *bg;
    while (line[*en] != ' ' && line[*en] != '\t' && line[*en] != '\0')(*en)++;

    (*en)--;

    return 0;
}

int param_getlength(const char *line, int paramnum) {
    int bg, en;

    if (param_getptr(line, &bg, &en, paramnum)) return 0;

    return en - bg + 1;
}

char param_getchar(const char *line, int paramnum) {
    return param_getchar_indx(line, 0, paramnum);
}

char param_getchar_indx(const char *line, int indx, int paramnum) {
    int bg, en;

    if (param_getptr(line, &bg, &en, paramnum)) return 0x00;

    if (bg + indx > en)
        return '\0';

    return line[bg + indx];
}

uint8_t param_get8(const char *line, int paramnum) {
    return param_get8ex(line, paramnum, 0, 10);
}

/**
 * @brief Reads a decimal integer (actually, 0-254, not 255)
 * @param line
 * @param paramnum
 * @return -1 if error
 */
uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination) {
    uint8_t val =  param_get8ex(line, paramnum, 255, 10);
    if ((int8_t) val == -1) return 1;
    (*destination) = val;
    return 0;
}
/**
 * @brief Checks if param is decimal
 * @param line
 * @param paramnum
 * @return
 */
uint8_t param_isdec(const char *line, int paramnum) {
    int bg, en;
    //TODO, check more thorougly
    if (!param_getptr(line, &bg, &en, paramnum)) return 1;
    // return strtoul(&line[bg], NULL, 10) & 0xff;

    return 0;
}

uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base) {
    int bg, en;
    if (!param_getptr(line, &bg, &en, paramnum))
        return strtoul(&line[bg], NULL, base) & 0xff;
    else
        return deflt;
}

uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base) {
    int bg, en;
    if (!param_getptr(line, &bg, &en, paramnum))
        return strtoul(&line[bg], NULL, base);
    else
        return deflt;
}

uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base) {
    int bg, en;
    if (!param_getptr(line, &bg, &en, paramnum))
        return strtoull(&line[bg], NULL, base);
    else
        return deflt;
}

float param_getfloat(const char *line, int paramnum, float deflt) {
    int bg, en;
    if (!param_getptr(line, &bg, &en, paramnum))
        return strtof(&line[bg], NULL);
    else
        return deflt;
}

int param_gethex(const char *line, int paramnum, uint8_t *data, int hexcnt) {
    int bg, en, i;
    uint32_t temp;

    if (hexcnt & 1) return 1;

    if (param_getptr(line, &bg, &en, paramnum)) return 1;

    if (en - bg + 1 != hexcnt) return 1;

    for (i = 0; i < hexcnt; i += 2) {
        if (!(isxdigit(line[bg + i]) && isxdigit(line[bg + i + 1]))) return 1;

        sscanf((char[]) {line[bg + i], line[bg + i + 1], 0}, "%X", &temp);
        data[i / 2] = temp & 0xff;
    }

    return 0;
}
int param_gethex_ex(const char *line, int paramnum, uint8_t *data, int *hexcnt) {
    int bg, en, i;
    uint32_t temp;

    if (param_getptr(line, &bg, &en, paramnum)) return 1;

    *hexcnt = en - bg + 1;
    if (*hexcnt % 2) //error if not complete hex bytes
        return 1;

    for (i = 0; i < *hexcnt; i += 2) {
        if (!(isxdigit(line[bg + i]) && isxdigit(line[bg + i + 1]))) return 1;

        sscanf((char[]) {line[bg + i], line[bg + i + 1], 0}, "%X", &temp);
        data[i / 2] = temp & 0xff;
    }

    return 0;
}

int param_gethex_to_eol(const char *line, int paramnum, uint8_t *data, int maxdatalen, int *datalen) {

    int bg, en;

    if (param_getptr(line, &bg, &en, paramnum))
        return 1;

    *datalen = 0;
    char buf[5] = {0};

    int indx = bg;
    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
            return 1;
        }

        if (*datalen >= maxdatalen) {
            // if we don't have space in buffer and have symbols to translate
            return 2;
        }

        if (strlen(buf) >= 2) {
            uint32_t temp = 0;
            sscanf(buf, "%x", &temp);
            data[*datalen] = (uint8_t)(temp & 0xFF);
            *buf = 0;
            (*datalen)++;
        }

        indx++;
    }

    if (strlen(buf) > 0)
        //error when not completed hex bytes
        return 3;

    return 0;
}

int param_getbin_to_eol(const char *line, int paramnum, uint8_t *data, int maxdatalen, int *datalen) {
    int bg, en;
    if (param_getptr(line, &bg, &en, paramnum)) {
        return 1;
    }

    *datalen = 0;
    char buf[5] = {0};
    int indx = bg;
    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (line[indx] == '0' || line[indx] == '1') {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and 0/1
            return 1;
        }

        if (*datalen >= maxdatalen) {
            // if we don't have space in buffer and have symbols to translate
            return 2;
        }

        if (strlen(buf) > 0) {
            uint32_t temp = 0;
            sscanf(buf, "%d", &temp);
            data[*datalen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            (*datalen)++;
        }

        indx++;
    }
    return 0;
}

int param_getstr(const char *line, int paramnum, char *str, size_t buffersize) {
    int bg, en;

    if (param_getptr(line, &bg, &en, paramnum)) {
        return 0;
    }

    // Prevent out of bounds errors
    if (en - bg + 1 >= buffersize) {
        PrintAndLogEx(ERR, "out of bounds error: want %d bytes have %zu bytes\n", en - bg + 1 + 1, buffersize);
        return 0;
    }

    memcpy(str, line + bg, en - bg + 1);
    str[en - bg + 1] = 0;

    return en - bg + 1;
}

/*
The following methods comes from Rfidler sourcecode.
https://github.com/ApertureLabsLtd/RFIDler/blob/master/firmware/Pic32/RFIDler.X/src/
*/
// convert hex to sequence of 0/1 bit values
// returns number of bits converted
int hextobinarray(char *target, char *source) {
    return hextobinarray_n(target, source, strlen(source));
}

int hextobinarray_n(char *target, char *source, int sourcelen) {
    int i, count = 0;
    char *start = source;
    // process 4 bits (1 hex digit) at a time
    while (sourcelen--) {
        char x = *(source++);
        // capitalize
        if (x >= 'a' && x <= 'f') {
            x -= 32;
        }
        // convert to numeric value
        if (x >= '0' && x <= '9') {
            x -= '0';
        } else if (x >= 'A' && x <= 'F') {
            x -= 'A' - 10;
        } else {
            PrintAndLogEx(INFO, "(hextobinarray) discovered unknown character %c %d at idx %d of %s", x, x, (int16_t)(source - start), start);
            return 0;
        }
        // output
        for (i = 0 ; i < 4 ; ++i, ++count) {
            *(target++) = (x >> (3 - i)) & 1;
        }
    }

    return count;
}

// convert hex to human readable binary string
int hextobinstring(char *target, char *source) {
    return hextobinstring_n(target, source, strlen(source));
}

int hextobinstring_n(char *target, char *source, int sourcelen) {
    int length = hextobinarray_n(target, source, sourcelen);
    if (length == 0) {
        return 0;
    }
    binarraytobinstring(target, target, length);
    return length;
}

// convert binary array of 0x00/0x01 values to hex
// return number of bits converted
int binarraytohex(char *target, const size_t targetlen, const char *source, size_t srclen) {
    uint8_t i = 0, x = 0;
    uint32_t t = 0; // written target chars
    uint32_t r = 0; // consumed bits
    uint8_t w = 0; // wrong bits separator printed
    for (size_t s = 0 ; s < srclen; s++) {
        if ((source[s] == 0) || (source[s] == 1)) {
            w = 0;
            x += (source[s] << (3 - i));
            i++;
            if (i == 4) {
                if (t >= targetlen - 2) {
                    return r;
                }
                snprintf(target + t, targetlen - t, "%X", x);
                t++;
                r += 4;
                x = 0;
                i = 0;
            }
        } else {
            if (i > 0) {
                if (t >= targetlen - 5) {
                    return r;
                }
                snprintf(target + t, targetlen - t, "%X[%i]", x, i);
                t += 4;
                r += i;
                x = 0;
                i = 0;
                w = 1;
            }
            if (w == 0) {
                if (t >= targetlen - 2) {
                    return r;
                }
                snprintf(target + t, targetlen - t, " ");
                t++;
            }
            r++;
        }
    }
    return r;
}

// convert binary array to human readable binary
void binarraytobinstring(char *target, char *source,  int length) {
    for (int i = 0 ; i < length; ++i)
        *(target++) = *(source++) + '0';
    *target = '\0';
}

int binstring2binarray(uint8_t *target, char *source, int length) {
    int count = 0;
    char *start = source;
    while (length--) {
        char x = *(source++);
        // convert from binary value
        if (x >= '0' && x <= '1')
            x -= '0';
        else {
            PrintAndLogEx(WARNING, "(binstring2binarray) discovered unknown character %c %d at idx %d of %s", x, x, (int16_t)(source - start), start);
            return 0;
        }
        *(target++) = x;
        count++;
    }
    return count;
}

// return parity bit required to match type
uint8_t GetParity(const uint8_t *bits, uint8_t type, int length) {
    int x;
    for (x = 0 ; length > 0 ; --length)
        x += bits[length - 1];
    x %= 2;
    return x ^ type;
}

// add HID parity to binary array: EVEN prefix for 1st half of ID, ODD suffix for 2nd half
void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length) {
    *(target++) = GetParity(source, EVEN, length / 2);
    memcpy(target, source, length);
    target += length;
    *(target) = GetParity(source + length / 2, ODD, length / 2);
}

// add HID parity to binary array: ODD prefix for 1st half of ID, EVEN suffix for 2nd half
void wiegand_add_parity_swapped(uint8_t *target, uint8_t *source, uint8_t length) {
    *(target++) = GetParity(source, ODD, length / 2);
    memcpy(target, source, length);
    target += length;
    *(target) = GetParity(source + length / 2, EVEN, length / 2);
}

// Pack a bitarray into a uint32_t.
uint32_t PackBits(uint8_t start, uint8_t len, const uint8_t *bits) {

    if (len > 32) return 0;

    int i = start;
    int j = len - 1;
    uint32_t tmp = 0;

    for (; j >= 0; --j, ++i)
        tmp |= bits[i] << j;

    return tmp;
}

uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor) {
    uint64_t remaind = 0, quotient = 0, result = 0;
    remaind = num % divider;
    quotient = num / divider;
    if (!(quotient == 0 && remaind == 0))
        result += HornerScheme(quotient, divider, factor) * factor + remaind;
    return result;
}

int num_CPUs(void) {
    if (g_numCPUs > 0) {
        return g_numCPUs;
    }

    return detect_num_CPUs();
}

// determine number of logical CPU cores (use for multithreaded functions)
int detect_num_CPUs(void) {
#if defined(_WIN32)
#include <sysinfoapi.h>
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#else
    int count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count <= 0)
        count = 1;
    return count;
#endif
}

void str_lower(char *s) {
    for (size_t i = 0; i < strlen(s); i++)
        s[i] = tolower(s[i]);
}

void str_upper(char *s) {
    strn_upper(s, strlen(s));
}

void strn_upper(char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        s[i] = toupper(s[i]);
}
// check for prefix in string
bool str_startswith(const char *s,  const char *pre) {
    return strncmp(pre, s, strlen(pre)) == 0;
}

// check for suffix in string
bool str_endswith(const char *s,  const char *suffix) {
    size_t ls = strlen(s);
    size_t lsuffix = strlen(suffix);
    if (ls >= lsuffix) {
        return strncmp(suffix, s + (ls - lsuffix), lsuffix) == 0;
    }
    return false;
}

// Replace unprintable characters with a dot in char buffer
void clean_ascii(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (!isprint(buf[i]))
            buf[i] = '.';
    }
}

// replace \r \n to \0
void strcleanrn(char *buf, size_t len) {
    strcreplace(buf, len, '\n', '\0');
    strcreplace(buf, len, '\r', '\0');
}

// replace char in buffer
void strcreplace(char *buf, size_t len, char from, char to) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == from)
            buf[i] = to;
    }
}


char *str_dup(const char *src) {
    return str_ndup(src, strlen(src));
}
char *str_ndup(const char *src, size_t len) {

    char *dest = (char *) calloc(len + 1, sizeof(uint8_t));
    if (dest != NULL) {
        memcpy(dest, src, len);
        dest[len] = '\0';
    }
    return dest;
}

/**
 * Converts a hex string to component "hi2", "hi" and "lo" 32-bit integers
 * one nibble at a time.
 *
 * Returns the number of nibbles (4 bits) entered.
 */
int hexstring_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const char *str) {
    uint32_t n = 0, i = 0;

    while (sscanf(&str[i++], "%1x", &n) == 1) {
        *hi2 = (*hi2 << 4) | (*hi >> 28);
        *hi = (*hi << 4) | (*lo >> 28);
        *lo = (*lo << 4) | (n & 0xf);
    }
    return i - 1;
}

/**
 * Converts a binary string to component "hi2", "hi" and "lo" 32-bit integers,
 * one bit at a time.
 *
 * Returns the number of bits entered.
 */
int binstring_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const char *str) {
    uint32_t n = 0, i = 0;

    for (;;) {

        int res = sscanf(&str[i], "%1u", &n);
        if ((res != 1) || (n > 1))
            break;

        *hi2 = (*hi2 << 1) | (*hi >> 31);
        *hi = (*hi << 1) | (*lo >> 31);
        *lo = (*lo << 1) | (n & 0x1);

        i++;
    }
    return i;
}


/**
 * Converts a binary array to component "hi2", "hi" and "lo" 32-bit integers,
 * one bit at a time.
 *
 * Returns the number of bits entered.
 */
int binarray_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const uint8_t *arr, int arrlen) {
    int i = 0;
    for (; i < arrlen; i++) {
        uint8_t n = arr[i];
        if (n > 1)
            break;

        *hi2 = (*hi2 << 1) | (*hi >> 31);
        *hi = (*hi << 1) | (*lo >> 31);
        *lo = (*lo << 1) | (n & 0x1);
    }
    return i;
}

inline uint32_t bitcount32(uint32_t a) {
#if defined __GNUC__
    return __builtin_popcountl(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
}

inline uint64_t bitcount64(uint64_t a) {
#if defined __GNUC__
    return __builtin_popcountll(a);
#else
    PrintAndLogEx(FAILED, "Was not compiled with fct bitcount64");
    return 0;
#endif
}

inline uint32_t leadingzeros32(uint32_t a) {
#if defined __GNUC__
    return __builtin_clz(a);
#else
    PrintAndLogEx(FAILED, "Was not compiled with fct bitcount64");
    return 0;
#endif
}

inline uint64_t leadingzeros64(uint64_t a) {
#if defined __GNUC__
    return __builtin_clzll(a);
#else
    PrintAndLogEx(FAILED, "Was not compiled with fct bitcount64");
    return 0;
#endif
}


// byte_strstr searches for the first occurrence of pattern in src
// returns the byte offset the pattern is found at, or -1 if not found
int byte_strstr(const uint8_t *src, size_t srclen, const uint8_t *pattern, size_t plen) {

    size_t max = srclen - plen + 1;

    for (size_t i = 0; i < max; i++) {

        // compare only first byte
        if (src[i] != pattern[0])
            continue;

        // try to match rest of the pattern
        for (int j = plen - 1; j >= 1; j--) {

            if (src[i + j] != pattern[j])
                break;

            if (j == 1)
                return i;
        }
    }
    return -1;
}

// byte_strrstr is like byte_strstr except searches in reverse
// ie it returns the last occurrence of the pattern in src instead of the first
// returns the byte offset the pattern is found at, or -1 if not found
int byte_strrstr(const uint8_t *src, size_t srclen, const uint8_t *pattern, size_t plen) {
    for (int i = srclen - plen; i >= 0; i--) {
        // compare only first byte
        if (src[i] != pattern[0])
            continue;

        // try to match rest of the pattern
        for (int j = plen - 1; j >= 1; j--) {

            if (src[i + j] != pattern[j])
                break;

            if (j == 1)
                return i;
        }
    }
    return -1;
}

void sb_append_char(smartbuf *sb, unsigned char c) {
    if (sb->idx >= sb->size) {
        sb->size *= 2;
        sb->ptr = realloc(sb->ptr, sb->size);
    }
    sb->ptr[sb->idx] = c;
    sb->idx++;
}
