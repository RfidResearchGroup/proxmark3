//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------
#include "util.h"

#define UTIL_BUFFER_SIZE_SPRINT 4097
// global client debug variable
uint8_t g_debugMode = 0;

#ifdef _WIN32
#include <windows.h>
#endif

#define MAX_BIN_BREAK_LENGTH   (3072+384+1)

#ifndef _WIN32
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdarg.h>

int ukbhit(void) {
    int cnt = 0;
    int error;
    static struct termios Otty, Ntty;

    if (tcgetattr(STDIN_FILENO, &Otty) == -1) return -1;

    Ntty = Otty;

    Ntty.c_iflag          = 0x0000;   // input mode
    Ntty.c_oflag          = 0x0000;   // output mode
    Ntty.c_lflag          &= ~ICANON; // control mode = raw
    Ntty.c_cc[VMIN]       = 1;        // return if at least 1 character is in the queue
    Ntty.c_cc[VTIME]      = 0;        // no timeout. Wait forever

    if (0 == (error = tcsetattr(STDIN_FILENO, TCSANOW, &Ntty))) {  // set new attributes
        error += ioctl(STDIN_FILENO, FIONREAD, &cnt);              // get number of characters available
        error += tcsetattr(STDIN_FILENO, TCSANOW, &Otty);          // reset attributes
    }
    return (error == 0 ? cnt : -1);
}

#else

#include <conio.h>
int ukbhit(void) {
    return kbhit();
}
#endif

// log files functions

// open, appped and close logfile
void AddLogLine(char *fn, char *data, char *c) {
    FILE *f = NULL;
    char filename[FILE_PATH_SIZE] = {0x00};
    int len = 0;

    len = strlen(fn);
    if (len > FILE_PATH_SIZE)
        len = FILE_PATH_SIZE;
    memcpy(filename, fn, len);

    f = fopen(filename, "a");
    if (!f) {
        printf("Could not append log file %s", filename);
        return;
    }

    fprintf(f, "%s", data);
    fprintf(f, "%s\n", c);
    fflush(f);
    fclose(f);
}

void AddLogHex(char *fn, char *extData, const uint8_t *data, const size_t len) {
    AddLogLine(fn, extData, sprint_hex(data, len));
}

void AddLogUint64(char *fn, char *data, const uint64_t value) {
    char buf[20] = {0};
    memset(buf, 0x00, sizeof(buf));
    sprintf(buf, "%016" PRIx64 "", value);
    AddLogLine(fn, data, buf);
}

void AddLogCurrentDT(char *fn) {
    char buf[20];
    memset(buf, 0x00, sizeof(buf));
    struct tm *curTime;
    time_t now = time(0);
    curTime = gmtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", curTime);
    AddLogLine(fn, "\nanticollision: ", buf);
}

// create filename on hex uid.
// param *fn   -  pointer to filename char array
// param *uid  -  pointer to uid byte array
// param *ext  -  ".log"
// param uidlen - length of uid array.
void FillFileNameByUID(char *filenamePrefix, uint8_t *uid, const char *ext, int uidlen) {
    if (filenamePrefix == NULL || uid == NULL || ext == NULL) {
        printf("[!] error parameter is NULL\n");
        return;
    }

    int len = 0;
    len = strlen(filenamePrefix);
    //memset(fn, 0x00, FILE_PATH_SIZE);

    for (int j = 0; j < uidlen; j++)
        sprintf(filenamePrefix + len + j * 2, "%02X", uid[j]);
    strcat(filenamePrefix, ext);
}

// fill buffer from structure [{uint8_t data, size_t length},...]
int FillBuffer(uint8_t *data, size_t maxDataLength, size_t *dataLength, ...) {
    *dataLength = 0;
    va_list valist;
    va_start(valist, dataLength);

    uint8_t *vdata = NULL;
    size_t vlength = 0;
    do {
        vdata = va_arg(valist, uint8_t *);
        if (!vdata)
            break;

        vlength = va_arg(valist, size_t);
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
    for (int i = 0; i < strlen(value); i++)
        if (!isxdigit(value[i]))
            return false;

    if (strlen(value) % 2)
        return false;

    return true;
}

void hex_to_buffer(const uint8_t *buf, const uint8_t *hex_data, const size_t hex_len, const size_t hex_max_len,
                   const size_t min_str_len, const size_t spaces_between, bool uppercase) {

    char *tmp = (char *)buf;
    size_t i;
    memset(tmp, 0x00, hex_max_len);

    int maxLen = (hex_len > hex_max_len) ? hex_max_len : hex_len;

    for (i = 0; i < maxLen; ++i, tmp += 2 + spaces_between) {
        sprintf(tmp, (uppercase) ? "%02X" : "%02x", (unsigned int) hex_data[i]);

        for (int j = 0; j < spaces_between; j++)
            sprintf(tmp + 2 + j, " ");
    }

    i *= (2 + spaces_between);
    int minStrLen = min_str_len > i ? min_str_len : 0;
    if (minStrLen > hex_max_len)
        minStrLen = hex_max_len;
    for (; i < minStrLen; i++, tmp += 1)
        sprintf(tmp, " ");

    return;
}

// printing and converting functions
void print_hex(const uint8_t *data, const size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x ", data[i]);
    printf("\n");
}

void print_hex_break(const uint8_t *data, const size_t len, uint8_t breaks) {
    int rownum = 0;
    printf("[%02d] | ", rownum);
    for (int i = 0; i < len; ++i) {

        printf("%02X ", data[i]);

        // check if a line break is needed
        if (breaks > 0 && !((i + 1) % breaks) && (i + 1 < len)) {
            ++rownum;
            printf("\n[%02d] | ", rownum);
        }
    }
    printf("\n");
}

char *sprint_hex(const uint8_t *data, const size_t len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT - 3] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, 0, 1, true);
    return buf;
}

char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, min_str_len, 0, true);
    return buf;
}

char *sprint_hex_inrow(const uint8_t *data, const size_t len) {
    return sprint_hex_inrow_ex(data, len, 0);
}
char *sprint_hex_inrow_spaces(const uint8_t *data, const size_t len, size_t spaces_between) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, 0, spaces_between, true);
    return buf;
}

char *sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks) {

    // make sure we don't go beyond our char array memory
    size_t in_index = 0, out_index = 0;

    int rowlen = (len > MAX_BIN_BREAK_LENGTH) ? MAX_BIN_BREAK_LENGTH : len;

    if (breaks > 0 && len % breaks != 0)
        rowlen = (len + (len / breaks) > MAX_BIN_BREAK_LENGTH) ? MAX_BIN_BREAK_LENGTH : len + (len / breaks);

    //printf("(sprint_bin_break) rowlen %d\n", rowlen);

    static char buf[MAX_BIN_BREAK_LENGTH]; // 3072 + end of line characters if broken at 8 bits
    //clear memory
    memset(buf, 0x00, sizeof(buf));
    char *tmp = buf;

    // loop through the out_index to make sure we don't go too far
    for (out_index = 0; out_index < rowlen; out_index++) {
        // set character
        if (data[in_index] == 7) // Manchester wrong bit marker
            sprintf(tmp++, ".");
        else
            sprintf(tmp++, "%u", data[in_index]);
        // check if a line break is needed and we have room to print it in our array
        if ((breaks > 0) && !((in_index + 1) % breaks) && (out_index + 1 != rowlen)) {
            // increment and print line break
            out_index++;
            sprintf(tmp++, "%s", "\n");
        }
        in_index++;
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

    printf("(sprint_bin_break) rowlen %d\n", rowlen);

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

char *sprint_bin(const uint8_t *data, const size_t len) {
    return sprint_bin_break(data, len, 0);
}

char *sprint_hex_ascii(const uint8_t *data, const size_t len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT];
    char *tmp = buf;
    memset(buf, 0x00, UTIL_BUFFER_SIZE_SPRINT);
    size_t max_len = (len > 1010) ? 1010 : len;

    snprintf(tmp, UTIL_BUFFER_SIZE_SPRINT, "%s| ", sprint_hex(data, max_len));

    size_t i = 0;
    size_t pos = (max_len * 3) + 2;
    while (i < max_len) {
        char c = data[i];
        if ((c < 32) || (c == 127))
            c = '.';
        sprintf(tmp + pos + i, "%c",  c);
        ++i;
    }
    return buf;
}

char *sprint_ascii_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT];
    char *tmp = buf;
    memset(buf, 0x00, UTIL_BUFFER_SIZE_SPRINT);
    size_t max_len = (len > 1010) ? 1010 : len;
    size_t i = 0;
    while (i < max_len) {
        char c = data[i];
        tmp[i] = ((c < 32) || (c == 127)) ? '.' : c;
        ++i;
    }

    int m = min_str_len > i ? min_str_len : 0;
    for (; i < m; ++i)
        tmp[i] = ' ';

    return buf;
}
char *sprint_ascii(const uint8_t *data, const size_t len) {
    return sprint_ascii_ex(data, len, 0);
}

void print_blocks(uint32_t *data, size_t len) {
    PrintAndLogEx(NORMAL, "Blk | Data ");
    PrintAndLogEx(NORMAL, "----+------------");

    if (!data) {
        PrintAndLogEx(ERR, "..empty data");
    } else {
        for (uint8_t i = 0; i < len; i++)
            PrintAndLogEx(NORMAL, "%02d | 0x%08X", i, data[i]);
    }
}

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = n & 0xFF;
        n >>= 8;
    }
}

uint64_t bytes_to_num(uint8_t *src, size_t len) {
    uint64_t num = 0;
    while (len--) {
        num = (num << 8) | (*src);
        src++;
    }
    return num;
}

// takes a number (uint64_t) and creates a binarray in dest.
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = n & 1;
        n >>= 1;
    }
}

//least significant bit first
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest) {
    for (int i = 0 ; i < len ; ++i) {
        dest[i] =  n & 1;
        n >>= 1;
    }
}

// aa,bb,cc,dd,ee,ff,gg,hh, ii,jj,kk,ll,mm,nn,oo,pp
// to
// hh,gg,ff,ee,dd,cc,bb,aa, pp,oo,nn,mm,ll,kk,jj,ii
// up to 64 bytes or 512 bits
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize) {
    static uint8_t buf[64];
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
    uint32_t temp;
    char buf[5] = {0};

    if (param_getptr(line, &bg, &en, paramnum)) return 1;

    *datalen = 0;

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
            // if we dont have space in buffer and have symbols to translate
            return 2;
        }

        if (strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            data[*datalen] = (uint8_t)(temp & 0xff);
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

int param_getstr(const char *line, int paramnum, char *str, size_t buffersize) {
    int bg, en;

    if (param_getptr(line, &bg, &en, paramnum)) {
        return 0;
    }

    // Prevent out of bounds errors
    if (en - bg + 1 >= buffersize) {
        printf("out of bounds error: want %d bytes have %zu bytes\n", en - bg + 1 + 1, buffersize);
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
    int length, i, count = 0;
    char *start = source;
    char x;

    length = strlen(source);
    // process 4 bits (1 hex digit) at a time
    while (length--) {
        x = *(source++);
        // capitalize
        if (x >= 'a' && x <= 'f')
            x -= 32;
        // convert to numeric value
        if (x >= '0' && x <= '9')
            x -= '0';
        else if (x >= 'A' && x <= 'F')
            x -= 'A' - 10;
        else {
            printf("Discovered unknown character %c %d at idx %d of %s\n", x, x, (int16_t)(source - start), start);
            return 0;
        }
        // output
        for (i = 0 ; i < 4 ; ++i, ++count)
            *(target++) = (x >> (3 - i)) & 1;
    }

    return count;
}

// convert hex to human readable binary string
int hextobinstring(char *target, char *source) {
    int length;

    if (!(length = hextobinarray(target, source)))
        return 0;
    binarraytobinstring(target, target, length);
    return length;
}

// convert binary array of 0x00/0x01 values to hex
// return number of bits converted
int binarraytohex(char *target, const size_t targetlen, char *source, size_t srclen) {
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
                if (t >= targetlen - 2) return r;
                sprintf(target + t, "%X", x);
                t++;
                r += 4;
                x = 0;
                i = 0;
            }
        } else {
            if (i > 0) {
                if (t >= targetlen - 5) return r;
                w = 0;
                sprintf(target + t, "%X[%i]", x, i);
                t += 4;
                r += i;
                x = 0;
                i = 0;
            }
            if (w == 0) {
                if (t >= targetlen - 2) return r;
                sprintf(target + t, " ");
                t++;
            }
            r++;
        }
    }
    return r;
}

// convert binary array to human readable binary
void binarraytobinstring(char *target, char *source,  int length) {
    int i;

    for (i = 0 ; i < length ; ++i)
        *(target++) = *(source++) + '0';
    *target = '\0';
}

// return parity bit required to match type
uint8_t GetParity(uint8_t *bits, uint8_t type, int length) {
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

// xor two arrays together for len items.  The dst array contains the new xored values.
void xor(unsigned char *dst, unsigned char *src, size_t len) {
    for (; len > 0; len--, dst++, src++)
        *dst ^= *src;
}

int32_t le24toh(uint8_t data[3]) {
    return (data[2] << 16) | (data[1] << 8) | data[0];
}
// Pack a bitarray into a uint32_t.
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t *bits) {

    if (len > 32) return 0;

    int i = start;
    int j = len - 1;
    uint32_t tmp = 0;

    for (; j >= 0; --j, ++i)
        tmp |= bits[i] << j;

    return tmp;
}

// RotateLeft - Ultralight, Desfire, works on byte level
// 00-01-02  >> 01-02-00
void rol(uint8_t *data, const size_t len) {
    uint8_t first = data[0];
    for (size_t i = 0; i < len - 1; i++) {
        data[i] = data[i + 1];
    }
    data[len - 1] = first;
}

/*
uint8_t pw_rev_A(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}
*/
uint8_t reflect8(uint8_t b) {
    return ((b * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32;
}
uint16_t reflect16(uint16_t b) {
    uint16_t v = 0;
    v |= (b & 0x8000) >> 15;
    v |= (b & 0x4000) >> 13;
    v |= (b & 0x2000) >> 11;
    v |= (b & 0x1000) >> 9;
    v |= (b & 0x0800) >> 7;
    v |= (b & 0x0400) >> 5;
    v |= (b & 0x0200) >> 3;
    v |= (b & 0x0100) >> 1;

    v |= (b & 0x0080) << 1;
    v |= (b & 0x0040) << 3;
    v |= (b & 0x0020) << 5;
    v |= (b & 0x0010) << 7;
    v |= (b & 0x0008) << 9;
    v |= (b & 0x0004) << 11;
    v |= (b & 0x0002) << 13;
    v |= (b & 0x0001) << 15;
    return v;
}
/*
 ref  http://www.csm.ornl.gov/~dunigan/crc.html
 Returns the value v with the bottom b [0,32] bits reflected.
 Example: reflect(0x3e23L,3) == 0x3e26
*/
uint32_t reflect(uint32_t v, int b) {
    uint32_t t = v;
    for (int i = 0; i < b; ++i) {
        if (t & 1)
            v |=  BITMASK((b - 1) - i);
        else
            v &= ~BITMASK((b - 1) - i);
        t >>= 1;
    }
    return v;
}

uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor) {
    uint64_t remainder = 0, quotient = 0, result = 0;
    remainder = num % divider;
    quotient = num / divider;
    if (!(quotient == 0 && remainder == 0))
        result += HornerScheme(quotient, divider, factor) * factor + remainder;
    return result;
}

// determine number of logical CPU cores (use for multithreaded functions)
extern int num_CPUs(void) {
#if defined(_WIN32)
#include <sysinfoapi.h>
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#elif defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
    return sysconf(_SC_NPROCESSORS_ONLN);
#else
    return 1;
#endif
}

extern void str_lower(char *s) {
    for (int i = 0; i < strlen(s); i++)
        s[i] = tolower(s[i]);
}
extern bool str_startswith(const char *s,  const char *pre) {
    return strncmp(pre, s, strlen(pre)) == 0;
}

// Replace unprintable characters with a dot in char buffer
extern void clean_ascii(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (!isprint(buf[i]))
            buf[i] = '.';
    }
}

// replace \r \n to \0
extern void strcleanrn(char *buf, size_t len) {
    strcreplace(buf, len, '\n', '\0');
    strcreplace(buf, len, '\r', '\0');
}

// replace char in buffer
extern void strcreplace(char *buf, size_t len, char from, char to) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == from)
            buf[i] = to;
    }
}

extern char *strmcopy(char *buf) {
    char *str = (char *) calloc(strlen(buf) + 1, sizeof(uint8_t));
    if (str != NULL) {
        memset(str, 0, strlen(buf) + 1);
        strcpy(str, buf);
    }
    return str;
}
