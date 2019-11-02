//-----------------------------------------------------------------------------
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main application code. This is the first thing called after start.c
// executes.
//-----------------------------------------------------------------------------

#include "dbprint.h"

#include "string.h"
#include "cmd.h"
#include "printf.h"

#define DEBUG 1

//=============================================================================
// Debug print functions, to go out over USB, to the usual PC-side client.
//=============================================================================

void DbpStringEx(uint32_t flags, char *src, size_t srclen) {
#if DEBUG
    struct {
        uint16_t flag;
        uint8_t buf[PM3_CMD_DATA_SIZE - sizeof(uint16_t)];
    } PACKED data;
    data.flag = flags;
    uint16_t len = MIN(srclen, sizeof(data.buf));
    memcpy(data.buf, src, len);
    reply_ng(CMD_DEBUG_PRINT_STRING, PM3_SUCCESS, (uint8_t *)&data, sizeof(data.flag) + len);
#endif
}

void DbpString(char *str) {
#if DEBUG
    DbpStringEx(FLAG_LOG, str, strlen(str));
#endif
}

void DbprintfEx(uint32_t flags, const char *fmt, ...) {
#if DEBUG
    // should probably limit size here; oh well, let's just use a big buffer
    char s[PM3_CMD_DATA_SIZE] = {0x00};
    va_list ap;
    va_start(ap, fmt);
    kvsprintf(fmt, s, 10, ap);
    va_end(ap);

    DbpStringEx(flags, s, strlen(s));
#endif
}

void Dbprintf(const char *fmt, ...) {
#if DEBUG
    // should probably limit size here; oh well, let's just use a big buffer
    char output_string[PM3_CMD_DATA_SIZE] = {0x00};
    va_list ap;

    va_start(ap, fmt);
    kvsprintf(fmt, output_string, 10, ap);
    va_end(ap);

    DbpString(output_string);
#endif
}

// prints HEX & ASCII
void Dbhexdump(int len, uint8_t *d, bool bAsci) {
#if DEBUG
    char ascii[9];

    while (len > 0) {

        int l = (len > 8) ? 8 : len;

        memcpy(ascii, d, l);
        ascii[l] = 0;

        // filter safe ascii
        for (int i = 0; i < l; i++) {
            if (ascii[i] < 32 || ascii[i] > 126) {
                ascii[i] = '.';
            }
        }

        if (bAsci)
            Dbprintf("%-8s %*D", ascii, l, d, " ");
        else
            Dbprintf("%*D", l, d, " ");

        len -= 8;
        d += 8;
    }
#endif
}

void print_result(char *name, uint8_t *buf, size_t len) {

    uint8_t *p = buf;
    uint16_t tmp = len & 0xFFF0;

    for (; p - buf < tmp; p += 16) {
        Dbprintf("[%s: %02d/%02d] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 name,
                 p - buf,
                 len,
                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]
                );
    }
    if (len % 16 != 0) {
        char s[46] = {0};
        char *sp = s;
        for (; p - buf < len; p++) {
            sprintf(sp, "%02x ", p[0]);
            sp += 3;
        }
        Dbprintf("[%s: %02d/%02d] %s", name, p - buf, len, s);
    }
}

/* useful when debugging new protocol implementations like FeliCa
void PrintToSendBuffer(void) {
    DbpString("Printing ToSendBuffer:");
    Dbhexdump(ToSendMax, ToSend, 0);
}
*/
