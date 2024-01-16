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
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdusart.h"

#include <stdlib.h>       // size_t
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "cliparser.h"    //
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"
#include "util_posix.h"
#include "usart_defs.h"
#include "ui.h"           // PrintAndLog

static int CmdHelp(const char *Cmd);

static int usart_tx(uint8_t *data, size_t len) {
    clearCommandBuffer();
    SendCommandNG(CMD_USART_TX, data, len);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_TX, &resp, 1000)) {
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int usart_rx(uint8_t *data, size_t *len, uint32_t waittime) {
    clearCommandBuffer();
    struct {
        uint32_t waittime;
    } PACKED payload;
    payload.waittime = waittime;
    SendCommandNG(CMD_USART_RX, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_RX, &resp, waittime + 500)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_SUCCESS) {
        *len = resp.length;
        memcpy(data, resp.data.asBytes, resp.length);
    }
    return resp.status;
}

static int usart_txrx(uint8_t *srcdata, size_t srclen, uint8_t *dstdata, size_t *dstlen, uint32_t waittime) {
    clearCommandBuffer();
    struct payload_header {
        uint32_t waittime;
    } PACKED;
    struct {
        struct payload_header header;
        uint8_t data[PM3_CMD_DATA_SIZE - sizeof(uint32_t)];
    } PACKED payload;

    payload.header.waittime = waittime;

    if (srclen >= sizeof(payload.data)) {
        return PM3_EOVFLOW;
    }

    memcpy(payload.data, srcdata, srclen);
    SendCommandNG(CMD_USART_TXRX, (uint8_t *)&payload, srclen + sizeof(payload.header));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_USART_TXRX, &resp, waittime + 500) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        *dstlen = resp.length;
        memcpy(dstdata, resp.data.asBytes, resp.length);
    }
    return resp.status;
}

static int set_usart_config(uint32_t baudrate, uint8_t parity) {
    clearCommandBuffer();
    struct {
        uint32_t baudrate;
        uint8_t parity;
    } PACKED payload;
    payload.baudrate = baudrate;
    payload.parity = parity;
    SendCommandNG(CMD_USART_CONFIG, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_CONFIG, &resp, 1000)) {
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int CmdUsartConfig(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart config",
                  "Configure USART.\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n"
                  "The changes are not permanent, restart Proxmark3 to get default settings back.",
                  "usart config -b 9600\n"
                  "usart config -b 9600 --none\n"
                  "usart config -E"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("b", "baud", "<dec>", "baudrate"),
        arg_lit0("N", "none", "mone parity"),
        arg_lit0("E", "even", "even parity"),
        arg_lit0("O", "odd", "odd parity"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t baudrate = arg_get_u32_def(ctx, 1, 0);
    bool pn = arg_get_lit(ctx, 2);
    bool pe = arg_get_lit(ctx, 3);
    bool po = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((pn + pe + po) > 1) {
        PrintAndLogEx(WARNING, "Only one parity can be used at a time");
        return PM3_EINVARG;
    }

    uint8_t parity = 0;
    if (pn)
        parity = 'N';
    else if (po)
        parity = 'O';
    else if (pe)
        parity = 'E';

    return set_usart_config(baudrate, parity);
}

static int usart_bt_testcomm(uint32_t baudrate, uint8_t parity) {
    int ret = set_usart_config(baudrate, parity);
    if (ret != PM3_SUCCESS)
        return ret;

    const char *string = "AT+VERSION";
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;

    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s at %u 8%c1", strlen(string), (int)strlen(string), string, baudrate, parity);

    // 1000, such large timeout needed
    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (str_startswith((char *)data, "hc01.comV2.0") || str_startswith((char *)data, "BT SPP V3.0")) {
            PrintAndLogEx(SUCCESS, "Add-on " _GREEN_("found!"));
            return PM3_SUCCESS;
        }
    }
    return PM3_ENODATA;
}

static int CmdUsartBtFactory(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart btfactory",
                  "Reset BT add-on to factory settings\n"
                  "This requires\n"
                  "    1) BTpower to be turned ON\n"
                  "    2) BT add-on to NOT be connected\n"
                  "      => the add-on blue LED must blink\n\n"
                  _RED_("WARNING:") _CYAN_(" process only if strictly needed!"),
                  "usart btfactory"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

// take care to define compatible settings:
# define BTADDON_BAUD_AT  "AT+BAUD8"
# define BTADDON_BAUD_NUM "115200"

    uint32_t baudrate = 0;
    uint8_t parity = 0;

    if (USART_BAUD_RATE != atoi(BTADDON_BAUD_NUM)) {
        PrintAndLogEx(WARNING, _RED_("WARNING:") " current Proxmark3 firmware has default USART baudrate = %i", USART_BAUD_RATE);
        PrintAndLogEx(WARNING, "Current btfactory implementation is hardcoded to " BTADDON_BAUD_NUM " bauds");
        return PM3_ENOTIMPL;
    }

    PrintAndLogEx(WARNING, _RED_("WARNING: process only if strictly needed!"));
    PrintAndLogEx(WARNING, "This requires BT turned ON and NOT connected!");
    PrintAndLogEx(WARNING, "Is the add-on blue light blinking? (Say 'n' if you want to abort) [y/n]");

    char input[3];
    if ((fgets(input, sizeof(input), stdin) == NULL) || (strncmp(input, "y\n", sizeof(input)) != 0)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(FAILED, "Aborting.");
        return PM3_EOPABORTED;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Trying to detect current settings... Please be patient.");

    bool found = usart_bt_testcomm(USART_BAUD_RATE, USART_PARITY) == PM3_SUCCESS;
    if (found) {
        baudrate = USART_BAUD_RATE;
        parity = USART_PARITY;
    } else {
        uint32_t brs[] = {1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1382400};
        uint8_t ps[] = { 'N', 'O', 'E' };
        for (uint8_t ip = 0; (ip < ARRAYLEN(ps)) && (!found); ip++) {
            for (uint8_t ibr = 0; (ibr < ARRAYLEN(brs)) && (!found); ibr++) {
                found = usart_bt_testcomm(brs[ibr], ps[ip]) == PM3_SUCCESS;
                if (found) {
                    baudrate = brs[ibr];
                    parity = ps[ip];
                }
            }
        }
    }

    if (!found) {
        PrintAndLogEx(FAILED, "Sorry, add-on not found. Abort.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Reconfiguring add-on to default settings.");
    const char *string;
    uint8_t data[PM3_CMD_DATA_SIZE];
    size_t len = 0;
    memset(data, 0, sizeof(data));

    string = "AT+NAMEPM3_RDV4.0";
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strcmp((char *)data, "OKsetname") == 0) {
            PrintAndLogEx(SUCCESS, "Name set to " _GREEN_("PM3_RDV4.0"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+NAME: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
        return PM3_ESOFT;
    }

    memset(data, 0, sizeof(data));
    len = 0;
    string = "AT+ROLE=S";
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strcmp((char *)data, "OK+ROLE:S") == 0) {
            PrintAndLogEx(SUCCESS, "Role set to " _GREEN_("Slave"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+ROLE=S: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
        return PM3_ESOFT;
    }

    memset(data, 0, sizeof(data));
    len = 0;
    string = "AT+PIN1234";
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strcmp((char *)data, "OKsetPIN") == 0) {
            PrintAndLogEx(SUCCESS, "PIN set to " _GREEN_("1234"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+PIN: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
        return PM3_ESOFT;
    }

    // parity must be changed before baudrate
    if (parity != USART_PARITY) {
        memset(data, 0, sizeof(data));
        len = 0;
        string = "AT+PN";
        PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

        ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
        if (ret == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
            if (strcmp((char *)data, "OK None") == 0) {
                PrintAndLogEx(SUCCESS, "Parity set to " _GREEN_("None"));
            } else {
                PrintAndLogEx(WARNING, "Unexpected response to AT+P: " _YELLOW_("%.*s"), (int)len, data);
            }
        } else {
            PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
            return PM3_ESOFT;
        }
    }

    if (baudrate != USART_BAUD_RATE) {
        memset(data, 0, sizeof(data));
        len = 0;
        string = BTADDON_BAUD_AT;
        PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

        ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
        if (ret == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
            if (strcmp((char *)data, "OK" BTADDON_BAUD_NUM) == 0) {
                PrintAndLogEx(SUCCESS, "Baudrate set to " _GREEN_(BTADDON_BAUD_NUM));
            } else {
                PrintAndLogEx(WARNING, "Unexpected response to AT+BAUD: " _YELLOW_("%.*s"), (int)len, data);
            }
        } else {
            PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
            return PM3_ESOFT;
        }
    }

    if ((baudrate != USART_BAUD_RATE) || (parity != USART_PARITY)) {
        PrintAndLogEx(WARNING, "Add-on uart settings changed, please turn BT add-on OFF and ON again, then press Enter.");
        while (!kbd_enter_pressed()) {
            msleep(200);
        }
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Trying to connect add-on with the new settings.");
        found = usart_bt_testcomm(USART_BAUD_RATE, USART_PARITY) == PM3_SUCCESS;
        if (!found) {
            PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
            return PM3_ESOFT;
        }
    }

    PrintAndLogEx(SUCCESS, "Add-on successfully " _GREEN_("reset"));
    return PM3_SUCCESS;
}

static int CmdUsartBtPin(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart btpin",
                  "Change BT add-on PIN.\n"
                  "WARNING: this requires\n"
                  "    1) BTpower to be turned ON\n"
                  "    2) BT add-on to NOT be connected\n"
                  "      => the add-on blue LED must blink",
                  "usart btpin -p 1234"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pin", "<dec>", "Desired PIN number (4 digits)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int plen = 4;
    char pin[5] = { 0, 0, 0, 0, 0 };
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)pin, sizeof(pin), &plen);
    CLIParserFree(ctx);

    if (plen != 4) {
        PrintAndLogEx(FAILED, "PIN must be 4 digits");
        return PM3_EINVARG;
    }

    for (uint8_t i = 0; i < plen; i++) {
        if (isdigit(pin[i]) == false) {
            PrintAndLogEx(FAILED, "PIN must be 4 digits");
            return PM3_EINVARG;
        }
    }

    char string[6 + sizeof(pin)] = {0};
    snprintf(string, sizeof(string), "AT+PIN%s", pin);
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 600);

    if (ret == PM3_ENODATA) {
        PrintAndLogEx(FAILED, "No response from add-on, is it ON and blinking?");
        return ret;
    }

    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Command failed, ret=%i", ret);
        return ret;
    }

    if (strcmp((char *)data, "OKsetPIN") == 0) {
        PrintAndLogEx(NORMAL, "PIN changed " _GREEN_("successfully"));
    } else {
        PrintAndLogEx(WARNING, "Unexpected answer: %.*s", (int)len, data);
    }
    return PM3_SUCCESS;
}

static int CmdUsartTX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart tx",
                  "Send string over USART.\n"
                  "WARNING:  it will have side-effects if used in USART HOST mode!",
                  "usart tx -d \"AT+VERSION\"\n"
                  "usart tx -d \"AT+VERSION\\r\\n\""
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", NULL, "string to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int slen = 0;
    char s[PM3_CMD_DATA_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)s, sizeof(s), &slen);
    CLIParserFree(ctx);

    char clean[PM3_CMD_DATA_SIZE] = {0};
    size_t i2 = 0;
    size_t n = strlen(s);

    // strip / replace
    for (size_t i = 0; i < n; i++) {
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '\\')) {
            i++;
            clean[i2++] = '\\';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '"')) {
            i++;
            clean[i2++] = '"';
            continue;
        }
        if (s[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'r')) {
            i++;
            clean[i2++] = '\r';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'n')) {
            i++;
            clean[i2++] = '\n';
            continue;
        }
        clean[i2++] = s[i];
    }
    return usart_tx((uint8_t *)clean, strlen(clean));
}

static int CmdUsartRX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart rx",
                  "Receive string over USART.\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n",
                  "usart rx -t 2000     ->  2 second timeout"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "timeout in ms, default is 0ms"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    PrintAndLogEx(SUCCESS, "RX:%.*s", (int)len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXRX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart txrx",
                  "Send string over USART and wait for response.\n"
                  "WARNING: if used in USART HOST mode, you can only send AT commands\n"
                  "to add-on when BT connection is not established (LED needs to be blinking)\n"
                  _RED_("Any other usage in USART HOST mode will have side-effects!"),

                  "usart txrx -d \"AT+VERSION\"               -> Talking to BT add-on (when no connection)\n"
                  "usart txrx -t 2000 -d \"AT+SOMESTUFF\\r\\n\" -> Talking to a target requiring longer time and end-of-line chars"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "timeout in ms, default is 1000 ms"),
        arg_str1("d", "data", NULL, "string to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 1000);
    int slen = 0;
    char s[PM3_CMD_DATA_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)s, sizeof(s), &slen);
    CLIParserFree(ctx);

    char clean[PM3_CMD_DATA_SIZE] = {0};
    size_t j = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '\\')) {
            i++;
            clean[j++] = '\\';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '"')) {
            i++;
            clean[j++] = '"';
            continue;
        }
        if (s[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'r')) {
            i++;
            clean[j++] = '\r';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'n')) {
            i++;
            clean[j++] = '\n';
            continue;
        }
        clean[j++] = s[i];
    }

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(clean), (int)strlen(clean), clean);
    int ret = usart_txrx((uint8_t *)clean, strlen(clean), data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXhex(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart txhex",
                  "Send bytes over USART.\n"
                  "WARNING:  it will have side-effects if used in USART HOST mode!",
                  "usart txhex -d 504d33620a80000000010100f09f988ef09fa5b36233"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int dlen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }
    return usart_tx(data, dlen);
}

static int CmdUsartRXhex(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "usart rxhex",
                  "Receive bytes over USART.\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n",
                  "usart rxhex -t 2000  -> 2 second timeout"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "timeout in ms, default is 0ms"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    print_hex_break(data, len, 32);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable,          "This help"},
    {"btpin",        CmdUsartBtPin,      IfPm3FpcUsartFromUsb,     "Change BT add-on PIN"},
    {"btfactory",    CmdUsartBtFactory,  IfPm3FpcUsartFromUsb,     "Reset BT add-on to factory settings"},
    {"tx",           CmdUsartTX,         IfPm3FpcUsartDevFromUsb,  "Send string over USART"},
    {"rx",           CmdUsartRX,         IfPm3FpcUsartDevFromUsb,  "Receive string over USART"},
    {"txrx",         CmdUsartTXRX,       IfPm3FpcUsartDevFromUsb,  "Send string over USART and wait for response"},
    {"txhex",        CmdUsartTXhex,      IfPm3FpcUsartDevFromUsb,  "Send bytes over USART"},
    {"rxhex",        CmdUsartRXhex,      IfPm3FpcUsartDevFromUsb,  "Receive bytes over USART"},
    {"config",       CmdUsartConfig,     IfPm3FpcUsartDevFromUsb,  "Configure USART"},
//    {"bridge",       CmdUsartBridge,     IfPm3FpcUsartDevFromUsb,  "Bridge USB-CDC & USART"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdUsart(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
