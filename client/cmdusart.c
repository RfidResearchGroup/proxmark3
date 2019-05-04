//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdusart.h"

static int CmdHelp(const char *Cmd);

static int usage_usart_tx(void) {
    PrintAndLogEx(NORMAL, "Send string over USART");
    PrintAndLogEx(NORMAL, "WARNING: it will have side-effects if used in USART HOST mode!");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart tx [h] \"string\"");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           d string   string to send");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      usart tx d \"AT+VERSION\"");
    PrintAndLogEx(NORMAL, "      usart tx d \"AT+VERSION\\r\\n\"");
    PrintAndLogEx(NORMAL, "expected output: nothing");
    return PM3_SUCCESS;
}

static int usage_usart_txhex(void) {
    PrintAndLogEx(NORMAL, "Send bytes over USART");
    PrintAndLogEx(NORMAL, "WARNING: it will have side-effects if used in USART HOST mode!");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart txhex [h] d <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           d <bytes>  bytes to send");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      usart txhex d 504d33620a80000000010100f09f988ef09fa5b36233");
    PrintAndLogEx(NORMAL, "expected output: nothing");
    return PM3_SUCCESS;
}

static int usage_usart_rx(void) {
    PrintAndLogEx(NORMAL, "Receive string over USART");
    PrintAndLogEx(NORMAL, "WARNING: it will have side-effects if used in USART HOST mode!");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart rx [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "expected output: Received string");
    return PM3_SUCCESS;
}

static int usage_usart_rxhex(void) {
    PrintAndLogEx(NORMAL, "Receive bytes over USART");
    PrintAndLogEx(NORMAL, "WARNING: it will have side-effects if used in USART HOST mode!");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart rx [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "expected output: Received bytes");
    return PM3_SUCCESS;
}

static int usage_usart_txrx(void) {
    PrintAndLogEx(NORMAL, "Send string over USART and wait for response");
    PrintAndLogEx(NORMAL, "WARNING: if used in USART HOST mode, you can only send AT commands");
    PrintAndLogEx(NORMAL, "to add-on when BT connection is not established (LED needs to be blinking)");
    PrintAndLogEx(NORMAL, "Any other usage in USART HOST mode will have side-effects!");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart txrx [h] [t <timeout>] \"string\"");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h           This help");
    PrintAndLogEx(NORMAL, "           t <timeout> timeout in ms, default is 1000ms");
    PrintAndLogEx(NORMAL, "           d string    string to send");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "    Talking to the BT add-on (when no connection):");
    PrintAndLogEx(NORMAL, "      usart txrx d \"AT+VERSION\"");
    PrintAndLogEx(NORMAL, "    Talking to a target requiring longer time and end-of-line chars:");
    PrintAndLogEx(NORMAL, "      usart txrx t 2000 d \"AT+SOMESTUFF\\r\\n\"");
    PrintAndLogEx(NORMAL, "expected output: Received string");
    return PM3_SUCCESS;
}

static int usart_tx(uint8_t *data, size_t len) {
    clearCommandBuffer();
    SendCommandNG(CMD_USART_TX, data, len);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_TX, &resp, 1000)) {
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int usart_rx(uint8_t *data, size_t *len) {
    clearCommandBuffer();
    SendCommandNG(CMD_USART_RX, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_RX, &resp, 1000)) {
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
    struct {
        uint32_t waittime;
        uint8_t data[PM3_CMD_DATA_SIZE - sizeof(uint32_t)];
    } PACKED payload;
    payload.waittime = waittime;
    if (srclen >= sizeof(payload.data))
        return PM3_EOVFLOW;
    memcpy(payload.data, srcdata, srclen);
    SendCommandNG(CMD_USART_TXRX, (uint8_t *)&payload, srclen + sizeof(payload.waittime));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_TXRX, &resp, 1000)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_SUCCESS) {
        *dstlen = resp.length;
        memcpy(dstdata, resp.data.asBytes, resp.length);
    }
    return resp.status;
}

static int CmdUsartTX(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    char string[PM3_CMD_DATA_SIZE] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_tx();
            case 'd':
                if (param_getstr(Cmd, cmdp + 1, string, sizeof(string)) >= sizeof(string)) {
                    PrintAndLogEx(FAILED, "String too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) {
        usage_usart_tx();
        return PM3_EINVARG;
    }
    char string2[PM3_CMD_DATA_SIZE] = {0};
    size_t i2 = 0;
    size_t n = strlen(string);
    for (size_t i = 0; i < n; i++) {
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == '\\')) {
            i++;
            string2[i2++] = '\\';
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == '"')) {
            i++;
            string2[i2++] = '"';
            continue;
        }
        if (string[i] == '"') {
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == 'r')) {
            i++;
            string2[i2++] = '\r';
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == 'n')) {
            i++;
            string2[i2++] = '\n';
            continue;
        }
        string2[i2++] = string[i];
    }
    return usart_tx((uint8_t *)string2, strlen(string2));
}

static int CmdUsartRX(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_rx();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) {
        usage_usart_rx();
        return PM3_EINVARG;
    }
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len);
    if (ret != PM3_SUCCESS)
        return ret;
    PrintAndLogEx(NORMAL, "RX:%.*s", len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXRX(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    char string[PM3_CMD_DATA_SIZE] = {0};
    uint32_t waittime = 1000;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_txrx();
            case 'd':
                if (param_getstr(Cmd, cmdp + 1, string, sizeof(string)) >= sizeof(string)) {
                    PrintAndLogEx(FAILED, "String too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 't':
                waittime = param_get32ex(Cmd, cmdp + 1, 1000, 10);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) {
        usage_usart_txrx();
        return PM3_EINVARG;
    }
    char string2[PM3_CMD_DATA_SIZE] = {0};
    size_t i2 = 0;
    size_t n = strlen(string);
    for (size_t i = 0; i < n; i++) {
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == '\\')) {
            i++;
            string2[i2++] = '\\';
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == '"')) {
            i++;
            string2[i2++] = '"';
            continue;
        }
        if (string[i] == '"') {
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == 'r')) {
            i++;
            string2[i2++] = '\r';
            continue;
        }
        if ((string[i] == '\\') && (i < n - 1) && (string[i + 1] == 'n')) {
            i++;
            string2[i2++] = '\n';
            continue;
        }
        string2[i2++] = string[i];
    }
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    PrintAndLogEx(NORMAL, "TX (%3u):%.*s", strlen(string2), strlen(string2), string2);
    int ret = usart_txrx((uint8_t *)string2, strlen(string2), data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;
    PrintAndLogEx(NORMAL, "RX (%3u):%.*s", len, len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXhex(const char *Cmd) {
    int hexlen, len = 0;
    uint8_t cmdp = 0;
    bool errors = false;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_txhex();
            case 'd':
                if (param_gethex_ex(Cmd, cmdp + 1, data, &hexlen)) {
                    PrintAndLogEx(ERR, "Error parsing bytes");
                    return PM3_EINVARG;
                }
                len = hexlen >> 1;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) {
        usage_usart_txhex();
        return PM3_EINVARG;
    }
    return usart_tx(data, len);
}

static int CmdUsartRXhex(const char *Cmd) {
    uint8_t cmdp = 0;
    bool errors = false;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_rxhex();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) {
        usage_usart_rxhex();
        return PM3_EINVARG;
    }

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len);
    if (ret != PM3_SUCCESS)
        return ret;

    print_hex_break(data, len, 32);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable,         "This help"},
    {"tx",           CmdUsartTX,         IfPm3FpcUsartDevFromUsb, "Send string over USART"},
    {"rx",           CmdUsartRX,         IfPm3FpcUsartDevFromUsb, "Receive string over USART"},
    {"txrx",         CmdUsartTXRX,       IfPm3FpcUsartDevFromUsb, "Send string over USART and wait for response"},
    {"txhex",        CmdUsartTXhex,      IfPm3FpcUsartDevFromUsb, "Send bytes over USART"},
    {"rxhex",        CmdUsartRXhex,      IfPm3FpcUsartDevFromUsb, "Receive bytes over USART"},
//    {"bridge",       CmdUsartBridge,     IfPm3FpcUsartDevFromUsb, "Bridge USB-CDC & USART"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdUsart(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
