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

static int usage_usart_bt_pin(void) {
    PrintAndLogEx(NORMAL, "Change BT add-on PIN");
    PrintAndLogEx(NORMAL, "WARNING: this requires");
    PrintAndLogEx(NORMAL, "      1) BTpower to be turned ON");
    PrintAndLogEx(NORMAL, "      2) BT add-on to NOT be connected");
    PrintAndLogEx(NORMAL, "      => the add-on blue LED must blink");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart btpin [h] d NNNN");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           d NNNN     Desired PIN");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "      usart btpin 1234");
    PrintAndLogEx(NORMAL, "expected output: nothing");
    return PM3_SUCCESS;
}

static int usage_usart_bt_factory(void) {
    PrintAndLogEx(NORMAL, "Reset BT add-on to factory settings");
    PrintAndLogEx(NORMAL, _RED_("WARNING: process only if strictly needed!"));
    PrintAndLogEx(NORMAL, "This requires");
    PrintAndLogEx(NORMAL, "      1) BTpower to be turned ON");
    PrintAndLogEx(NORMAL, "      2) BT add-on to NOT be connected");
    PrintAndLogEx(NORMAL, "      => the add-on blue LED must blink");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart btfactory [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    return PM3_SUCCESS;
}

static int usage_usart_tx(void) {
    PrintAndLogEx(NORMAL, "Send string over USART");
    PrintAndLogEx(NORMAL, _RED_("WARNING: it will have side-effects if used in USART HOST mode!"));
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
    PrintAndLogEx(NORMAL, _RED_("WARNING: it will have side-effects if used in USART HOST mode!"));
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
    PrintAndLogEx(NORMAL, "Receive string over USART [t <timeout>]");
    PrintAndLogEx(NORMAL, _RED_("WARNING: it will have side-effects if used in USART HOST mode!"));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart rx [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           t <timeout> timeout in ms, default is 0ms");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "expected output: Received string");
    return PM3_SUCCESS;
}

static int usage_usart_rxhex(void) {
    PrintAndLogEx(NORMAL, "Receive bytes over USART");
    PrintAndLogEx(NORMAL, _RED_("WARNING: it will have side-effects if used in USART HOST mode!"));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart rxhex [h] [t <timeout>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           t <timeout> timeout in ms, default is 0ms");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "expected output: Received bytes");
    return PM3_SUCCESS;
}

static int usage_usart_txrx(void) {
    PrintAndLogEx(NORMAL, "Send string over USART and wait for response");
    PrintAndLogEx(NORMAL, _YELLOW_("WARNING: if used in USART HOST mode, you can only send AT commands"));
    PrintAndLogEx(NORMAL, _YELLOW_("to add-on when BT connection is not established (LED needs to be blinking)"));
    PrintAndLogEx(NORMAL, _RED_("Any other usage in USART HOST mode will have side-effects!"));
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

static int usage_usart_config(void) {
    PrintAndLogEx(NORMAL, "Configure USART");
    PrintAndLogEx(NORMAL, _RED_("WARNING: it will have side-effects if used in USART HOST mode!"));
    PrintAndLogEx(NORMAL, "The changes are not permanent, restart Proxmark3 to get default settings back.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  usart config [h] [b <baudrate>] [p <N|O|E>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h             This help");
    PrintAndLogEx(NORMAL, "           b <baudrate>  Baudrate");
    PrintAndLogEx(NORMAL, "           p <N|O|E>     Parity (None/Odd/Even)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      usart config b 9600");
    PrintAndLogEx(NORMAL, "      usart config b 9600 p N");
    PrintAndLogEx(NORMAL, "      usart config p E");
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
    if (srclen >= sizeof(payload.data))
        return PM3_EOVFLOW;
    memcpy(payload.data, srcdata, srclen);
    SendCommandNG(CMD_USART_TXRX, (uint8_t *)&payload, srclen + sizeof(payload.header));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_USART_TXRX, &resp, waittime + 500)) {
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
    uint8_t cmdp = 0;
    bool errors = false;
    uint32_t baudrate = 0;
    uint8_t parity = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_config();
            case 'p':
                switch (tolower(param_getchar(Cmd, cmdp + 1))) {
                    case 'n':
                        parity = 'N';
                        break;
                    case 'o':
                        parity = 'O';
                        break;
                    case 'e':
                        parity = 'E';
                        break;
                    default:
                        PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp + 1));
                        errors = true;
                        break;
                }
                cmdp += 2;
                break;
            case 'b':
                baudrate = param_get32ex(Cmd, cmdp + 1, 0, 10);
                if (baudrate == 0) {
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp + 1));
                    errors = true;
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
    if (errors || ((baudrate == 0) && (parity == 0))) {
        usage_usart_config();
        return PM3_EINVARG;
    }
    return set_usart_config(baudrate, parity);
}

static int usart_bt_testcomm(uint32_t baudrate, uint8_t parity) {
    int ret = set_usart_config(baudrate, parity);
    if (ret != PM3_SUCCESS)
        return ret;

    char *string = "AT+VERSION";
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;

    PrintAndLogEx(SUCCESS, "TX (%3u):%.*s at %u 8%c1", strlen(string), strlen(string), string, baudrate, parity);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000); // such large timeout needed
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
        if (strcmp((char *)data, "hc01.comV2.0") == 0) {
            PrintAndLogEx(SUCCESS, "Add-on " _GREEN_("found!"), len, len, data);
            return PM3_SUCCESS;
        }
    }
    return PM3_ENODATA;
}

static int CmdUsartBtFactory(const char *Cmd) {
// take care to define compatible settings:
# define BTADDON_BAUD_AT  "AT+BAUD8"
# define BTADDON_BAUD_NUM "115200"
    uint8_t cmdp = 0;
    bool errors = false;
    uint32_t baudrate = 0;
    uint8_t parity = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_bt_factory();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) {
        usage_usart_bt_factory();
        return PM3_EINVARG;
    }

    if (USART_BAUD_RATE != atoi(BTADDON_BAUD_NUM)) {
        PrintAndLogEx(WARNING, _RED_("WARNING:") "current Proxmark3 firmware has default USART baudrate = %i", USART_BAUD_RATE);
        PrintAndLogEx(WARNING, "Current btfactory implementation is hardcoded to " BTADDON_BAUD_NUM " bauds");
        return PM3_ENOTIMPL;
    }

    PrintAndLogEx(WARNING, _RED_("WARNING: process only if strictly needed!"));
    PrintAndLogEx(WARNING, "This requires BT turned ON and NOT connected!");
    PrintAndLogEx(WARNING, "Is the add-on blue light blinking? (Say 'n' if you want to abort) [y/n]");
    while (!ukbhit()) {
        msleep(200);
    }

    if (tolower(getchar()) != 'y') {
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
    char *string;
    uint8_t data[PM3_CMD_DATA_SIZE];
    size_t len = 0;
    memset(data, 0, sizeof(data));

    string = "AT+NAMEPM3_RDV4.0";
    PrintAndLogEx(SUCCESS, "TX (%3u):%.*s", strlen(string), strlen(string), string);

    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
        if (strcmp((char *)data, "OKsetname") == 0) {
            PrintAndLogEx(SUCCESS, "Name set to " _GREEN_("PM3_RDV4.0"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+NAME: " _YELLOW_("%.*s"), len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
        return PM3_ESOFT;
    }

    memset(data, 0, sizeof(data));
    len = 0;
    string = "AT+ROLE=S";
    PrintAndLogEx(SUCCESS, "TX (%3u):%.*s", strlen(string), strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
        if (strcmp((char *)data, "OK+ROLE:S") == 0) {
            PrintAndLogEx(SUCCESS, "Role set to " _GREEN_("Slave"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+ROLE=S: " _YELLOW_("%.*s"), len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
        return PM3_ESOFT;
    }

    memset(data, 0, sizeof(data));
    len = 0;
    string = "AT+PIN1234";
    PrintAndLogEx(SUCCESS, "TX (%3u):%.*s", strlen(string), strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
        if (strcmp((char *)data, "OKsetPIN") == 0) {
            PrintAndLogEx(SUCCESS, "PIN set to " _GREEN_("1234"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+PIN: " _YELLOW_("%.*s"), len, data);
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
        PrintAndLogEx(SUCCESS, "TX (%3u):%.*s", strlen(string), strlen(string), string);

        ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
        if (ret == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
            if (strcmp((char *)data, "OK None") == 0) {
                PrintAndLogEx(SUCCESS, "Parity set to " _GREEN_("None"));
            } else {
                PrintAndLogEx(WARNING, "Unexpected response to AT+P: " _YELLOW_("%.*s"), len, data);
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
        PrintAndLogEx(SUCCESS, "TX (%3u):%.*s", strlen(string), strlen(string), string);

        ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
        if (ret == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "RX (%3u):%.*s", len, len, data);
            if (strcmp((char *)data, "OK" BTADDON_BAUD_NUM) == 0) {
                PrintAndLogEx(SUCCESS, "Baudrate set to " _GREEN_(BTADDON_BAUD_NUM));
            } else {
                PrintAndLogEx(WARNING, "Unexpected response to AT+BAUD: " _YELLOW_("%.*s"), len, data);
            }
        } else {
            PrintAndLogEx(WARNING, "Lost contact with add-on, please try again");
            return PM3_ESOFT;
        }
    }

    if ((baudrate != USART_BAUD_RATE) || (parity != USART_PARITY)) {
        PrintAndLogEx(WARNING, "Add-on uart settings changed, please turn BT add-on OFF and ON again, then press any key.");
        while (!ukbhit()) {
            msleep(200);
        }
        getchar();
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
    uint8_t cmdp = 0;
    bool errors = false;
    char pin[5] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_bt_pin();
            case 'd':
                if (param_getstr(Cmd, cmdp + 1, pin, sizeof(pin)) != sizeof(pin) - 1) {
                    PrintAndLogEx(FAILED, "PIN has wrong length, must be 4 digits");
                    errors = true;
                    break;
                }
                for (size_t i = 0; i < sizeof(pin) - 1; i++) {
                    if ((pin[i] < '0') || (pin[i] > '9')) {
                        PrintAndLogEx(FAILED, "PIN has wrong char \"%c\", must be 4 digits", pin[i]);
                        errors = true;
                        break;
                    }
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
        usage_usart_bt_pin();
        return PM3_EINVARG;
    }
    char string[6 + sizeof(pin)] = {0};
    sprintf(string, "AT+PIN%s", pin);
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
//    PrintAndLogEx(NORMAL, "TX (%3u):%.*s", strlen(string), strlen(string), string);
    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 600);
    if (ret == PM3_ENODATA) {
        PrintAndLogEx(FAILED, "No response from add-on, is it ON and blinking?");
        return ret;
    }
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Command failed, ret=%i", ret);
        return ret;
    }
//    PrintAndLogEx(NORMAL, "RX (%3u):%.*s", len, len, data);
    if (strcmp((char *)data, "OKsetPIN") == 0) {
        PrintAndLogEx(NORMAL, "PIN changed " _GREEN_("successfully"));
    } else {
        PrintAndLogEx(WARNING, "Unexpected answer: %.*s", len, data);
    }
    return PM3_SUCCESS;
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
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == '\\')) {
            i++;
            string2[i2++] = '\\';
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == '"')) {
            i++;
            string2[i2++] = '"';
            continue;
        }
        if (string[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == 'r')) {
            i++;
            string2[i2++] = '\r';
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == 'n')) {
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
    uint32_t waittime = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_rx();
            case 't':
                waittime = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
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
    int ret = usart_rx(data, &len, waittime);
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
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == '\\')) {
            i++;
            string2[i2++] = '\\';
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == '"')) {
            i++;
            string2[i2++] = '"';
            continue;
        }
        if (string[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == 'r')) {
            i++;
            string2[i2++] = '\r';
            continue;
        }
        if ((i < n - 1) && (string[i] == '\\') && (string[i + 1] == 'n')) {
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
    uint32_t waittime = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_usart_rxhex();
            case 't':
                waittime = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
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
    int ret = usart_rx(data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    print_hex_break(data, len, 32);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable,          "This help"},
    {"btpin",        CmdUsartBtPin,      IfPm3FpcUsartHostFromUsb, "Change BT add-on PIN"},
    {"btfactory",    CmdUsartBtFactory,  IfPm3FpcUsartHostFromUsb, "Reset BT add-on to factory settings"},
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
    return 0;
}

int CmdUsart(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
