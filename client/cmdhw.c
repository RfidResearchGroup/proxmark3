//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hardware commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ui.h"
#include "proxmark3.h"
#include "cmdparser.h"
#include "cmdhw.h"
#include "cmdmain.h"
#include "cmddata.h"

/* low-level hardware control */

static int CmdHelp(const char *Cmd);

static void lookupChipID(uint32_t iChipID, uint32_t mem_used) {
    char asBuff[120];
    memset(asBuff, 0, sizeof(asBuff));
    uint32_t mem_avail = 0;
    PrintAndLogEx(NORMAL, "\n [ Hardware ] ");

    switch (iChipID) {
        case 0x270B0A40:
            sprintf(asBuff, "AT91SAM7S512 Rev A");
            break;
        case 0x270B0A4F:
            sprintf(asBuff, "AT91SAM7S512 Rev B");
            break;
        case 0x270D0940:
            sprintf(asBuff, "AT91SAM7S256 Rev A");
            break;
        case 0x270B0941:
            sprintf(asBuff, "AT91SAM7S256 Rev B");
            break;
        case 0x270B0942:
            sprintf(asBuff, "AT91SAM7S256 Rev C");
            break;
        case 0x270B0943:
            sprintf(asBuff, "AT91SAM7S256 Rev D");
            break;
        case 0x270C0740:
            sprintf(asBuff, "AT91SAM7S128 Rev A");
            break;
        case 0x270A0741:
            sprintf(asBuff, "AT91SAM7S128 Rev B");
            break;
        case 0x270A0742:
            sprintf(asBuff, "AT91SAM7S128 Rev C");
            break;
        case 0x270A0743:
            sprintf(asBuff, "AT91SAM7S128 Rev D");
            break;
        case 0x27090540:
            sprintf(asBuff, "AT91SAM7S64 Rev A");
            break;
        case 0x27090543:
            sprintf(asBuff, "AT91SAM7S64 Rev B");
            break;
        case 0x27090544:
            sprintf(asBuff, "AT91SAM7S64 Rev C");
            break;
        case 0x27080342:
            sprintf(asBuff, "AT91SAM7S321 Rev A");
            break;
        case 0x27080340:
            sprintf(asBuff, "AT91SAM7S32 Rev A");
            break;
        case 0x27080341:
            sprintf(asBuff, "AT91SAM7S32 Rev B");
            break;
        case 0x27050241:
            sprintf(asBuff, "AT9SAM7S161 Rev A");
            break;
        case 0x27050240:
            sprintf(asBuff, "AT91SAM7S16 Rev A");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= uC: %s", asBuff);
    switch ((iChipID & 0xE0) >> 5) {
        case 1:
            sprintf(asBuff, "ARM946ES");
            break;
        case 2:
            sprintf(asBuff, "ARM7TDMI");
            break;
        case 4:
            sprintf(asBuff, "ARM920T");
            break;
        case 5:
            sprintf(asBuff, "ARM926EJS");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Embedded Processor: %s", asBuff);
    switch ((iChipID & 0xF00) >> 8) {
        case 0:
            mem_avail = 0;
            break;
        case 1:
            mem_avail = 8;
            break;
        case 2:
            mem_avail = 16;
            break;
        case 3:
            mem_avail = 32;
            break;
        case 5:
            mem_avail = 64;
            break;
        case 7:
            mem_avail = 128;
            break;
        case 9:
            mem_avail = 256;
            break;
        case 10:
            mem_avail = 512;
            break;
        case 12:
            mem_avail = 1024;
            break;
        case 14:
            mem_avail = 2048;
            break;
    }

    uint32_t mem_left = 0;
    if (mem_avail > 0)
        mem_left = (mem_avail * 1024) - mem_used;

    PrintAndLogEx(NORMAL, "  --= Nonvolatile Program Memory Size: %uK bytes, Used: %u bytes (%2.0f%%) Free: %u bytes (%2.0f%%)",
                  mem_avail,
                  mem_used,
                  mem_avail == 0 ? 0.0f : (float)mem_used / (mem_avail * 1024) * 100,
                  mem_left,
                  mem_avail == 0 ? 0.0f : (float)mem_left / (mem_avail * 1024) * 100
                 );

    switch ((iChipID & 0xF000) >> 12) {
        case 0:
            sprintf(asBuff, "None");
            break;
        case 1:
            sprintf(asBuff, "8K bytes");
            break;
        case 2:
            sprintf(asBuff, "16K bytes");
            break;
        case 3:
            sprintf(asBuff, "32K bytes");
            break;
        case 5:
            sprintf(asBuff, "64K bytes");
            break;
        case 7:
            sprintf(asBuff, "128K bytes");
            break;
        case 9:
            sprintf(asBuff, "256K bytes");
            break;
        case 10:
            sprintf(asBuff, "512K bytes");
            break;
        case 12:
            sprintf(asBuff, "1024K bytes");
            break;
        case 14:
            sprintf(asBuff, "2048K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Second Nonvolatile Program Memory Size: %s", asBuff);
    switch ((iChipID & 0xF0000) >> 16) {
        case 1:
            sprintf(asBuff, "1K bytes");
            break;
        case 2:
            sprintf(asBuff, "2K bytes");
            break;
        case 3:
            sprintf(asBuff, "6K bytes");
            break;
        case 4:
            sprintf(asBuff, "112K bytes");
            break;
        case 5:
            sprintf(asBuff, "4K bytes");
            break;
        case 6:
            sprintf(asBuff, "80K bytes");
            break;
        case 7:
            sprintf(asBuff, "160K bytes");
            break;
        case 8:
            sprintf(asBuff, "8K bytes");
            break;
        case 9:
            sprintf(asBuff, "16K bytes");
            break;
        case 10:
            sprintf(asBuff, "32K bytes");
            break;
        case 11:
            sprintf(asBuff, "64K bytes");
            break;
        case 12:
            sprintf(asBuff, "128K bytes");
            break;
        case 13:
            sprintf(asBuff, "256K bytes");
            break;
        case 14:
            sprintf(asBuff, "96K bytes");
            break;
        case 15:
            sprintf(asBuff, "512K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Internal SRAM Size: %s", asBuff);
    switch ((iChipID & 0xFF00000) >> 20) {
        case 0x19:
            sprintf(asBuff, "AT91SAM9xx Series");
            break;
        case 0x29:
            sprintf(asBuff, "AT91SAM9XExx Series");
            break;
        case 0x34:
            sprintf(asBuff, "AT91x34 Series");
            break;
        case 0x37:
            sprintf(asBuff, "CAP7 Series");
            break;
        case 0x39:
            sprintf(asBuff, "CAP9 Series");
            break;
        case 0x3B:
            sprintf(asBuff, "CAP11 Series");
            break;
        case 0x40:
            sprintf(asBuff, "AT91x40 Series");
            break;
        case 0x42:
            sprintf(asBuff, "AT91x42 Series");
            break;
        case 0x55:
            sprintf(asBuff, "AT91x55 Series");
            break;
        case 0x60:
            sprintf(asBuff, "AT91SAM7Axx Series");
            break;
        case 0x61:
            sprintf(asBuff, "AT91SAM7AQxx Series");
            break;
        case 0x63:
            sprintf(asBuff, "AT91x63 Series");
            break;
        case 0x70:
            sprintf(asBuff, "AT91SAM7Sxx Series");
            break;
        case 0x71:
            sprintf(asBuff, "AT91SAM7XCxx Series");
            break;
        case 0x72:
            sprintf(asBuff, "AT91SAM7SExx Series");
            break;
        case 0x73:
            sprintf(asBuff, "AT91SAM7Lxx Series");
            break;
        case 0x75:
            sprintf(asBuff, "AT91SAM7Xxx Series");
            break;
        case 0x92:
            sprintf(asBuff, "AT91x92 Series");
            break;
        case 0xF0:
            sprintf(asBuff, "AT75Cxx Series");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Architecture Identifier: %s", asBuff);
    switch ((iChipID & 0x70000000) >> 28) {
        case 0:
            sprintf(asBuff, "ROM");
            break;
        case 1:
            sprintf(asBuff, "ROMless or on-chip Flash");
            break;
        case 2:
            sprintf(asBuff, "Embedded Flash Memory");
            break;
        case 3:
            sprintf(asBuff, "ROM and Embedded Flash Memory\nNVPSIZ is ROM size\nNVPSIZ2 is Flash size");
            break;
        case 4:
            sprintf(asBuff, "SRAM emulating ROM");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Nonvolatile Program Memory Type: %s", asBuff);
}

static int CmdDetectReader(const char *Cmd) {
    uint16_t arg = 0;
    // 'l' means LF - 125/134 kHz
    if (*Cmd == 'l') {
        arg = 1;
    } else if (*Cmd == 'h') {
        arg = 2;
    } else if (*Cmd != '\0') {
        PrintAndLogEx(NORMAL, "use 'detectreader' or 'detectreader l' or 'detectreader h'");
        return PM3_EINVARG;
    }
    clearCommandBuffer();
    SendCommandOLD(CMD_LISTEN_READER_FIELD, arg, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

// ## FPGA Control
static int CmdFPGAOff(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandOLD(CMD_FPGA_MAJOR_MODE_OFF, 0, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

#ifdef WITH_LCD
static int CmdLCD(const char *Cmd) {
    int i, j;
    sscanf(Cmd, "%x %d", &i, &j);
    while (j--) {
        clearCommandBuffer();
        SendCommandOLD(CMD_LCD, i & 0x1ff, 0, 0, NULL, 0);
    }
    return PM3_SUCCESS;
}

static int CmdLCDReset(const char *Cmd) {
    clearCommandBuffer();
    SendCommandOLD(CMD_LCD_RESET, strtol(Cmd, NULL, 0), 0, 0, NULL, 0);
    return PM3_SUCCESS;
}
#endif

static int CmdReadmem(const char *Cmd) {
    clearCommandBuffer();
    SendCommandOLD(CMD_READ_MEM, strtol(Cmd, NULL, 0), 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdReset(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandOLD(CMD_HARDWARE_RESET, 0, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
static int CmdSetDivisor(const char *Cmd) {
    uint16_t arg = strtol(Cmd, NULL, 0);

    if (arg < 19 || arg > 255) {
        PrintAndLogEx(NORMAL, "divisor must be between 19 and 255");
        return PM3_EINVARG;
    }
    // 12 000 000 (12Mhz)
    clearCommandBuffer();
    SendCommandOLD(CMD_SET_LF_DIVISOR, arg, 0, 0, NULL, 0);
    PrintAndLogEx(NORMAL, "Divisor set, expected %.1f KHz", ((double)12000 / (arg + 1)));
    return PM3_SUCCESS;
}

static int CmdSetMux(const char *Cmd) {

    if (strlen(Cmd) < 5) {
        PrintAndLogEx(NORMAL, "expected:  lopkd | loraw | hipkd | hiraw");
        return PM3_EINVARG;
    }

    uint16_t arg = 0;
    if (strcmp(Cmd, "lopkd") == 0)      arg = 0;
    else if (strcmp(Cmd, "loraw") == 0) arg = 1;
    else if (strcmp(Cmd, "hipkd") == 0) arg = 2;
    else if (strcmp(Cmd, "hiraw") == 0) arg = 3;
    else {
        PrintAndLogEx(NORMAL, "expected:  lopkd | loraw | hipkd | hiraw");
        return PM3_EINVARG;
    }
    clearCommandBuffer();
    SendCommandOLD(CMD_SET_ADC_MUX, arg, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdTune(const char *Cmd) {
    return CmdTuneSamples(Cmd);
}

static int CmdVersion(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    pm3_version(true);
    return PM3_SUCCESS;
}

static int CmdStatus(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandOLD(CMD_STATUS, 0, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1900))
        PrintAndLogEx(NORMAL, "Status command failed. USB Speed Test timed out");
    return PM3_SUCCESS;
}

static int CmdPing(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_PING, 0, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1000))
        PrintAndLogEx(NORMAL, "Ping " _GREEN_("successful"));
    else
        PrintAndLogEx(NORMAL, "Ping " _RED_("failed"));
    return PM3_SUCCESS;
}

static int CmdPingNG(const char *Cmd) {
    uint32_t len = strtol(Cmd, NULL, 0);
    if (len > USB_CMD_DATA_SIZE)
        len = USB_CMD_DATA_SIZE;
    PrintAndLogEx(NORMAL, "PingNG sent with payload len=%d", len);
    clearCommandBuffer();
    PacketResponseNG resp;
    uint8_t data[USB_CMD_DATA_SIZE] = {0};
    for (uint16_t i = 0; i < len; i++)
        data[i] = i & 0xFF;
    SendCommandNG(CMD_PING, data, len);
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000)) {
        bool error = false;
        if (len)
            error = memcmp(data, resp.data.asBytes, len) != 0;
        PrintAndLogEx(NORMAL, "PingNG response received, content is %s", error ? _RED_("NOT ok") : _GREEN_("ok"));
    } else
        PrintAndLogEx(NORMAL, "PingNG response " _RED_("timeout"));
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",          CmdHelp,        1, "This help"},
    {"detectreader",  CmdDetectReader, 0, "['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)"},
    {"fpgaoff",       CmdFPGAOff,     0, "Set FPGA off"},
#ifdef WITH_LCD
    {"lcd",           CmdLCD,         0, "<HEX command> <count> -- Send command/data to LCD"},
    {"lcdreset",      CmdLCDReset,    0, "Hardware reset LCD"},
#endif
    {"readmem",       CmdReadmem,     0, "[address] -- Read memory at decimal address from flash"},
    {"reset",         CmdReset,       0, "Reset the Proxmark3"},
    {"setlfdivisor",  CmdSetDivisor,  0, "<19 - 255> -- Drive LF antenna at 12Mhz/(divisor+1)"},
    {"setmux",        CmdSetMux,      0, "<loraw|hiraw|lopkd|hipkd> -- Set the ADC mux to a specific value"},
    {"tune",          CmdTune,        0, "Measure antenna tuning"},
    {"version",       CmdVersion,     0, "Show version information about the connected Proxmark3"},
    {"status",        CmdStatus,      0, "Show runtime status information about the connected Proxmark3"},
    {"ping",          CmdPing,        0, "Test if the Proxmark3 is responding"},
    {"pingng",        CmdPingNG,      0, "Test if the Proxmark3 is responsive, using new frame format (experimental)"},
    {NULL, NULL, 0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHW(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

void pm3_version(bool verbose) {
    if (!verbose)
        return;
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandOLD(CMD_VERSION, 0, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {
        PrintAndLogEx(NORMAL, "\n" _BLUE_(" [ Proxmark3 RFID instrument ]") "\n");
        char s[60] = {0};
#if defined(WITH_FLASH) || defined(WITH_SMARTCARD) || defined(WITH_FPC)
        strncat(s, "build for RDV40 with ", sizeof(s) - strlen(s) - 1);
#endif
#ifdef WITH_FLASH
        strncat(s, "flashmem; ", sizeof(s) - strlen(s) - 1);
#endif
#ifdef WITH_SMARTCARD
        strncat(s, "smartcard; ", sizeof(s) - strlen(s) - 1);
#endif
#ifdef WITH_FPC
#ifdef WITH_FPC_HOST
        strncat(s, "fpc-host; ", sizeof(s) - strlen(s) - 1);
#else
        strncat(s, "fpc; ", sizeof(s) - strlen(s) - 1);
#endif
#endif
        PrintAndLogEx(NORMAL, "\n [ CLIENT ]");
        PrintAndLogEx(NORMAL, "  client: iceman %s \n", s);

        PrintAndLogEx(NORMAL, (char *)resp.data.asBytes);
        lookupChipID(resp.oldarg[0], resp.oldarg[1]);
    }
    PrintAndLogEx(NORMAL, "\n");
}
