//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hardware commands
// low-level hardware control
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "usart_defs.h"
#include "ui.h"
#include "cmdhw.h"
#include "cmddata.h"

static int CmdHelp(const char *Cmd);

static int usage_dbg(void) {
    PrintAndLogEx(NORMAL, "Usage:  hw dbg [h] <debug level>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h    this help");
    PrintAndLogEx(NORMAL, "       <debug level>  (Optional) see list for valid levels");
    PrintAndLogEx(NORMAL, "           0 - no debug messages");
    PrintAndLogEx(NORMAL, "           1 - error messages");
    PrintAndLogEx(NORMAL, "           2 - plus information messages");
    PrintAndLogEx(NORMAL, "           3 - plus debug messages");
    PrintAndLogEx(NORMAL, "           4 - print even debug messages in timing critical functions");
    PrintAndLogEx(NORMAL, "               Note: this option therefore may cause malfunction itself");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hw dbg 3");
    return 0;
}

static int usage_hw_detectreader(void) {
    PrintAndLogEx(NORMAL, "Start to detect presences of reader field");
    PrintAndLogEx(NORMAL, "press pm3 button to change modes and finally exit");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hw detectreader [h] <L|H>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "       <type>     L = 125/134 kHz, H = 13.56 MHz");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hw detectreader L");
    return PM3_SUCCESS;
}

static int usage_hw_setmux(void) {
    PrintAndLogEx(NORMAL, "Set the ADC mux to a specific value");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hw setmux [h] <lopkd | loraw | hipkd | hiraw>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "       <type>     Low peak, Low raw, Hi peak, Hi raw");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hw setmux lopkd");
    return PM3_SUCCESS;
}

static int usage_hw_connect(void) {
    PrintAndLogEx(NORMAL, "Connects to a Proxmark3 device via specified serial port");
    PrintAndLogEx(NORMAL, "Baudrate here is only for physical UART or UART-BT, " _YELLOW_("not")"for USB-CDC or blue shark add-on");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hw connect [h] [p <port>] [b <baudrate>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       p <port>       Serial port to connect to, else retry the last used one");
    PrintAndLogEx(NORMAL, "       b <baudrate>   Baudrate");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hw connect p "SERIAL_PORT_EXAMPLE_H);
    PrintAndLogEx(NORMAL, "      hw connect p "SERIAL_PORT_EXAMPLE_H" b 115200");
    return PM3_SUCCESS;
}

static void lookupChipID(uint32_t iChipID, uint32_t mem_used) {
    char asBuff[120];
    memset(asBuff, 0, sizeof(asBuff));
    uint32_t mem_avail = 0;
    PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ Hardware ]"));

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

static int CmdDbg(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_dbg();

    uint8_t dbgMode = param_get8ex(Cmd, 0, 0, 10);
    if (dbgMode > 4) return usage_dbg();

    SendCommandNG(CMD_SET_DBGMODE, &dbgMode, 1);
    return PM3_SUCCESS;
}

static int CmdDetectReader(const char *Cmd) {
    uint8_t arg = 0;
    char c = toupper(Cmd[0]);
    switch (c) {
        case 'L':
            arg = 1;
            break;
        case 'H':
            arg = 2;
            break;
        default: {
            usage_hw_detectreader();
            return PM3_EINVARG;
        }
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LISTEN_READER_FIELD, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

// ## FPGA Control
static int CmdFPGAOff(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandNG(CMD_FPGA_MAJOR_MODE_OFF, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLCD(const char *Cmd) {
    int i, j;
    sscanf(Cmd, "%x %d", &i, &j);
    while (j--) {
        clearCommandBuffer();
        SendCommandMIX(CMD_LCD, i & 0x1ff, 0, 0, NULL, 0);
    }
    return PM3_SUCCESS;
}

static int CmdLCDReset(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandNG(CMD_LCD_RESET, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdReadmem(const char *Cmd) {
    uint32_t address = strtol(Cmd, NULL, 0);
    clearCommandBuffer();
    SendCommandNG(CMD_READ_MEM, (uint8_t *)&address, sizeof(address));
    return PM3_SUCCESS;
}

static int CmdReset(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandNG(CMD_HARDWARE_RESET, NULL, 0);
    PrintAndLogEx(INFO, "Proxmark3 has been reset.");
    return PM3_SUCCESS;
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
static int CmdSetDivisor(const char *Cmd) {
    uint8_t arg = param_get8ex(Cmd, 0, 95, 10);

    if (arg < 19) {
        PrintAndLogEx(ERR, "divisor must be between" _YELLOW_("19") " and " _YELLOW_("255"));
        return PM3_EINVARG;
    }
    // 12 000 000 (12MHz)
    clearCommandBuffer();
    SendCommandNG(CMD_LF_SET_DIVISOR, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(SUCCESS, "Divisor set, expected " _YELLOW_("%.1f")" kHz", ((double)12000 / (arg + 1)));
    return PM3_SUCCESS;
}

static int CmdSetMux(const char *Cmd) {

    if (strlen(Cmd) < 5) {
        usage_hw_setmux();
        return PM3_EINVARG;
    }

    str_lower((char *)Cmd);

    uint8_t arg = 0;
    if (strcmp(Cmd, "lopkd") == 0)
        arg = 0;
    else if (strcmp(Cmd, "loraw") == 0)
        arg = 1;
    else if (strcmp(Cmd, "hipkd") == 0)
        arg = 2;
    else if (strcmp(Cmd, "hiraw") == 0)
        arg = 3;
    else {
        usage_hw_setmux();
        return PM3_EINVARG;
    }
    clearCommandBuffer();
    SendCommandNG(CMD_SET_ADC_MUX, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

static int CmdStandalone(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    SendCommandNG(CMD_STANDALONE, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdTune(const char *Cmd) {
    return CmdTuneSamples(Cmd);
}

static int CmdVersion(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    pm3_version(true, false);
    return PM3_SUCCESS;
}

static int CmdStatus(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_STATUS, NULL, 0);
    if (WaitForResponseTimeout(CMD_STATUS, &resp, 2000) == false)
        PrintAndLogEx(WARNING, "Status command failed. Communication speed test timed out");
    return PM3_SUCCESS;
}

static int CmdTia(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    clearCommandBuffer();
    PrintAndLogEx(INFO, "Triggering new Timing Interval Acquisition (TIA)...");
    PacketResponseNG resp;
    SendCommandNG(CMD_TIA, NULL, 0);
    if (WaitForResponseTimeout(CMD_TIA, &resp, 2000) == false)
        PrintAndLogEx(WARNING, "TIA command failed. You probably need to unplug the Proxmark3.");
    PrintAndLogEx(INFO, "TIA done.");
    return PM3_SUCCESS;
}

static int CmdPing(const char *Cmd) {
    uint32_t len = strtol(Cmd, NULL, 0);
    if (len > PM3_CMD_DATA_SIZE)
        len = PM3_CMD_DATA_SIZE;
    if (len) {
        PrintAndLogEx(INFO, "Ping sent with payload len = %d", len);
    } else {
        PrintAndLogEx(INFO, "Ping sent");
    }
    clearCommandBuffer();
    PacketResponseNG resp;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    for (uint16_t i = 0; i < len; i++)
        data[i] = i & 0xFF;
    SendCommandNG(CMD_PING, data, len);
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000)) {
        if (len) {
            bool error = (memcmp(data, resp.data.asBytes, len) != 0);
            PrintAndLogEx((error) ? ERR : SUCCESS, "Ping response " _GREEN_("received") "and content is %s", error ? _RED_("NOT ok") : _GREEN_("OK"));
        } else {
            PrintAndLogEx(SUCCESS, "Ping response " _GREEN_("received"));
        }
    } else
        PrintAndLogEx(WARNING, "Ping response " _RED_("timeout"));
    return PM3_SUCCESS;
}

static int CmdConnect(const char *Cmd) {

    uint32_t baudrate = USART_BAUD_RATE;
    uint8_t cmdp = 0;
    char port[FILE_PATH_SIZE] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hw_connect();
            case 'p': {
                param_getstr(Cmd, cmdp + 1, port, sizeof(port));
                cmdp += 2;
                break;
            }
            case 'b':
                baudrate = param_get32ex(Cmd, cmdp + 1, USART_BAUD_RATE, 10);
                if (baudrate == 0)
                    return usage_hw_connect();
                cmdp += 2;
                break;
            default:
                usage_hw_connect();
                return PM3_EINVARG;
        }
    }

    // default back to previous used serial port
    if (strlen(port) == 0) {
        if (strlen((char *)conn.serial_port_name) == 0) {
            return usage_hw_connect();
        }
        memcpy(port, conn.serial_port_name, sizeof(port));
    }

    if (session.pm3_present) {
        CloseProxmark();
    }

    // 10 second timeout
    OpenProxmark(port, false, 10, false, baudrate);

    if (session.pm3_present && (TestProxmark() != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") "cannot communicate with the Proxmark3\n");
        CloseProxmark();
        return PM3_ENOTTY;
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",          CmdHelp,        AlwaysAvailable, "This help"},
    {"connect",       CmdConnect,     AlwaysAvailable, "connect Proxmark3 to serial port"},
    {"dbg",           CmdDbg,         IfPm3Present,    "Set Proxmark3 debug level"},
    {"detectreader",  CmdDetectReader, IfPm3Present,    "['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)"},
    {"fpgaoff",       CmdFPGAOff,     IfPm3Present,    "Set FPGA off"},
    {"lcd",           CmdLCD,         IfPm3Lcd,        "<HEX command> <count> -- Send command/data to LCD"},
    {"lcdreset",      CmdLCDReset,    IfPm3Lcd,        "Hardware reset LCD"},
    {"ping",          CmdPing,        IfPm3Present,    "Test if the Proxmark3 is responsive"},
    {"readmem",       CmdReadmem,     IfPm3Present,    "[address] -- Read memory at decimal address from flash"},
    {"reset",         CmdReset,       IfPm3Present,    "Reset the Proxmark3"},
    {"setlfdivisor",  CmdSetDivisor,  IfPm3Present,    "<19 - 255> -- Drive LF antenna at 12MHz/(divisor+1)"},
    {"setmux",        CmdSetMux,      IfPm3Present,    "Set the ADC mux to a specific value"},
    {"standalone",    CmdStandalone,  IfPm3Present,    "Jump to the standalone mode"},
    {"status",        CmdStatus,      IfPm3Present,    "Show runtime status information about the connected Proxmark3"},
    {"tia",           CmdTia,         IfPm3Present,    "Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider"},
    {"tune",          CmdTune,        IfPm3Present,    "Measure antenna tuning"},
    {"version",       CmdVersion,     IfPm3Present,    "Show version information about the connected Proxmark3"},
    {NULL, NULL, NULL, NULL}
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

void pm3_version(bool verbose, bool oneliner) {

#if defined(__MINGW64__)
# define PM3CLIENTCOMPILER "MinGW-w64 "
#elif defined(__MINGW32__)
# define PM3CLIENTCOMPILER "MinGW "
#elif defined(__clang__)
# define PM3CLIENTCOMPILER "Clang/LLVM "
#elif defined(__GNUC__) || defined(__GNUG__)
# define PM3CLIENTCOMPILER "GCC "
#else
# define PM3CLIENTCOMPILER "unknown compiler "
#endif

#if defined(__APPLE__) || defined(__MACH__)
# define PM3HOSTOS " OS:OSX"
#elif defined(__ANDROID__) || defined(ANDROID)
// must be tested before __linux__
# define PM3HOSTOS " OS:Android"
#elif defined(__linux__)
# define PM3HOSTOS " OS:Linux"
#elif defined(__FreeBSD__)
# define PM3HOSTOS " OS:FreeBSD"
#elif defined(__NetBSD__)
# define PM3HOSTOS " OS:NetBSD"
#elif defined(__OpenBSD__)
# define PM3HOSTOS " OS:OpenBSD"
#elif defined(__CYGWIN__)
# define PM3HOSTOS " OS:Cygwin"
#elif defined(_WIN64) | defined(__WIN64__)
// must be tested before _WIN32
# define PM3HOSTOS " OS:Windows (64b)"
#elif defined(_WIN32) | defined(__WIN32__)
# define PM3HOSTOS " OS:Windows (32b)"
#else
# define PM3HOSTOS " OS:unknown"
#endif

#if defined(__x86_64__)
# define PM3HOSTARCH " ARCH:x86_64"
#elif defined(__i386__)
# define PM3HOSTARCH " ARCH:x86"
#elif defined(__aarch64__)
# define PM3HOSTARCH " ARCH:aarch64"
#elif defined(__arm__)
# define PM3HOSTARCH " ARCH:arm"
#elif defined(__powerpc64__)
# define PM3HOSTARCH " ARCH:powerpc64"
#elif defined(__mips__)
# define PM3HOSTARCH " ARCH:mips"
#else
# define PM3HOSTARCH " ARCH:unknown"
#endif

    if (oneliner) {
        // For "proxmark3 -v", simple printf, avoid logging
        printf("Client: RRG/Iceman compiled with " PM3CLIENTCOMPILER __VERSION__ PM3HOSTOS PM3HOSTARCH "\n");
        return;
    }

    if (!verbose)
        return;

    PacketResponseNG resp;
    clearCommandBuffer();

    SendCommandNG(CMD_VERSION, NULL, 0);

    if (WaitForResponseTimeout(CMD_VERSION, &resp, 1000)) {
        PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ Proxmark3 RFID instrument ]"));
        PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ CLIENT ]"));
        PrintAndLogEx(NORMAL, "  client: RRG/Iceman"); // TODO version info?
        PrintAndLogEx(NORMAL, "  compiled with " PM3CLIENTCOMPILER __VERSION__ PM3HOSTOS PM3HOSTARCH);

        if (IfPm3Flash() == false && IfPm3Smartcard() == false && IfPm3FpcUsartHost() == false) {
            PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ PROXMARK3 ]"));
        } else {
            PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ PROXMARK3 RDV4 ]"));
            PrintAndLogEx(NORMAL, "  external flash:                  %s", IfPm3Flash() ? _GREEN_("present") : _YELLOW_("absent"));
            PrintAndLogEx(NORMAL, "  smartcard reader:                %s", IfPm3Smartcard() ? _GREEN_("present") : _YELLOW_("absent"));
            PrintAndLogEx(NORMAL, "\n " _YELLOW_("[ PROXMARK3 RDV4 Extras ]"));
            PrintAndLogEx(NORMAL, "  FPC USART for BT add-on support: %s", IfPm3FpcUsartHost() ? _GREEN_("present") : _YELLOW_("absent"));

            if (IfPm3FpcUsartDevFromUsb()) {
                PrintAndLogEx(NORMAL, "  FPC USART for developer support: %s", _GREEN_("present"));
            }
        }

        PrintAndLogEx(NORMAL, "");

        struct p {
            uint32_t id;
            uint32_t section_size;
            uint32_t versionstr_len;
            char versionstr[PM3_CMD_DATA_SIZE - 12];
        } PACKED;

        struct p *payload = (struct p *)&resp.data.asBytes;

        PrintAndLogEx(NORMAL,  payload->versionstr);

        lookupChipID(payload->id, payload->section_size);
    }
    PrintAndLogEx(NORMAL, "\n");
}
