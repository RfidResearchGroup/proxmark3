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
// BWM (battery/wireless module) commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cmdparser.h" // command_t
#include "cliparser.h"
#include "comms.h"
#include "usart_defs.h"
#include "ui.h"
#include "cmdbwm.h"
#include "cmdhw.h"
#include "commonutil.h"
#include "pm3_cmd.h"
#include "cmdflashmem.h" // loadFile_safe
#include "util_posix.h"

static int CmdBwmAutoOff(const char *Cmd) {
    // Positional sub-action (no dashes): hw bwm autooff on | off
    char verb[16] = {0};
    sscanf(Cmd, "%15s", verb);
    bool on  = (strcmp(verb, "on")  == 0);
    bool off = (strcmp(verb, "off") == 0);

    if (!on && !off) {
        // Not a recognised sub-action: render help (also serves -h / empty),
        // or error on a stray token, then stop.
        CLIParserContext *ctx;
        CLIParserInit(&ctx, "hw bwm autooff",
                      "Toggle automatic power-off when the PM5 is unplugged from USB (BWM only).\n"
                      "Default is " _GREEN_("on") ". When on, the board powers itself down ~10s after\n"
                      "USB is removed, so a BWM-equipped PM5 doesn't silently drain the battery.\n"
                      "Button power-on is unaffected. Disable for standalone/BLE use on battery.\n"
                      _YELLOW_("Runtime only:") " resets to on at each boot.",
                      "hw bwm autooff off   --> disable auto power-off\n"
                      "hw bwm autooff on    --> re-enable auto power-off");
        void *argtable[] = {
            arg_param_begin,
            arg_param_end
        };
        CLIExecWithReturn(ctx, Cmd, argtable, true);
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "specify " _YELLOW_("on") " or " _YELLOW_("off"));
        return PM3_EINVARG;
    }

    uint8_t payload = off ? 0 : 1;   // on -> 1 (enable), off -> 0 (disable)

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_AUTOOFF, &payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_BWM_AUTOOFF, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command timeout (is this a PM5?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_ENOTIMPL) {
        PrintAndLogEx(WARNING, "firmware built without auto power-off support");
        return resp.status;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to set auto power-off");
        return resp.status;
    }
    PrintAndLogEx(SUCCESS, "Auto power-off %s.", payload ? _GREEN_("enabled") : _YELLOW_("disabled"));
    return PM3_SUCCESS;
}

static int CmdBWMWifi(const char *Cmd) {
    // Sub-actions that carry no other arguments are positional keywords now:
    //   hw bwm wifi status   (was --status)
    //   hw bwm wifi stop     (was --stop)
    // Bringing WiFi up still takes value flags, so it stays the default
    // (no-keyword) form: hw bwm wifi --ssid <ssid> --pwd <pwd> [--port <n>]
    char verb[16] = {0};
    sscanf(Cmd, "%15s", verb);

    if (strcmp(verb, "status") == 0) {
        uint8_t q[1] = { BWM_WIFI_ACTION_STATUS };
        clearCommandBuffer();
        SendCommandNG(CMD_PM5_BWM_WIFI, q, sizeof(q));
        PacketResponseNG r;
        if (WaitForResponseTimeout(CMD_PM5_BWM_WIFI, &r, 5000) == false) {
            PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
            return PM3_ETIMEOUT;
        }
        if (r.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "could not query BWM WiFi status (BWM present?)");
            return r.status;
        }
        uint8_t state = (r.length >= 1) ? r.data.asBytes[0] : 0xFF;
        uint32_t ip = 0;
        if (r.length >= 5) {
            ip = r.data.asBytes[1] | (r.data.asBytes[2] << 8) | (r.data.asBytes[3] << 16) | ((uint32_t)r.data.asBytes[4] << 24);
        }
        switch (state) {
            case 0xFF:
                PrintAndLogEx(INFO, "BWM WiFi disabled (BLE-only). Bring it up with " _YELLOW_("hw bwm wifi --ssid <ssid> --pwd <pwd>"));
                break;
            case 2: // connected
                if (ip) {
                    PrintAndLogEx(SUCCESS, "BWM WiFi connected, IP " _YELLOW_("%u.%u.%u.%u"),
                                  ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
                    PrintAndLogEx(HINT, "Connect with: " _YELLOW_("pm3 -p tcp:%u.%u.%u.%u:<port>"),
                                  ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
                } else {
                    PrintAndLogEx(INFO, "BWM WiFi associated, waiting for a DHCP lease...");
                }
                break;
            case 1: // connecting
                PrintAndLogEx(INFO, "BWM WiFi connecting...");
                break;
            case 3: // reconnect wait
                PrintAndLogEx(INFO, "BWM WiFi reconnecting...");
                break;
            case 4: // task stopped
                PrintAndLogEx(INFO, "BWM WiFi connect task stopped");
                break;
            case 0: // disconnected
            default:
                PrintAndLogEx(INFO, "BWM WiFi configured but not connected");
                break;
        }
        return PM3_SUCCESS;
    }

    if (strcmp(verb, "stop") == 0) {
        uint8_t off[1] = { BWM_WIFI_ACTION_STOP };
        clearCommandBuffer();
        SendCommandNG(CMD_PM5_BWM_WIFI, off, sizeof(off));
        PacketResponseNG r;
        if (WaitForResponseTimeout(CMD_PM5_BWM_WIFI, &r, 5000) == false) {
            PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
            return PM3_ETIMEOUT;
        }
        if (r.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "failed to disable BWM WiFi");
            return r.status;
        }
        PrintAndLogEx(SUCCESS, "BWM WiFi disabled (back to BLE-only)");
        return PM3_SUCCESS;
    }

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bwm wifi",
                  "Bring up the BWM in STA + TCP-server mode: join a WiFi network and\n"
                  "start a TCP server so the client can connect over WiFi. PM5 only.\n"
                  "Sub-actions (no dashes): 'status' shows state, 'stop' tears WiFi down.",
                  "hw bwm wifi status                              --> show connection state + IP\n"
                  "hw bwm wifi stop                                --> tear down WiFi, back to BLE-only\n"
                  "hw bwm wifi --ssid Home --pwd secret            --> bring up, port 7777\n"
                  "hw bwm wifi --ssid Home --pwd secret --port 9000");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "ssid", "<ssid>", "WiFi SSID to join"),
        arg_str0(NULL, "pwd",  "<pwd>",  "WiFi password (omit for open network)"),
        arg_int0(NULL, "port", "<dec>",  "TCP server listen port (default 7777)"),
        arg_str0(NULL, "hostname", "<name>", "DHCP hostname (default Proxmark5)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t ssid[64] = {0};
    int ssid_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 1), ssid, sizeof(ssid) - 1, &ssid_len);

    uint8_t pwd[64] = {0};
    int pwd_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), pwd, sizeof(pwd) - 1, &pwd_len);

    int port = arg_get_int_def(ctx, 3, 7777);

    uint8_t host[33] = {0};
    int host_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), host, sizeof(host) - 1, &host_len);
    if (host_len == 0) {
        strcpy((char *)host, "Proxmark5");
        host_len = 9;
    }
    CLIParserFree(ctx);

    if (ssid_len == 0) {
        PrintAndLogEx(FAILED, "an SSID is required (or " _YELLOW_("hw bwm wifi stop") " to tear down)");
        return PM3_EINVARG;
    }
    if (port < 1 || port > 65535) {
        PrintAndLogEx(FAILED, "port must be 1..65535");
        return PM3_EINVARG;
    }

    // payload: [action:u8][port:u16 LE][ssid\0][pwd\0][hostname\0]
    uint8_t data[200] = {0};
    int n = 0;
    data[n++] = BWM_WIFI_ACTION_START;
    data[n++] = (uint8_t)(port & 0xFF);
    data[n++] = (uint8_t)((port >> 8) & 0xFF);
    memcpy(&data[n], ssid, ssid_len);
    n += ssid_len;
    data[n++] = 0;
    memcpy(&data[n], pwd,  pwd_len);
    n += pwd_len;
    data[n++] = 0;
    memcpy(&data[n], host, host_len);
    n += host_len;
    data[n++] = 0;

    PrintAndLogEx(INFO, "Bringing up BWM WiFi (SSID \"%s\", port %d)... this can take ~15s", ssid, port);

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_WIFI, data, n);
    PacketResponseNG resp;
    // ARM blocks during join + DHCP wait, so allow a long client timeout
    if (WaitForResponseTimeout(CMD_PM5_BWM_WIFI, &resp, 60000) == false) {
        PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "BWM WiFi bring-up failed (check SSID/password and signal)");
        PrintAndLogEx(HINT, "If it may have joined after DHCP, check: " _YELLOW_("hw bwm wifi status"));
        return resp.status;
    }

    uint32_t ip = resp.data.asDwords[0];
    PrintAndLogEx(SUCCESS, "BWM on WiFi at %u.%u.%u.%u",
                  ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    PrintAndLogEx(HINT, "Connect with: " _YELLOW_("pm3 -p tcp:%u.%u.%u.%u:%d"),
                  ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, port);
    PrintAndLogEx(HINT, "Or by name (router-dependent): " _YELLOW_("pm3 -p tcp:%s:%d"), host, port);
    return PM3_SUCCESS;
}

static int CmdBwmCharge(const char *Cmd) {
    // Positional sub-action (no dashes): hw bwm charge on | off
    char verb[16] = {0};
    sscanf(Cmd, "%15s", verb);
    bool on  = (strcmp(verb, "on")  == 0);
    bool off = (strcmp(verb, "off") == 0);

    if (!on && !off) {
        // Not a recognised sub-action: render help (also serves -h / empty),
        // or error on a stray token, then stop.
        CLIParserContext *ctx;
        CLIParserInit(&ctx, "hw bwm charge",
                      "Enable or disable BWM battery charging by clearing/setting the\n"
                      "AW32001E charge-enable bit (CEB, REG01[3]). PM5 only.\n"
                      _RED_("One-shot:") " the charger watchdog reverts this after ~160 s unless\n"
                      "serviced, so charging may stop on its own. Use to nudge a top-up.",
                      "hw bwm charge off    --> disable charging\n"
                      "hw bwm charge on     --> enable charging");
        void *argtable[] = {
            arg_param_begin,
            arg_param_end
        };
        CLIExecWithReturn(ctx, Cmd, argtable, true);
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "specify " _YELLOW_("on") " or " _YELLOW_("off"));
        return PM3_EINVARG;
    }

    uint8_t payload = off ? 0 : 1;   // on -> 1 (enable), off -> 0 (disable)
    PrintAndLogEx(INFO, "%s BWM battery charging...", off ? "Disabling" : "Enabling");

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_CHARGE_EN, &payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_BWM_CHARGE_EN, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "charger did not respond (check BWM present)");
        return resp.status;
    }
    PrintAndLogEx(SUCCESS, "Charging %s. Verify with " _YELLOW_("hw status") ".",
                  off ? "disabled" : "enabled");
    if (off == false) {
        PrintAndLogEx(HINT, "Reverts on the charger watchdog (~160 s) if not serviced.");
    }
    return PM3_SUCCESS;
}

static int CmdBwmVchg(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bwm vchg",
                  "Set the BWM charger (AW32001E) charge-voltage regulation target.\n"
                  "Lowering it below 4.2 V reduces top-of-charge stress and extends cell\n"
                  "life. Snaps to the nearest 15 mV step; clamped to 3600..4200 mV. This is\n"
                  "a runtime register write (reverts on the charger watchdog / POR); the\n"
                  "firmware re-applies the " _YELLOW_("4100 mV") " default at every boot. PM5 only.",
                  "hw bwm vchg              --> set charge voltage to default 4100 mV (->4.095 V)\n"
                  "hw bwm vchg --mv 4200    --> set charge voltage to 4200 mV");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "mv", "<mV>", "charge voltage in mV (default 4100, clamped 3600..4200)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int mv = arg_get_int_def(ctx, 1, 4100);
    CLIParserFree(ctx);

    if (mv < 3600 || mv > 4200) {
        PrintAndLogEx(WARNING, "charge voltage out of range (3600..4200 mV): %d", mv);
        return PM3_EINVARG;
    }

    uint8_t payload[2] = { (uint8_t)(mv & 0xFF), (uint8_t)((mv >> 8) & 0xFF) };
    PrintAndLogEx(INFO, "Setting BWM charge voltage to " _YELLOW_("%d mV") "...", mv);

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_SET_VCHG, payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_BWM_SET_VCHG, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to set charge voltage - check BWM present");
        return resp.status;
    }
    uint16_t applied = (resp.length >= 2) ? (resp.data.asBytes[0] | (resp.data.asBytes[1] << 8)) : 0;
    PrintAndLogEx(SUCCESS, "Charge voltage set to " _YELLOW_("%u.%03u V") " (nearest 15 mV step).", applied / 1000, applied % 1000);
    return PM3_SUCCESS;
}

static int CmdBwmSetCap(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bwm setcap",
                  "Program the BWM fuel gauge (BQ27427) Design Capacity for the fitted cell.\n"
                  "Run ONCE after fitting or replacing the battery. This triggers a gauge\n"
                  "config-update; do not run it repeatedly, as that disrupts the Impedance\n"
                  "Track learning cycle. PM5 only.",
                  "hw bwm setcap             --> set design capacity to default 500 mAh\n"
                  "hw bwm setcap --cap 500   --> set design capacity to 500 mAh");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "cap", "<mAh>", "design capacity in mAh (default 500)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int cap = arg_get_int_def(ctx, 1, 500);
    CLIParserFree(ctx);

    if (cap <= 0 || cap > 32000) {
        PrintAndLogEx(WARNING, "capacity out of range: %d mAh", cap);
        return PM3_EINVARG;
    }

    uint8_t payload[2] = { (uint8_t)(cap & 0xFF), (uint8_t)((cap >> 8) & 0xFF) };
    PrintAndLogEx(INFO, "Programming BWM gauge design capacity to " _YELLOW_("%d mAh") "...", cap);
    PrintAndLogEx(INFO, "Run this " _YELLOW_("once") "; then perform a full charge/discharge learning cycle.");

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_SET_CAP, payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_BWM_SET_CAP, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "command timeout (is this a PM5 with a BWM fitted?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "gauge provisioning failed - check BWM present and gauge unsealed");
        return resp.status;
    }
    PrintAndLogEx(SUCCESS, "Design capacity programmed. `hw status` should now report sane capacity.");
    return PM3_SUCCESS;
}


static void progressbar(long sent, long total, int style) {
    int percent = (int)((double)sent / total * 100);
    
    // Use \r at the start to move the cursor back to the beginning of the line
    printf("\rProgress: [%d%%]", percent); 
    
    // Force stdout to print immediately without waiting for a newline
    fflush(stdout); 
}

// One full OTA attempt: BEGIN -> WRITE... -> END. The BWM OTA has no resume
// (DEV.md 8.4): a dropped chunk can't be re-sent, so any failure here means the
// caller must restart the whole thing.
static int bwm_ota_once(const uint8_t *fw, size_t fwlen, uint32_t write_delay_ms) {
    PacketResponseNG resp;

    // BEGIN: tell the BWM how many bytes are coming. The ESP erases the idle
    // OTA slot here; that can take 20-40 s on a 4 MB ESP32-C2, so wait longer
    // than the device-side 60 s timeout plus USB round-trip.
    uint8_t beg[5] = { BWM_OTA_ACTION_BEGIN,
                       (uint8_t)(fwlen & 0xFF),         (uint8_t)((fwlen >> 8) & 0xFF),
                       (uint8_t)((fwlen >> 16) & 0xFF), (uint8_t)((fwlen >> 24) & 0xFF) };
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_ESP_OTA, beg, sizeof(beg));
    if (WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &resp, 75000) == false) {
        PrintAndLogEx(FAILED, "OTA begin timed out (ESP is likely still erasing the OTA slot)");
        PrintAndLogEx(HINT, "Wait a few seconds and retry; do not power-cycle mid-erase.");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "OTA begin failed (status %d)%s", resp.status,
                      (resp.status == PM3_ETIMEOUT) ? " - UART timeout waiting for ESP" : "");
        return resp.status;
    }
    PrintAndLogEx(INFO, "Uploading " _YELLOW_("%zu") " bytes of ESP firmware over the BWM link...", fwlen);

    // WRITE chunks. Bounded by BWM_OTA_CHUNK_MAX (the ESP forwards each WRITE over
    // its own small app_com UART frame - see bwm_wifi.c), not just the USB frame.
    size_t maxchunk = MIN((size_t)g_conn.max_cmd_data_size - 1, (size_t)BWM_OTA_CHUNK_MAX);
    uint8_t *buf = calloc(1, maxchunk + 1);
    if (buf == NULL) {
        return PM3_EMALLOC;
    }
    size_t sent = 0;
    while (sent < fwlen) {
        size_t n = MIN(maxchunk, fwlen - sent);
        buf[0] = BWM_OTA_ACTION_WRITE;
        memcpy(buf + 1, fw + sent, n);
        clearCommandBuffer();
        SendCommandNG(CMD_PM5_BWM_ESP_OTA, buf, (uint16_t)(n + 1));
        bool got = WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &resp, 25000);
        if (!got || resp.status != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            if (!got) {
                PrintAndLogEx(WARNING, "OTA write stalled at offset %zu (no response)", sent);
            } else if (resp.status == PM3_ETIMEOUT) {
                PrintAndLogEx(WARNING, "OTA write timed out at offset %zu (ESP did not ACK that chunk)", sent);
            } else {
                PrintAndLogEx(WARNING, "OTA write rejected at offset %zu (status %d)", sent, resp.status);
            }
            free(buf);
            return PM3_EFAILED;
        }
        sent += n;
        progressbar(sent, fwlen, STYLE_MIXED);

        // Pace the stream. The client->AT32 hop (USB/BLE) is far faster than the
        // AT32->ESP UART, so back-to-back writes can outrun the UART and drop a
        // chunk -> esp_ota_end() then sees written < total and aborts. A small
        // gap gives the UART time to drain. (BLE is naturally paced, which is why
        // it "worked" and bursty USB did not - see nemanjan00.)
        if (write_delay_ms) {
            msleep(write_delay_ms);
        }
    }
    free(buf);
    PrintAndLogEx(NORMAL, "");

    // END: finalize + set the new boot partition
    uint8_t end[1] = { BWM_OTA_ACTION_END };
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_ESP_OTA, end, sizeof(end));
    bool got_end = WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &resp, 30000);
    if (got_end && (resp.status == PM3_SUCCESS)) {
        return PM3_SUCCESS;
    }
    if (got_end) {
        // The BWM answered END with an error. The common one is a size mismatch:
        // esp_ota_end() found written < total, i.e. chunks were dropped in transit.
        // That is a genuine failure (boot partition NOT switched) - restart, and
        // hint at pacing, which is the usual cure.
        PrintAndLogEx(WARNING, "OTA finalize rejected (status %d) - data was lost in transit", resp.status);
        PrintAndLogEx(HINT, "Try a per-write delay: " _YELLOW_("hw bwm upgrade -f <fw> --delay 20"));
        return PM3_EFAILED;
    }
    // No answer at all. Over BLE the END auto-reboot drops the link before the ack
    // returns, so a timeout here means "reached END, reboot likely happened" -
    // verify by version rather than discarding a possibly-good flash.
    return PM3_ETIMEOUT;
}

// Query the BWM's running firmware version string (APP_CMD_GET_VERSION_INFO).
static int bwm_get_version(char *out, size_t outlen) {
    uint8_t a[1] = { BWM_OTA_ACTION_VERSION };
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_ESP_OTA, a, sizeof(a));
    PacketResponseNG r;
    if ((WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &r, 5000) == false) || (r.status != PM3_SUCCESS)) {
        return PM3_EFAILED;
    }
    uint16_t n = (r.length < (uint16_t)(outlen - 1)) ? r.length : (uint16_t)(outlen - 1);
    memcpy(out, r.data.asBytes, n);
    out[n] = 0;
    return PM3_SUCCESS;
}

static int CmdBWMUpgrade(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bwm upgrade",
                  "Reflash the BWM (ESP32) firmware over the BWM link - no header, no soldering.\n"
                  "Requires a BWM that still responds; this updates a wrong-version ESP, it cannot\n"
                  "recover a fully bricked one (that still needs the 5-pin header + esptool).",
                  "hw bwm upgrade -f bwm_esp32.bin");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "ESP32 firmware image (.bin)"),
        arg_int0(NULL, "delay", "<ms>", "per-chunk delay to pace the slow AT32<->ESP UART (default 20)"),
        arg_param_end,
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)fn, sizeof(fn), &fnlen);
    uint32_t write_delay_ms = (uint32_t)arg_get_int_def(ctx, 2, 20);
    CLIParserFree(ctx);

    if (fnlen == 0) {
        PrintAndLogEx(FAILED, "no filename given");
        return PM3_EINVARG;
    }

    uint8_t *fw = NULL;
    size_t fwlen = 0;
    if ((loadFile_safe(fn, "", (void **)&fw, &fwlen) != PM3_SUCCESS) || (fwlen == 0)) {
        PrintAndLogEx(FAILED, "could not read " _YELLOW_("%s"), fn);
        return PM3_EFILE;
    }

    // Safeguard: refuse to flash anything that is not an ESP32-C2 app image. The
    // BWM ESP is an ESP32-C2; a wrong/other-chip image would brick it.
    //   [0x00]       == 0xE9   -> ESP image magic
    //   [0x0C..0x0D] == 0x000C -> chip_id ESP32-C2 (LE uint16)
    //   [0xABCD5432..0x20] == 0xABCD5432 -> app descriptor (LE uint32)
    if (fwlen < 16) {
        PrintAndLogEx(FAILED, "file is too small to be an ESP firmware image (%zu bytes)", fwlen);
        free(fw);
        return PM3_EFILE;
    }
    if (fw[0] != 0xE9) {
        PrintAndLogEx(FAILED, "refusing to flash: not an ESP image (magic " _YELLOW_("0x%02X") ", expected 0xE9)", fw[0]);
        free(fw);
        return PM3_EFILE;
    }
    
    // Check Chip ID at offset 0x0C (2 bytes, little-endian)
    uint16_t chip_id = MemLeToUint2byte(fw + 0x0C);
    if (chip_id != 0x000C) {
        PrintAndLogEx(FAILED, "refusing to flash: image chip_id " _YELLOW_("0x%04X") " is not ESP32-C2 (0x000C)", chip_id);
        free(fw);
        return PM3_EFILE;
    }

    // Check Application Signature at offset 0x20 (4 bytes, little-endian)
    uint32_t app_sign = MemLeToUint4byte(fw + 0x20);
    if (app_sign != 0xABCD5432) {
        PrintAndLogEx(FAILED, "refusing to flash: image app_sign " _YELLOW_("0x%08X") " is invalid (expected 0xABCD5432)", app_sign);
        free(fw);
        return PM3_EFILE;
    }
    
    // Record the running version first, so we can confirm the update actually took
    // even when the finalize ack is lost (the case that used to discard a completed
    // flash and restart from scratch).
    char ver_before[64] = {0};
    bool have_before = (bwm_get_version(ver_before, sizeof(ver_before)) == PM3_SUCCESS);
    if (have_before) {
        PrintAndLogEx(INFO, "Current BWM firmware..... " _YELLOW_("%s"), ver_before);
    }

    // No resume (DEV.md 8.4): a chunk lost mid-transfer restarts the whole upload.
    const int max_attempts = 6;   // a single dropped chunk restarts the whole upload;
                                  // more attempts make an all-fail run rare until per-chunk
                                  // retry (offset-idempotent ESP write) lands.
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        if (attempt > 1) {
            // Abort the in-flight ESP OTA (if any) and give a slow erase a chance
            // to finish before we BEGIN again. Otherwise attempt N's BEGIN races
            // attempt N-1's still-running erase and times out.
            PrintAndLogEx(INFO, "restarting OTA from the beginning (attempt " _YELLOW_("%d") "/%d)", attempt, max_attempts);
            uint8_t ab[1] = { BWM_OTA_ACTION_ABORT };
            clearCommandBuffer();
            SendCommandNG(CMD_PM5_BWM_ESP_OTA, ab, sizeof(ab));
            PacketResponseNG abortr;
            (void)WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &abortr, 8000);
            msleep(3000);
        }
        int res = bwm_ota_once(fw, fwlen, write_delay_ms);

        // Failed during BEGIN/WRITE: image incomplete, restart the whole thing.
        if ((res != PM3_SUCCESS) && (res != PM3_ETIMEOUT)) {
            continue;
        }

        // Reached OTA_END (acked, or ack lost). The image is written and the boot
        // partition is set - reboot into it and confirm by version.
        if (res == PM3_ETIMEOUT) {
            PrintAndLogEx(INFO, "finalize ack not seen - all data was sent, confirming by version...");
        }
        // Upload is complete and the ESP is rebooting into the new image. The
        // AT32<->ESP link is now desynced (the ESP comes back at its boot-default
        // baud), and the AT32 only re-negotiates on its own reset - so reset the PM5
        // to re-sync the link cleanly rather than trying to re-link in place. This
        // drops the client link; the user reconnects to a cleanly re-linked PM5.
        (void)have_before;
        PrintAndLogEx(SUCCESS, "BWM firmware uploaded; resetting the PM5 to re-sync the link...");
        free(fw);
        clearCommandBuffer();
        SendCommandNG(CMD_HARDWARE_RESET, NULL, 0);
        PrintAndLogEx(INFO, "PM5 has been reset - reconnect, then run " _YELLOW_("hw status") " to confirm the new BWM version.");
        return PM3_SUCCESS;
    }
    free(fw);

    // Exhausted retries without a confirmed update - restore the link and report.
    PacketResponseNG resp;
    uint8_t ab[1] = { BWM_OTA_ACTION_ABORT };
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_ESP_OTA, ab, sizeof(ab));
    (void)WaitForResponseTimeout(CMD_PM5_BWM_ESP_OTA, &resp, 8000);
    PrintAndLogEx(FAILED, "BWM firmware update could not be confirmed after %d attempts", max_attempts);
    return PM3_EFAILED;
}
static int CmdHelpBwm(const char *Cmd);

static int CmdBwmName(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bwm name",
                  "Get or set the BWM BLE advertising name (stored on the BWM, in NVS).\n"
                  "With no --set, prints the current name. Setting a name stores it and reboots\n"
                  "the BWM to apply it - this briefly drops a BLE/WiFi connection; reconnect after\n"
                  "a few seconds. Over USB the reboot is not noticeable.",
                  "hw bwm name                 --> show current BLE name\n"
                  "hw bwm name --set MyPM5      --> set BLE name to 'MyPM5'");
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "set", "<name>", "new BLE name (1-31 chars); omit to read current name"),
        arg_param_end,
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t name[64] = {0};
    int nlen = sizeof(name) - 1; // CLIGetStrWithReturn does not guarantee NUL-termination
    CLIGetStrWithReturn(ctx, 1, name, &nlen);
    CLIParserFree(ctx);

    if (nlen == 0) {
        // GET
        uint8_t a[1] = { BWM_BLE_NAME_ACTION_GET };
        clearCommandBuffer();
        SendCommandNG(CMD_PM5_BWM_BLE_NAME, a, sizeof(a));
        PacketResponseNG r;
        if ((WaitForResponseTimeout(CMD_PM5_BWM_BLE_NAME, &r, 5000) == false) || (r.status != PM3_SUCCESS)) {
            PrintAndLogEx(FAILED, "failed to read BWM BLE name (is a responsive BWM fitted?)");
            return PM3_EFAILED;
        }
        char out[BWM_BLE_NAME_MAX_LEN + 1] = {0};
        uint16_t n = (r.length < sizeof(out) - 1) ? r.length : (uint16_t)(sizeof(out) - 1);
        memcpy(out, r.data.asBytes, n);
        PrintAndLogEx(SUCCESS, "BWM BLE name..... " _YELLOW_("%s"), out);
        return PM3_SUCCESS;
    }

    // SET
    if (nlen > BWM_BLE_NAME_MAX_LEN) {
        PrintAndLogEx(FAILED, "name too long: %d chars (max " _YELLOW_("%d") ")", nlen, BWM_BLE_NAME_MAX_LEN);
        return PM3_EINVARG;
    }
    uint8_t payload[1 + BWM_BLE_NAME_MAX_LEN];
    payload[0] = BWM_BLE_NAME_ACTION_SET;
    memcpy(payload + 1, name, nlen);
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_BWM_BLE_NAME, payload, (uint16_t)(1 + nlen));
    PacketResponseNG r;
    if ((WaitForResponseTimeout(CMD_PM5_BWM_BLE_NAME, &r, 5000) == false) || (r.status != PM3_SUCCESS)) {
        PrintAndLogEx(FAILED, "failed to set BWM BLE name (is a responsive BWM fitted?)");
        return PM3_EFAILED;
    }
    PrintAndLogEx(SUCCESS, "BWM BLE name set to " _YELLOW_("%s"), name);

    // The ESP applies the name at BLE start-up, so it reboots (device-side) to pick
    // it up. That reboot leaves the AT32<->ESP link desynced (the ESP comes back at
    // its boot-default baud, and the AT32 only re-negotiates on its own reset), so
    // reset the PM5 to re-sync. This drops the client link - reconnect afterwards.
    PrintAndLogEx(INFO, "Resetting the PM5 to apply the new name and re-sync the BWM link...");
    clearCommandBuffer();
    SendCommandNG(CMD_HARDWARE_RESET, NULL, 0);
    PrintAndLogEx(INFO, "PM5 has been reset - reconnect after a few seconds.");
    return PM3_SUCCESS;
}

static command_t BwmCommandTable[] = {
    {"help",     CmdHelpBwm,    AlwaysAvailable, "This help"},
    {"autooff",  CmdBwmAutoOff, IfPm5, "Toggle auto power-off on USB unplug"},
    {"charge",   CmdBwmCharge,  IfPm5, "Enable/disable battery charging (one-shot)"},
    {"name",     CmdBwmName,    IfPm5, "Get/set the BWM BLE advertising name"},
    {"setcap",   CmdBwmSetCap,  IfPm5, "Set fuel-gauge design capacity (run once after battery change)"},
    {"upgrade",  CmdBWMUpgrade, IfPm5, "Reflash BWM (ESP32) firmware over the BWM link, no header"},
    {"vchg",     CmdBwmVchg,    IfPm5, "Set charger charge-voltage target (default 4100 mV)"},
    {"wifi",     CmdBWMWifi,    IfPm5, "Bring up WiFi (STA + TCP server) for a tcp: connection"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelpBwm(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(BwmCommandTable);
    return PM3_SUCCESS;
}

int CmdBwm(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(BwmCommandTable, Cmd);
}
