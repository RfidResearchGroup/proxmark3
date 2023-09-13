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
// Code for communicating with the proxmark3 hardware.
//-----------------------------------------------------------------------------

#include "comms.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "uart/uart.h"
#include "ui.h"
#include "crc16.h"
#include "util.h" // g_pendingPrompt
#include "util_posix.h" // msclock
#include "util_darwin.h" // en/dis-ableNapp();

// #define COMMS_DEBUG
// #define COMMS_DEBUG_RAW

// Serial port that we are communicating with the PM3 on.
static serial_port sp = NULL;

communication_arg_t g_conn;
capabilities_t g_pm3_capabilities;

static pthread_t communication_thread;
static bool comm_thread_dead = false;

// Transmit buffer.
static PacketCommandOLD txBuffer;
static PacketCommandNGRaw txBufferNG;
static size_t txBufferNGLen;
static bool txBuffer_pending = false;
static pthread_mutex_t txBufferMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t txBufferSig = PTHREAD_COND_INITIALIZER;

// Used by PacketResponseReceived as a ring buffer for messages that are yet to be
// processed by a command handler (WaitForResponse{,Timeout})
static PacketResponseNG rxBuffer[CMD_BUFFER_SIZE];

// Points to the next empty position to write to
static int cmd_head = 0;

// Points to the position of the last unread command
static int cmd_tail = 0;

// to lock rxBuffer operations from different threads
static pthread_mutex_t rxBufferMutex = PTHREAD_MUTEX_INITIALIZER;

// Global start time for WaitForResponseTimeout & dl_it, so we can reset timeout when we get packets
// as sending lot of these packets can slow down things wuite a lot on slow links (e.g. hw status or lf read at 9600)
static uint64_t timeout_start_time;

static uint64_t last_packet_time;

static bool dl_it(uint8_t *dest, uint32_t bytes, PacketResponseNG *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd);

// Simple alias to track usages linked to the Bootloader, these commands must not be migrated.
// - commands sent to enter bootloader mode as we might have to talk to old firmwares
// - commands sent to the bootloader as it only supports OLD frames (which will always be the case for old BL)
void SendCommandBL(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    SendCommandOLD(cmd, arg0, arg1, arg2, data, len);
}

void SendCommandOLD(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketCommandOLD c = {CMD_UNKNOWN, {0, 0, 0}, {{0}}};
    c.cmd = cmd;
    c.arg[0] = arg0;
    c.arg[1] = arg1;
    c.arg[2] = arg2;
    if (len && data)
        memcpy(&c.d, data, len);

#ifdef COMMS_DEBUG
    PrintAndLogEx(NORMAL, "Sending %s", "OLD");
#endif
#ifdef COMMS_DEBUG_RAW
    print_hex_break((uint8_t *)&c.cmd, sizeof(c.cmd), 32);
    print_hex_break((uint8_t *)&c.arg, sizeof(c.arg), 32);
    print_hex_break((uint8_t *)&c.d, sizeof(c.d), 32);
#endif

    if (!g_session.pm3_present) {
        PrintAndLogEx(WARNING, "Sending bytes to Proxmark3 failed ( " _RED_("offline") " )");
        return;
    }

    pthread_mutex_lock(&txBufferMutex);
    /**
    This causes hangups at times, when the pm3 unit is unresponsive or disconnected. The main console thread is alive,
    but comm thread just spins here. Not good.../holiman
    **/
    while (txBuffer_pending) {
        // wait for communication thread to complete sending a previous command
        pthread_cond_wait(&txBufferSig, &txBufferMutex);
    }

    txBuffer = c;
    txBuffer_pending = true;

    // tell communication thread that a new command can be send
    pthread_cond_signal(&txBufferSig);

    pthread_mutex_unlock(&txBufferMutex);

//__atomic_test_and_set(&txcmd_pending, __ATOMIC_SEQ_CST);
}

static void SendCommandNG_internal(uint16_t cmd, uint8_t *data, size_t len, bool ng) {
#ifdef COMMS_DEBUG
    PrintAndLogEx(INFO, "Sending %s", ng ? "NG" : "MIX");
#endif

    if (!g_session.pm3_present) {
        PrintAndLogEx(INFO, "Sending bytes to proxmark failed - offline");
        return;
    }
    if (len > PM3_CMD_DATA_SIZE) {
        PrintAndLogEx(WARNING, "Sending %zu bytes of payload is too much, abort", len);
        return;
    }

    PacketCommandNGPostamble *tx_post = (PacketCommandNGPostamble *)((uint8_t *)&txBufferNG + sizeof(PacketCommandNGPreamble) + len);

    pthread_mutex_lock(&txBufferMutex);
    /**
    This causes hangups at times, when the pm3 unit is unresponsive or disconnected. The main console thread is alive,
    but comm thread just spins here. Not good.../holiman
    **/
    while (txBuffer_pending) {
        // wait for communication thread to complete sending a previous command
        pthread_cond_wait(&txBufferSig, &txBufferMutex);
    }

    txBufferNG.pre.magic = COMMANDNG_PREAMBLE_MAGIC;
    txBufferNG.pre.ng = ng;
    txBufferNG.pre.length = len;
    txBufferNG.pre.cmd = cmd;
    if (len > 0 && data)
        memcpy(&txBufferNG.data, data, len);

    if ((g_conn.send_via_fpc_usart && g_conn.send_with_crc_on_fpc) || ((!g_conn.send_via_fpc_usart) && g_conn.send_with_crc_on_usb)) {
        uint8_t first = 0, second = 0;
        compute_crc(CRC_14443_A, (uint8_t *)&txBufferNG, sizeof(PacketCommandNGPreamble) + len, &first, &second);
        tx_post->crc = (first << 8) + second;
    } else {
        tx_post->crc = COMMANDNG_POSTAMBLE_MAGIC;
    }

    txBufferNGLen = sizeof(PacketCommandNGPreamble) + len + sizeof(PacketCommandNGPostamble);

#ifdef COMMS_DEBUG_RAW
    print_hex_break((uint8_t *)&txBufferNG.pre, sizeof(PacketCommandNGPreamble), 32);
    if (ng) {
        print_hex_break((uint8_t *)&txBufferNG.data, len, 32);
    } else {
        print_hex_break((uint8_t *)&txBufferNG.data, 3 * sizeof(uint64_t), 32);
        print_hex_break((uint8_t *)&txBufferNG.data + 3 * sizeof(uint64_t), len - 3 * sizeof(uint64_t), 32);
    }
    print_hex_break((uint8_t *)tx_post, sizeof(PacketCommandNGPostamble), 32);
#endif
    txBuffer_pending = true;

    // tell communication thread that a new command can be send
    pthread_cond_signal(&txBufferSig);

    pthread_mutex_unlock(&txBufferMutex);

//__atomic_test_and_set(&txcmd_pending, __ATOMIC_SEQ_CST);
}

void SendCommandNG(uint16_t cmd, uint8_t *data, size_t len) {
    SendCommandNG_internal(cmd, data, len, true);
}

void SendCommandMIX(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    uint64_t arg[3] = {arg0, arg1, arg2};
    if (len > PM3_CMD_DATA_SIZE_MIX) {
        PrintAndLogEx(WARNING, "Sending %zu bytes of payload is too much for MIX frames, abort", len);
        return;
    }
    uint8_t cmddata[PM3_CMD_DATA_SIZE];
    memcpy(cmddata, arg, sizeof(arg));
    if (len && data)
        memcpy(cmddata + sizeof(arg), data, len);
    SendCommandNG_internal(cmd, cmddata, len + sizeof(arg), false);
}


/**
 * @brief This method should be called when sending a new command to the pm3. In case any old
 *  responses from previous commands are stored in the buffer, a call to this method should clear them.
 *  A better method could have been to have explicit command-ACKS, so we can know which ACK goes to which
 *  operation. Right now we'll just have to live with this.
 */
void clearCommandBuffer(void) {
    //This is a very simple operation
    pthread_mutex_lock(&rxBufferMutex);
    cmd_tail = cmd_head;
    pthread_mutex_unlock(&rxBufferMutex);
}
/**
 * @brief storeCommand stores a USB command in a circular buffer
 * @param UC
 */
static void storeReply(PacketResponseNG *packet) {
    pthread_mutex_lock(&rxBufferMutex);
    if ((cmd_head + 1) % CMD_BUFFER_SIZE == cmd_tail) {
        //If these two are equal, we're about to overwrite in the
        // circular buffer.
        PrintAndLogEx(FAILED, "WARNING: Command buffer about to overwrite command! This needs to be fixed!");
        fflush(stdout);
    }
    //Store the command at the 'head' location
    PacketResponseNG *destination = &rxBuffer[cmd_head];
    memcpy(destination, packet, sizeof(PacketResponseNG));

    //increment head and wrap
    cmd_head = (cmd_head + 1) % CMD_BUFFER_SIZE;
    pthread_mutex_unlock(&rxBufferMutex);
}
/**
 * @brief getCommand gets a command from an internal circular buffer.
 * @param response location to write command
 * @return 1 if response was returned, 0 if nothing has been received
 */
static int getReply(PacketResponseNG *packet) {
    pthread_mutex_lock(&rxBufferMutex);
    //If head == tail, there's nothing to read, or if we just got initialized
    if (cmd_head == cmd_tail)  {
        pthread_mutex_unlock(&rxBufferMutex);
        return 0;
    }

    //Pick out the next unread command
    memcpy(packet, &rxBuffer[cmd_tail], sizeof(PacketResponseNG));

    //Increment tail - this is a circular buffer, so modulo buffer size
    cmd_tail = (cmd_tail + 1) % CMD_BUFFER_SIZE;

    pthread_mutex_unlock(&rxBufferMutex);
    return 1;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
static void PacketResponseReceived(PacketResponseNG *packet) {

    // we got a packet, reset WaitForResponseTimeout timeout
    uint64_t prev_clk = __atomic_load_n(&last_packet_time, __ATOMIC_SEQ_CST);
    uint64_t clk = msclock();
    __atomic_store_n(&timeout_start_time,  clk, __ATOMIC_SEQ_CST);
    __atomic_store_n(&last_packet_time, clk, __ATOMIC_SEQ_CST);
    (void) prev_clk;
//    PrintAndLogEx(NORMAL, "[%07"PRIu64"] RECV %s magic %08x length %04x status %04x crc %04x cmd %04x",
//                clk - prev_clk, packet->ng ? "NG" : "OLD", packet->magic, packet->length, packet->status, packet->crc, packet->cmd);

    switch (packet->cmd) {
        // First check if we are handling a debug message
        case CMD_DEBUG_PRINT_STRING: {

            char s[PM3_CMD_DATA_SIZE + 1];
            memset(s, 0x00, sizeof(s));

            size_t len;
            uint16_t flag;
            if (packet->ng) {
                struct d {
                    uint16_t flag;
                    uint8_t buf[PM3_CMD_DATA_SIZE - sizeof(uint16_t)];
                } PACKED;
                struct d *data = (struct d *)&packet->data.asBytes;
                len = packet->length - sizeof(data->flag);
                flag = data->flag;
                memcpy(s, data->buf, len);
            } else {
                len = MIN(packet->oldarg[0], PM3_CMD_DATA_SIZE);
                flag = packet->oldarg[1];
                memcpy(s, packet->data.asBytes, len);
            }

            if (flag & FLAG_LOG) {
                if (g_pendingPrompt) {
                    PrintAndLogEx(NORMAL, "");
                    g_pendingPrompt = false;
                }
                //PrintAndLogEx(NORMAL, "[" _MAGENTA_("pm3") "] ["_BLUE_("#")"] " "%s", s);
                PrintAndLogEx(NORMAL, "[" _BLUE_("#") "] %s", s);
            } else {
                if (flag & FLAG_INPLACE)
                    PrintAndLogEx(NORMAL, "\r" NOLF);

                PrintAndLogEx(NORMAL, "%s" NOLF, s);

                if (flag & FLAG_NEWLINE)
                    PrintAndLogEx(NORMAL, "");
            }
            break;
        }
        case CMD_DEBUG_PRINT_INTEGERS: {
            if (packet->ng == false)
                PrintAndLogEx(NORMAL, "[" _MAGENTA_("pm3") "] ["_BLUE_("#")"] " "%" PRIx64 ", %" PRIx64 ", %" PRIx64 "", packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        // iceman:  hw status - down the path on device, runs printusbspeed which starts sending a lot of
        // CMD_DOWNLOAD_BIGBUF packages which is not dealt with. I wonder if simply ignoring them will
        // work. lets try it.
        default: {
            storeReply(packet);
            break;
        }
    }
}


// The communications thread.
// signals to main thread when a response is ready to process.
//
static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*uart_communication(void *targ) {
    communication_arg_t *connection = (communication_arg_t *)targ;
    uint32_t rxlen;
    bool commfailed = false;
    PacketResponseNG rx;
    PacketResponseNGRaw rx_raw;

#if defined(__MACH__) && defined(__APPLE__)
    disableAppNap("Proxmark3 polling UART");
#endif

    // is this connection->run a cross thread call?
    while (connection->run) {
        rxlen = 0;
        bool ACK_received = false;
        bool error = false;
        int res;

        // Signal to main thread that communications seems off.
        // main thread will kill and restart this thread.
        if (commfailed) {
            if (g_conn.last_command != CMD_HARDWARE_RESET) {
                PrintAndLogEx(WARNING, "\nCommunicating with Proxmark3 device " _RED_("failed"));
            }
            __atomic_test_and_set(&comm_thread_dead, __ATOMIC_SEQ_CST);
            break;
        }

        res = uart_receive(sp, (uint8_t *)&rx_raw.pre, sizeof(PacketResponseNGPreamble), &rxlen);

        if ((res == PM3_SUCCESS) && (rxlen == sizeof(PacketResponseNGPreamble))) {
            rx.magic = rx_raw.pre.magic;
            uint16_t length = rx_raw.pre.length;
            rx.ng = rx_raw.pre.ng;
            rx.status = rx_raw.pre.status;
            rx.cmd = rx_raw.pre.cmd;
            if (rx.magic == RESPONSENG_PREAMBLE_MAGIC) { // New style NG reply
                if (length > PM3_CMD_DATA_SIZE) {
                    PrintAndLogEx(WARNING, "Received packet frame with incompatible length: 0x%04x", length);
                    error = true;
                }

                if ((!error) && (length > 0)) { // Get the variable length payload

                    res = uart_receive(sp, (uint8_t *)&rx_raw.data, length, &rxlen);
                    if ((res != PM3_SUCCESS) || (rxlen != length)) {
                        PrintAndLogEx(WARNING, "Received packet frame with variable part too short? %d/%d", rxlen, length);
                        error = true;
                    } else {

                        if (rx.ng) {      // Received a valid NG frame
                            memcpy(&rx.data, &rx_raw.data, length);
                            rx.length = length;
                            if ((rx.cmd == g_conn.last_command) && (rx.status == PM3_SUCCESS)) {
                                ACK_received = true;
                            }
                        } else {
                            uint64_t arg[3];
                            if (length < sizeof(arg)) {
                                PrintAndLogEx(WARNING, "Received MIX packet frame with incompatible length: 0x%04x", length);
                                error = true;
                            }
                            if (!error) { // Received a valid MIX frame
                                memcpy(arg, &rx_raw.data, sizeof(arg));
                                rx.oldarg[0] = arg[0];
                                rx.oldarg[1] = arg[1];
                                rx.oldarg[2] = arg[2];
                                memcpy(&rx.data, ((uint8_t *)&rx_raw.data) + sizeof(arg), length - sizeof(arg));
                                rx.length = length - sizeof(arg);
                                if (rx.cmd == CMD_ACK) {
                                    ACK_received = true;
                                }
                            }
                        }
                    }
                } else if ((!error) && (length == 0)) { // we received an empty frame
                    if (rx.ng)
                        rx.length = 0; // set received length to 0
                    else {  // old frames can't be empty
                        PrintAndLogEx(WARNING, "Received empty MIX packet frame (length: 0x00)");
                        error = true;
                    }
                }

                if (!error) {                        // Get the postamble
                    res = uart_receive(sp, (uint8_t *)&rx_raw.foopost, sizeof(PacketResponseNGPostamble), &rxlen);
                    if ((res != PM3_SUCCESS) || (rxlen != sizeof(PacketResponseNGPostamble))) {
                        PrintAndLogEx(WARNING, "Received packet frame without postamble");
                        error = true;
                    }
                }

                if (!error) {                        // Check CRC, accept MAGIC as placeholder
                    rx.crc = rx_raw.foopost.crc;
                    if (rx.crc != RESPONSENG_POSTAMBLE_MAGIC) {
                        uint8_t first, second;
                        compute_crc(CRC_14443_A, (uint8_t *)&rx_raw, sizeof(PacketResponseNGPreamble) + length, &first, &second);
                        if ((first << 8) + second != rx.crc) {
                            PrintAndLogEx(WARNING, "Received packet frame with invalid CRC %02X%02X <> %04X", first, second, rx.crc);
                            error = true;
                        }
                    }
                }
                if (!error) {             // Received a valid OLD frame
#ifdef COMMS_DEBUG
                    PrintAndLogEx(NORMAL, "Receiving %s:", rx.ng ? "NG" : "MIX");
#endif
#ifdef COMMS_DEBUG_RAW
                    print_hex_break((uint8_t *)&rx_raw.pre, sizeof(PacketResponseNGPreamble), 32);
                    print_hex_break((uint8_t *)&rx_raw.data, rx_raw.pre.length, 32);
                    print_hex_break((uint8_t *)&rx_raw.foopost, sizeof(PacketResponseNGPostamble), 32);
#endif
                    PacketResponseReceived(&rx);
                }
            } else {                               // Old style reply
                PacketResponseOLD rx_old;
                memcpy(&rx_old, &rx_raw.pre, sizeof(PacketResponseNGPreamble));

                res = uart_receive(sp, ((uint8_t *)&rx_old) + sizeof(PacketResponseNGPreamble), sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble), &rxlen);
                if ((res != PM3_SUCCESS) || (rxlen != sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble))) {
                    PrintAndLogEx(WARNING, "Received packet OLD frame with payload too short? %d/%zu", rxlen, sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble));
                    error = true;
                }
                if (!error) {
#ifdef COMMS_DEBUG
                    PrintAndLogEx(NORMAL, "Receiving OLD:");
#endif
#ifdef COMMS_DEBUG_RAW
                    print_hex_break((uint8_t *)&rx_old.cmd, sizeof(rx_old.cmd), 32);
                    print_hex_break((uint8_t *)&rx_old.arg, sizeof(rx_old.arg), 32);
                    print_hex_break((uint8_t *)&rx_old.d, sizeof(rx_old.d), 32);
#endif
                    rx.ng = false;
                    rx.magic = 0;
                    rx.status = 0;
                    rx.crc = 0;
                    rx.cmd = rx_old.cmd;
                    rx.oldarg[0] = rx_old.arg[0];
                    rx.oldarg[1] = rx_old.arg[1];
                    rx.oldarg[2] = rx_old.arg[2];
                    rx.length = PM3_CMD_DATA_SIZE;
                    memcpy(&rx.data, &rx_old.d, rx.length);
                    PacketResponseReceived(&rx);
                    if (rx.cmd == CMD_ACK) {
                        ACK_received = true;
                    }
                }
            }
        } else {
            if (rxlen > 0) {
                PrintAndLogEx(WARNING, "Received packet frame preamble too short: %d/%zu", rxlen, sizeof(PacketResponseNGPreamble));
                error = true;
            }
            if (res == PM3_ENOTTY) {
                commfailed = true;
            }
        }

        // TODO if error, shall we resync ?

        pthread_mutex_lock(&txBufferMutex);

        if (connection->block_after_ACK) {
            // if we just received an ACK, wait here until a new command is to be transmitted
            // This is only working on OLD frames, and only used by flasher and flashmem
            if (ACK_received) {
#ifdef COMMS_DEBUG
                PrintAndLogEx(NORMAL, "Received ACK, fast TX mode: ignoring other RX till TX");
#endif
                while (!txBuffer_pending) {
                    pthread_cond_wait(&txBufferSig, &txBufferMutex);
                }
            }
        }

        if (txBuffer_pending) {

            if (txBufferNGLen) { // NG packet
                res = uart_send(sp, (uint8_t *) &txBufferNG, txBufferNGLen);
                if (res == PM3_EIO) {
                    commfailed = true;
                }
                g_conn.last_command = txBufferNG.pre.cmd;
                txBufferNGLen = 0;
            } else {
                res = uart_send(sp, (uint8_t *) &txBuffer, sizeof(PacketCommandOLD));
                if (res == PM3_EIO) {
                    commfailed = true;
                }
                g_conn.last_command = txBuffer.cmd;
            }

            txBuffer_pending = false;

            // main thread doesn't know send failed...

            // tell main thread that txBuffer is empty
            pthread_cond_signal(&txBufferSig);
        }

        pthread_mutex_unlock(&txBufferMutex);
    }

    // when thread dies, we close the serial port.
    uart_close(sp);
    sp = NULL;

#if defined(__MACH__) && defined(__APPLE__)
    enableAppNap();
#endif

    pthread_exit(NULL);
    return NULL;
}

bool IsCommunicationThreadDead(void) {
    bool ret = __atomic_load_n(&comm_thread_dead, __ATOMIC_SEQ_CST);
    return ret;
}

bool OpenProxmark(pm3_device_t **dev, const char *port, bool wait_for_port, int timeout, bool flash_mode, uint32_t speed) {

    if (!wait_for_port) {
        PrintAndLogEx(INFO, "Using UART port " _YELLOW_("%s"), port);
        sp = uart_open(port, speed);
    } else {
        PrintAndLogEx(SUCCESS, "Waiting for Proxmark3 to appear on " _YELLOW_("%s"), port);
        fflush(stdout);
        int openCount = 0;
        PrintAndLogEx(INPLACE, "% 3i", timeout);
        do {
            sp = uart_open(port, speed);
            msleep(500);
            PrintAndLogEx(INPLACE, "% 3i", timeout - openCount - 1);

        } while (++openCount < timeout && (sp == INVALID_SERIAL_PORT || sp == CLAIMED_SERIAL_PORT));
    }

    // check result of uart opening
    if (sp == INVALID_SERIAL_PORT) {
        PrintAndLogEx(WARNING, "\n" _RED_("ERROR:") " invalid serial port " _YELLOW_("%s"), port);
        PrintAndLogEx(HINT, "Try the shell script " _YELLOW_("`./pm3 --list`") " to get a list of possible serial ports");
        sp = NULL;
        return false;
    } else if (sp == CLAIMED_SERIAL_PORT) {
        PrintAndLogEx(WARNING, "\n" _RED_("ERROR:") " serial port " _YELLOW_("%s") " is claimed by another process", port);
        PrintAndLogEx(HINT, "Try the shell script " _YELLOW_("`./pm3 --list`") " to get a list of possible serial ports");

        sp = NULL;
        return false;
    } else {
        // start the communication thread
        if (port != g_conn.serial_port_name) {
            uint16_t len = MIN(strlen(port), FILE_PATH_SIZE - 1);
            memset(g_conn.serial_port_name, 0, FILE_PATH_SIZE);
            memcpy(g_conn.serial_port_name, port, len);
        }
        g_conn.run = true;
        g_conn.block_after_ACK = flash_mode;
        // Flags to tell where to add CRC on sent replies
        g_conn.send_with_crc_on_usb = false;
        g_conn.send_with_crc_on_fpc = true;
        // "Session" flag, to tell via which interface next msgs should be sent: USB or FPC USART
        g_conn.send_via_fpc_usart = false;

        pthread_create(&communication_thread, NULL, &uart_communication, &g_conn);
        __atomic_clear(&comm_thread_dead, __ATOMIC_SEQ_CST);
        g_session.pm3_present = true; // TODO support for multiple devices

        fflush(stdout);
        if (*dev == NULL) {
            *dev = calloc(sizeof(pm3_device_t), sizeof(uint8_t));
        }
        (*dev)->g_conn = &g_conn; // TODO g_conn shouldn't be global
        return true;
    }
}

// check if we can communicate with Pm3
int TestProxmark(pm3_device_t *dev) {

    uint16_t len = 32;
    uint8_t data[len];
    for (uint16_t i = 0; i < len; i++)
        data[i] = i & 0xFF;

    __atomic_store_n(&last_packet_time,  msclock(), __ATOMIC_SEQ_CST);
    clearCommandBuffer();
    SendCommandNG(CMD_PING, data, len);

    uint32_t timeout;

#ifdef USART_SLOW_LINK
    // 10s timeout for slow FPC, e.g. over BT
    // as this is the very first command sent to the pm3
    // that initiates the BT connection
    timeout = 10000;
#else
    timeout = 1000;
#endif

    PacketResponseNG resp;
    if (WaitForResponseTimeoutW(CMD_PING, &resp, timeout, false) == 0) {
        return PM3_ETIMEOUT;
    }

    bool error = memcmp(data, resp.data.asBytes, len) != 0;
    if (error) {
        return PM3_EIO;
    }

    SendCommandNG(CMD_CAPABILITIES, NULL, 0);
    if (WaitForResponseTimeoutW(CMD_CAPABILITIES, &resp, 1000, false) == 0) {
        return PM3_ETIMEOUT;
    }

    if ((resp.length != sizeof(g_pm3_capabilities)) || (resp.data.asBytes[0] != CAPABILITIES_VERSION)) {
        PrintAndLogEx(ERR, _RED_("Capabilities structure version sent by Proxmark3 is not the same as the one used by the client!"));
        PrintAndLogEx(ERR, _RED_("Please flash the Proxmark with the same version as the client."));
        return PM3_EDEVNOTSUPP;
    }

    memcpy(&g_pm3_capabilities, resp.data.asBytes, MIN(sizeof(capabilities_t), resp.length));
    g_conn.send_via_fpc_usart = g_pm3_capabilities.via_fpc;
    g_conn.uart_speed = g_pm3_capabilities.baudrate;

    bool is_tcp_conn = (memcmp(g_conn.serial_port_name, "tcp:", 4) == 0);
    bool is_bt_conn = (memcmp(g_conn.serial_port_name, "bt:", 3) == 0);

    PrintAndLogEx(INFO, "Communicating with PM3 over %s%s%s",
                  (g_conn.send_via_fpc_usart) ? _YELLOW_("FPC UART") : _YELLOW_("USB-CDC"),
                  (is_tcp_conn) ? " over " _YELLOW_("TCP") : "",
                  (is_bt_conn) ? " over " _YELLOW_("BT") : ""
                 );

    if (g_conn.send_via_fpc_usart) {
        PrintAndLogEx(INFO, "PM3 UART serial baudrate: " _YELLOW_("%u") "\n", g_conn.uart_speed);
    } else {
        int res = uart_reconfigure_timeouts(is_tcp_conn ? UART_TCP_CLIENT_RX_TIMEOUT_MS : UART_USB_CLIENT_RX_TIMEOUT_MS);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }
    return PM3_SUCCESS;
}

void CloseProxmark(pm3_device_t *dev) {
    dev->g_conn->run = false;

#ifdef __BIONIC__
    if (communication_thread != 0) {
        pthread_join(communication_thread, NULL);
    }
#else
    pthread_join(communication_thread, NULL);
#endif

    if (sp) {
        uart_close(sp);
    }

    // Clean up our state
    sp = NULL;
#ifdef __BIONIC__
    if (communication_thread != 0) {
        memset(&communication_thread, 0, sizeof(pthread_t));
    }
#else
    memset(&communication_thread, 0, sizeof(pthread_t));
#endif

    g_session.pm3_present = false;
}

// Gives a rough estimate of the communication delay based on channel & baudrate
// Max communication delay is when sending largest frame and receiving largest frame
// Empirical measures on FTDI with physical cable:
// "hw pingng 512"
//    usb ->    6..32ms
// 460800 ->   40..70ms
//   9600 -> 1100..1150ms
//           ~ = 12000000 / USART_BAUD_RATE
// Let's take 2x (maybe we need more for BT link?)
static size_t communication_delay(void) {
    if (g_conn.send_via_fpc_usart)  // needed also for Windows USB USART??
        return 2 * (12000000 / g_conn.uart_speed);
    return 0;
}

/**
 * @brief Waits for a certain response type. This method waits for a maximum of
 * ms_timeout milliseconds for a specified response command.

 * @param cmd command to wait for, or CMD_UNKNOWN to take any command.
 * @param response struct to copy received command into.
 * @param ms_timeout display message after 3 seconds
 * @param show_warning display message after 3 seconds
 * @return true if command was returned, otherwise false
 */
bool WaitForResponseTimeoutW(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout, bool show_warning) {

    PacketResponseNG resp;
    // init to ZERO
    resp.cmd = 0,
    resp.length = 0,
    resp.magic = 0,
    resp.status = 0,
    resp.crc = 0,
    resp.ng = false,
    resp.oldarg[0] = 0;
    resp.oldarg[1] = 0;
    resp.oldarg[2] = 0;
    memset(resp.data.asBytes, 0, PM3_CMD_DATA_SIZE);

    if (response == NULL) {
        response = &resp;
    }

    // Add delay depending on the communication channel & speed
    if (ms_timeout != (size_t) - 1)
        ms_timeout += communication_delay();

    __atomic_store_n(&timeout_start_time,  msclock(), __ATOMIC_SEQ_CST);

    // Wait until the command is received
    while (true) {

        while (getReply(response)) {
            if (cmd == CMD_UNKNOWN || response->cmd == cmd) {
                return true;
            }
            if (response->cmd == CMD_WTX && response->length == sizeof(uint16_t)) {
                uint16_t wtx = response->data.asDwords[0] & 0xFFFF;
                PrintAndLogEx(DEBUG, "Got Waiting Time eXtension request %i ms", wtx);
                if (ms_timeout != (size_t) - 1)
                    ms_timeout += wtx;
            }
        }

        uint64_t tmp_clk = __atomic_load_n(&timeout_start_time, __ATOMIC_SEQ_CST);
        if ((ms_timeout != (size_t) - 1) && (msclock() - tmp_clk > ms_timeout))
            break;

        if (msclock() - tmp_clk > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
        // just to avoid CPU busy loop:
        msleep(10);
    }
    return false;
}

bool WaitForResponseTimeout(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout) {
    return WaitForResponseTimeoutW(cmd, response, ms_timeout, true);
}

bool WaitForResponse(uint32_t cmd, PacketResponseNG *response) {
    return WaitForResponseTimeoutW(cmd, response, -1, true);
}

/**
* Data transfer from Proxmark to client. This method times out after
* ms_timeout milliseconds.
* @brief GetFromDevice
* @param memtype Type of memory to download from proxmark
* @param dest Destination address for transfer
* @param bytes number of bytes to be transferred
* @param start_index offset into Proxmark3 BigBuf[]
* @param data used by SPIFFS to provide filename
* @param datalen used by SPIFFS to provide filename length
* @param response struct to copy last command (CMD_ACK) into
* @param ms_timeout timeout in milliseconds
* @param show_warning display message after 2 seconds
* @return true if command was returned, otherwise false
*/
bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, uint8_t *data, uint32_t datalen, PacketResponseNG *response, size_t ms_timeout, bool show_warning) {

    if (dest == NULL) return false;

    PacketResponseNG resp;
    if (response == NULL) {
        response = &resp;
    }

    // init to ZERO
    resp.cmd = 0,
    resp.length = 0,
    resp.magic = 0,
    resp.status = 0,
    resp.crc = 0,
    resp.ng = false,
    resp.oldarg[0] = 0;
    resp.oldarg[1] = 0;
    resp.oldarg[2] = 0;
    memset(resp.data.asBytes, 0, PM3_CMD_DATA_SIZE);

    if (bytes == 0) return true;


    // clear
    clearCommandBuffer();

    switch (memtype) {
        case BIG_BUF: {
            SendCommandMIX(CMD_DOWNLOAD_BIGBUF, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_DOWNLOADED_BIGBUF);
        }
        case BIG_BUF_EML: {
            SendCommandMIX(CMD_DOWNLOAD_EML_BIGBUF, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_DOWNLOADED_EML_BIGBUF);
        }
        case SPIFFS: {
            SendCommandMIX(CMD_SPIFFS_DOWNLOAD, start_index, bytes, 0, data, datalen);
            return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_SPIFFS_DOWNLOADED);
        }
        case FLASH_MEM: {
            SendCommandMIX(CMD_FLASHMEM_DOWNLOAD, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_FLASHMEM_DOWNLOADED);
        }
        case SIM_MEM: {
            //SendCommandMIX(CMD_DOWNLOAD_SIM_MEM, start_index, bytes, 0, NULL, 0);
            //return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_DOWNLOADED_SIMMEM);
            return false;
        }
        case FPGA_MEM: {
            SendCommandNG(CMD_FPGAMEM_DOWNLOAD, NULL, 0);
            return dl_it(dest, bytes, response, ms_timeout, show_warning, CMD_FPGAMEM_DOWNLOADED);
        }
    }
    return false;
}

static bool dl_it(uint8_t *dest, uint32_t bytes, PacketResponseNG *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd) {

    uint32_t bytes_completed = 0;
    __atomic_store_n(&timeout_start_time,  msclock(), __ATOMIC_SEQ_CST);

    // Add delay depending on the communication channel & speed
    if (ms_timeout != (size_t) - 1)
        ms_timeout += communication_delay();

    while (true) {

        if (getReply(response)) {

            if (response->cmd == CMD_ACK)
                return true;
            if (response->cmd == CMD_SPIFFS_DOWNLOAD && response->status == PM3_EMALLOC)
                return false;
            // Spiffs // fpgamem-plot download is converted to NG,
            if (response->cmd == CMD_SPIFFS_DOWNLOAD || response->cmd == CMD_FPGAMEM_DOWNLOAD)
                return true;

            // sample_buf is a array pointer, located in data.c
            // arg0 = offset in transfer. Startindex of this chunk
            // arg1 = length bytes to transfer
            // arg2 = bigbuff tracelength (?)
            if (response->cmd == rec_cmd) {

                uint32_t offset = response->oldarg[0];
                uint32_t copy_bytes = MIN(bytes - bytes_completed, response->oldarg[1]);
                //uint32_t tracelen = response->oldarg[2];

                // extended bounds check1.  upper limit is PM3_CMD_DATA_SIZE
                // shouldn't happen
                copy_bytes = MIN(copy_bytes, PM3_CMD_DATA_SIZE);

                // extended bounds check2.
                if (offset + copy_bytes > bytes) {
                    PrintAndLogEx(FAILED, "ERROR: Out of bounds when downloading from device,  offset %u | len %u | total len %u > buf_size %u", offset, copy_bytes,  offset + copy_bytes,  bytes);
                    break;
                }

                memcpy(dest + offset, response->data.asBytes, copy_bytes);
                bytes_completed += copy_bytes;
            } else if (response->cmd == CMD_WTX && response->length == sizeof(uint16_t)) {
                uint16_t wtx = response->data.asDwords[0] & 0xFFFF;
                PrintAndLogEx(DEBUG, "Got Waiting Time eXtension request %i ms", wtx);
                if (ms_timeout != (size_t) - 1)
                    ms_timeout += wtx;
            }
        }

        uint64_t tmp_clk = __atomic_load_n(&timeout_start_time, __ATOMIC_SEQ_CST);
        if (msclock() - tmp_clk > ms_timeout) {
            PrintAndLogEx(FAILED, "Timed out while trying to download data from device");
            break;
        }

        if (msclock() - tmp_clk > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(INFO, "Waiting for a response from the Proxmark3...");
            PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}
