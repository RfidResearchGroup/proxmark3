//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code for communicating with the proxmark3 hardware.
//-----------------------------------------------------------------------------

#include "comms.h"
#include "crc16.h"

// Serial port that we are communicating with the PM3 on.
static serial_port sp = NULL;
static char *serial_port_name = NULL;

// If TRUE, then there is no active connection to the PM3, and we will drop commands sent.
static bool offline;
// Flags to tell where to add CRC on sent replies
bool send_with_crc_on_usb = false;
bool send_with_crc_on_fpc = true;
// "Session" flag, to tell via which interface next msgs should be sent: USB or FPC USART
bool send_via_fpc = false;

static communication_arg_t conn;

static pthread_t USB_communication_thread;
//static pthread_t FPC_communication_thread;

// Transmit buffer.
static PacketCommandOLD txBuffer;
static PacketCommandNGRaw txBufferNG;
size_t txBufferNGLen;
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

static bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, PacketResponseNG *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd);

// These wrappers are required because it is not possible to access a static
// global variable outside of the context of a single file.
void SetOffline(bool value) {
    offline = value;
}

bool IsOffline() {
    return offline;
}

void SendCommand(PacketCommandOLD *c) {

#ifdef COMMS_DEBUG
    PrintAndLogEx(NORMAL, "Sending %d bytes | cmd %04x\n", sizeof(PacketCommandOLD), c->cmd);
#endif

    if (offline) {
        PrintAndLogEx(WARNING, "Sending bytes to Proxmark3 failed." _YELLOW_("offline"));
        return;
    }

    pthread_mutex_lock(&txBufferMutex);
    /**
    This causes hangups at times, when the pm3 unit is unresponsive or disconnected. The main console thread is alive,
    but comm thread just spins here. Not good.../holiman
    **/
    while (txBuffer_pending) {
        // wait for communication thread to complete sending a previous commmand
        pthread_cond_wait(&txBufferSig, &txBufferMutex);
    }

    txBuffer = *c;
    txBuffer_pending = true;

    // tell communication thread that a new command can be send
    pthread_cond_signal(&txBufferSig);

    pthread_mutex_unlock(&txBufferMutex);

//__atomic_test_and_set(&txcmd_pending, __ATOMIC_SEQ_CST);
}

// Let's move slowly to an API closer to SendCommandNG
void SendCommandOLD(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketCommandOLD c = {CMD_UNKNOWN, {0, 0, 0}, {{0}}};
    c.cmd = cmd;
    c.arg[0] = arg0;
    c.arg[1] = arg1;
    c.arg[2] = arg2;
    if (len && data)
        memcpy(&c.d, data, len);
    SendCommand(&c);
}

static void SendCommandNG_internal(uint16_t cmd, uint8_t *data, size_t len, bool ng) {
#ifdef COMMS_DEBUG
    PrintAndLogEx(NORMAL, "Sending %d bytes of payload | cmd %04x\n", len, cmd);
#endif

    if (offline) {
        PrintAndLogEx(NORMAL, "Sending bytes to proxmark failed - offline");
        return;
    }
    if (len > USB_CMD_DATA_SIZE) {
        PrintAndLogEx(WARNING, "Sending %d bytes of payload is too much, abort", len);
        return;
    }

    PacketCommandNGPostamble *tx_post = (PacketCommandNGPostamble *)((uint8_t *)&txBufferNG + sizeof(PacketCommandNGPreamble) + len);

    pthread_mutex_lock(&txBufferMutex);
    /**
    This causes hangups at times, when the pm3 unit is unresponsive or disconnected. The main console thread is alive,
    but comm thread just spins here. Not good.../holiman
    **/
    while (txBuffer_pending) {
        // wait for communication thread to complete sending a previous commmand
        pthread_cond_wait(&txBufferSig, &txBufferMutex);
    }

    txBufferNG.pre.magic = COMMANDNG_PREAMBLE_MAGIC;
    txBufferNG.pre.ng = ng;
    txBufferNG.pre.length = len;
    txBufferNG.pre.cmd = cmd;
    memcpy(&txBufferNG.data, data, len);

    if ((send_via_fpc && send_with_crc_on_fpc) || ((!send_via_fpc) && send_with_crc_on_usb)) {
        uint8_t first, second;
        compute_crc(CRC_14443_A, (uint8_t *)&txBufferNG, sizeof(PacketCommandNGPreamble) + len, &first, &second);
        tx_post->crc = (first << 8) + second;
    } else {
        tx_post->crc = COMMANDNG_POSTAMBLE_MAGIC;
    }


    txBufferNGLen = sizeof(PacketCommandNGPreamble) + len + sizeof(PacketCommandNGPostamble);
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
    if (len > USB_CMD_DATA_SIZE - sizeof(arg)) {
        PrintAndLogEx(WARNING, "Sending %d bytes of payload is too much for MIX frames, abort", len);
        return;
    }
    uint8_t cmddata[USB_CMD_DATA_SIZE];
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
void clearCommandBuffer() {
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

static void memcpy_filtered(void *dest, const void *src, size_t n, bool filter) {
#if defined(__linux__) || (__APPLE__)
    memcpy(dest, src, n);
#else
    if (filter) {
        // Filter out ANSI sequences on these OS
        uint16_t si=0;
        for (uint16_t i=0; i < n; i++) {
            if ((src[i] == '\x1b') && (i < n - 1) && (src[i+1] >= 0x40) && (src[i+1] <= 0x5F)) { // entering ANSI sequence
                i++;
                if ((src[i] == '[') && (i < n - 1)) { // entering CSI sequence
                    i++;
                    while ((i < n - 1) && (src[i] >= 0x30) && (src[i] <= 0x3F)) { // parameter bytes
                        i++;
                    }
                    while ((i < n - 1) && (src[i] >= 0x20) && (src[i] <= 0x2F)) { // intermediate bytes
                        i++;
                    }
                    if ((src[i] >= 0x40) && (src[i] <= 0x7F)) { // final byte
                        continue;
                    }
                } else {
                    continue;
                }
            }
            dest[si++] = src[i];
        }
    } else {
        memcpy(dest, src, n);
    }
#endif
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
static void PacketResponseReceived(PacketResponseNG *packet) {

//  PrintAndLogEx(NORMAL, "RECV %s magic %08x length %04x status %04x crc %04x cmd %04x",
//                packet->ng ? "NG" : "OLD", packet->magic, packet->length, packet->status, packet->crc, packet->cmd);

    // we got a packet, reset WaitForResponseTimeout timeout
    timeout_start_time = msclock();

    switch (packet->cmd) {
        // First check if we are handling a debug message
        case CMD_DEBUG_PRINT_STRING: {

            char s[USB_CMD_DATA_SIZE + 1];
            memset(s, 0x00, sizeof(s));

            size_t len;
            uint16_t flag;
            if (packet->ng) {
                struct d {
                    uint16_t flag;
                    uint8_t buf[USB_CMD_DATA_SIZE - sizeof(uint16_t)];
                } PACKED;
                struct d *data = (struct d *)&packet->data.asBytes;
                len = packet->length - sizeof(data->flag);
                flag = data->flag;
                memcpy_filtered(s, data->buf, len, flag & FLAG_ANSI);
            } else {
                len = MIN(packet->oldarg[0], USB_CMD_DATA_SIZE);
                flag = packet->oldarg[1];
                memcpy_filtered(s, packet->data.asBytes, len, flag & FLAG_ANSI);
            }

            if (flag & FLAG_LOG) {
                PrintAndLogEx(NORMAL, "#db# %s", s);
            } else {
                if (flag & FLAG_INPLACE)
                    printf("\r");
                printf("%s", s);
                if (flag & FLAG_NEWLINE)
                    printf("\r\n");
            }

            fflush(stdout);
            break;
        }
        case CMD_DEBUG_PRINT_INTEGERS: {
            PrintAndLogEx(NORMAL, "#db# %" PRIx64 ", %" PRIx64 ", %" PRIx64 "", packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        // iceman:  hw status - down the path on device, runs printusbspeed which starts sending a lot of
        // CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K packages which is not dealt with. I wonder if simply ignoring them will
        // work. lets try it.
        default: {
            storeReply(packet);
            break;
        }
    }
}

/*
bool hookUpPM3() {
    bool ret = false;
    sp = uart_open( comport, speed );

    if (sp == INVALID_SERIAL_PORT) {
        PrintAndLogEx(WARNING, "Reconnect failed, retrying...  (reason: invalid serial port)\n");
        sp = NULL;
        serial_port_name = NULL;
        ret = false;
        offline = 1;
    } else if (sp == CLAIMED_SERIAL_PORT) {
        PrintAndLogEx(WARNING, "Reconnect failed, retrying... (reason: serial port is claimed by another process)\n");
        sp = NULL;
        serial_port_name = NULL;
        ret = false;
        offline = 1;
    } else {
        PrintAndLogEx(SUCCESS, "Proxmark3 reconnected\n");
        serial_port_name = ;
        ret = true;
        offline = 0;
    }
    return ret;
}
*/

static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*uart_communication(void *targ) {
    communication_arg_t *connection = (communication_arg_t *)targ;
    uint32_t rxlen;

    PacketResponseNG rx;
    PacketResponseNGRaw rx_raw;
    //int counter_to_offline = 0;

#if defined(__MACH__) && defined(__APPLE__)
    disableAppNap("Proxmark3 polling UART");
#endif

    while (connection->run) {
        rxlen = 0;
        bool ACK_received = false;
        bool error = false;
        if (uart_receive(sp, (uint8_t *)&rx_raw.pre, sizeof(PacketResponseNGPreamble), &rxlen) && (rxlen == sizeof(PacketResponseNGPreamble))) {
            rx.magic = rx_raw.pre.magic;
            uint16_t length = rx_raw.pre.length;
            rx.ng = rx_raw.pre.ng;
            rx.status = rx_raw.pre.status;
            rx.cmd = rx_raw.pre.cmd;
            if (rx.magic == RESPONSENG_PREAMBLE_MAGIC) { // New style NG reply
                if (length > USB_CMD_DATA_SIZE) {
                    PrintAndLogEx(WARNING, "Received packet frame with incompatible length: 0x%04x", length);
                    error = true;
                }
                if ((!error) && (length > 0)) { // Get the variable length payload
                    if ((!uart_receive(sp, (uint8_t *)&rx_raw.data, length, &rxlen)) || (rxlen != length)) {
                        PrintAndLogEx(WARNING, "Received packet frame error variable part too short? %d/%d", rxlen, length);
                        error = true;
                    } else {


                        if (rx.ng) {
                            memcpy(&rx.data, &rx_raw.data, length);
                            rx.length = length;
                        } else {
                            uint64_t arg[3];
                            if (length < sizeof(arg)) {
                                PrintAndLogEx(WARNING, "Received MIX packet frame with incompatible length: 0x%04x", length);
                                error = true;
                            }
                            if (!error) {
                                memcpy(arg, &rx_raw.data, sizeof(arg));
                                rx.oldarg[0] = arg[0];
                                rx.oldarg[1] = arg[1];
                                rx.oldarg[2] = arg[2];
                                memcpy(&rx.data, ((uint8_t *)&rx_raw.data) + sizeof(arg), length - sizeof(arg));
                                rx.length = length - sizeof(arg);
                            }
                        }
                    }
                }
                if (!error) {                        // Get the postamble
                    if ((!uart_receive(sp, (uint8_t *)&rx_raw.foopost, sizeof(PacketResponseNGPostamble), &rxlen)) || (rxlen != sizeof(PacketResponseNGPostamble))) {
                        PrintAndLogEx(WARNING, "Received packet frame error fetching postamble");
                        error = true;
                    }
                }
                if (!error) {                        // Check CRC, accept MAGIC as placeholder
                    rx.crc = rx_raw.foopost.crc;
                    if (rx.crc != RESPONSENG_POSTAMBLE_MAGIC) {
                        uint8_t first, second;
                        compute_crc(CRC_14443_A, (uint8_t *)&rx_raw, sizeof(PacketResponseNGPreamble) + length, &first, &second);
                        if ((first << 8) + second != rx.crc) {
                            PrintAndLogEx(WARNING, "Received packet frame CRC error %02X%02X <> %04X", first, second, rx.crc);
                            error = true;
                        }
                    }
                }
                if (!error) {
//                    PrintAndLogEx(NORMAL, "Received reply NG full !!");
                    PacketResponseReceived(&rx);
//TODO NG don't send ACK anymore but reply with the corresponding cmd, still things seem to work fine...
                    if (rx.cmd == CMD_ACK) {
                        ACK_received = true;
                    }
                }
            } else {                               // Old style reply
                PacketResponseOLD rx_old;
                memcpy(&rx_old, &rx_raw.pre, sizeof(PacketResponseNGPreamble));
                if ((!uart_receive(sp, ((uint8_t *)&rx_old) + sizeof(PacketResponseNGPreamble), sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble), &rxlen)) || (rxlen != sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble))) {
                    PrintAndLogEx(WARNING, "Received packet OLD frame payload error too short? %d/%d", rxlen, sizeof(PacketResponseOLD) - sizeof(PacketResponseNGPreamble));
                    error = true;
                }
                if (!error) {
//                    PrintAndLogEx(NORMAL, "Received reply old full !!");
                    rx.ng = false;
                    rx.magic = 0;
                    rx.status = 0;
                    rx.crc = 0;
                    rx.cmd = rx_old.cmd;
                    rx.oldarg[0] = rx_old.arg[0];
                    rx.oldarg[1] = rx_old.arg[1];
                    rx.oldarg[2] = rx_old.arg[2];
                    rx.length = USB_CMD_DATA_SIZE;
                    memcpy(&rx.data, &rx_old.d, rx.length);
                    PacketResponseReceived(&rx);
                    if (rx.cmd == CMD_ACK) {
                        ACK_received = true;
                    }
                }
            }
        } else {
            if (rxlen > 0) {
                PrintAndLogEx(WARNING, "Received packet frame preamble too short: %d/%d", rxlen, sizeof(PacketResponseNGPreamble));
                error = true;
            }
        }
        // TODO if error, shall we resync ?

        pthread_mutex_lock(&txBufferMutex);

        if (connection->block_after_ACK) {
            // if we just received an ACK, wait here until a new command is to be transmitted
            if (ACK_received) {
                while (!txBuffer_pending) {
                    pthread_cond_wait(&txBufferSig, &txBufferMutex);
                }
            }
        }

        if (txBuffer_pending) {
            if (txBufferNGLen) { // NG packet
                if (!uart_send(sp, (uint8_t *) &txBufferNG, txBufferNGLen)) {
                    //counter_to_offline++;
                    PrintAndLogEx(WARNING, "sending bytes to Proxmark3 device " _RED_("failed"));
                }
                txBufferNGLen = 0;
            } else {
                if (!uart_send(sp, (uint8_t *) &txBuffer, sizeof(PacketCommandOLD))) {
                    //counter_to_offline++;
                    PrintAndLogEx(WARNING, "sending bytes to Proxmark3 device " _RED_("failed"));
                }
            }
            txBuffer_pending = false;

            // tell main thread that txBuffer is empty
            pthread_cond_signal(&txBufferSig);
        }

        pthread_mutex_unlock(&txBufferMutex);
    }

    // when this reader thread dies, we close the serial port.
    uart_close(sp);
    sp = NULL;

#if defined(__MACH__) && defined(__APPLE__)
    enableAppNap();
#endif

    pthread_exit(NULL);
    return NULL;
}

bool OpenProxmark(void *port, bool wait_for_port, int timeout, bool flash_mode, uint32_t speed) {

    char *portname = (char *)port;
    if (!wait_for_port) {
        PrintAndLogEx(INFO, "Using UART port " _YELLOW_("%s"), portname);
        sp = uart_open(portname, speed);
    } else {
        PrintAndLogEx(SUCCESS, "Waiting for Proxmark3 to appear on " _YELLOW_("%s"), portname);
        fflush(stdout);
        int openCount = 0;
        do {
            sp = uart_open(portname, speed);
            msleep(500);
            printf(".");
            fflush(stdout);
        } while (++openCount < timeout && (sp == INVALID_SERIAL_PORT || sp == CLAIMED_SERIAL_PORT));
        //PrintAndLogEx(NORMAL, "\n");
    }

    // check result of uart opening
    if (sp == INVALID_SERIAL_PORT) {
        PrintAndLogEx(WARNING, _RED_("ERROR:") "invalid serial port " _YELLOW_("%s"), portname);
        sp = NULL;
        serial_port_name = NULL;
        return false;
    } else if (sp == CLAIMED_SERIAL_PORT) {
        PrintAndLogEx(WARNING, _RED_("ERROR:") "serial port " _YELLOW_("%s") " is claimed by another process", portname);
        sp = NULL;
        serial_port_name = NULL;
        return false;
    } else {
        // start the USB communication thread
        serial_port_name = portname;
        conn.run = true;
        conn.block_after_ACK = flash_mode;
        pthread_create(&USB_communication_thread, NULL, &uart_communication, &conn);
        //pthread_create(&FPC_communication_thread, NULL, &uart_communication, &conn);
        fflush(stdout);
        // create a mutex to avoid interlacing print commands from our different threads
        //pthread_mutex_init(&print_lock, NULL);
        return true;
    }
}

// check if we can communicate with Pm3
int TestProxmark(void) {
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandOLD(CMD_PING, 0, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 5000)) {
        send_via_fpc = resp.oldarg[0] == 1;
        PrintAndLogEx(INFO, "Communicating with PM3 over %s.", send_via_fpc ? "FPC" : "USB");
        return 1;
    } else {
        return 0;
    }
}

void CloseProxmark(void) {
    conn.run = false;

#ifdef __BIONIC__
    if (USB_communication_thread != 0) {
        pthread_join(USB_communication_thread, NULL);
    }
#else
    pthread_join(USB_communication_thread, NULL);
    //pthread_join(FPC_communication_thread, NULL);
#endif

    if (sp) {
        uart_close(sp);
    }

#if defined(__linux__) && !defined(NO_UNLINK)
    // Fix for linux, it seems that it is extremely slow to release the serial port file descriptor /dev/*
    //
    // This may be disabled at compile-time with -DNO_UNLINK (used for a JNI-based serial port on Android).
    if (serial_port_name) {
        unlink(serial_port_name);
    }
#endif

    // Clean up our state
    sp = NULL;
    serial_port_name = NULL;
    memset(&USB_communication_thread, 0, sizeof(pthread_t));
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
    if (send_via_fpc)  // needed also for Windows USB USART??
        return 2 * (12000000 / uart_speed);
    return 100;
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

    if (response == NULL)
        response = &resp;

    // Add delay depending on the communication channel & speed
    if (ms_timeout != (size_t) -1)
        ms_timeout += communication_delay();

    timeout_start_time = msclock();

    // Wait until the command is received
    while (true) {

        while (getReply(response)) {
            if (cmd == CMD_UNKNOWN || response->cmd == cmd) {
//                PrintAndLogEx(INFO, "Waited %i ms", msclock() - timeout_start_time);
                return true;
            }
        }

        if (msclock() - timeout_start_time > ms_timeout)
            break;

        if (msclock() - timeout_start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(INFO, "Waiting for a response from the proxmark3...");
            PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
//    PrintAndLogEx(INFO, "Wait timeout after %i ms", msclock() - timeout_start_time);
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
* @param response struct to copy last command (CMD_ACK) into
* @param ms_timeout timeout in milliseconds
* @param show_warning display message after 2 seconds
* @return true if command was returned, otherwise false
*/
bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, PacketResponseNG *response, size_t ms_timeout, bool show_warning) {

    if (dest == NULL) return false;
    if (bytes == 0) return true;

    PacketResponseNG resp;
    if (response == NULL)
        response = &resp;

    // clear
    clearCommandBuffer();

    switch (memtype) {
        case BIG_BUF: {
            SendCommandOLD(CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
        }
        case BIG_BUF_EML: {
            SendCommandOLD(CMD_DOWNLOAD_EML_BIGBUF, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_EML_BIGBUF);
        }
        case FLASH_MEM: {
            SendCommandOLD(CMD_FLASHMEM_DOWNLOAD, start_index, bytes, 0, NULL, 0);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_FLASHMEM_DOWNLOADED);
        }
        case SIM_MEM: {
            //SendCommandOLD(CMD_DOWNLOAD_SIM_MEM, start_index, bytes, 0, NULL, 0);
            //return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_SIMMEM);
            return false;
        }
    }
    return false;
}

static bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, PacketResponseNG *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd) {

    uint32_t bytes_completed = 0;
    timeout_start_time = msclock();

    // Add delay depending on the communication channel & speed
    if (ms_timeout != (size_t) -1)
        ms_timeout += communication_delay();

    while (true) {

        if (getReply(response)) {

            // sample_buf is a array pointer, located in data.c
            // arg0 = offset in transfer. Startindex of this chunk
            // arg1 = length bytes to transfer
            // arg2 = bigbuff tracelength (?)
            if (response->cmd == rec_cmd) {

                uint32_t offset = response->oldarg[0];
                uint32_t copy_bytes = MIN(bytes - bytes_completed, response->oldarg[1]);
                //uint32_t tracelen = response->oldarg[2];

                // extended bounds check1.  upper limit is USB_CMD_DATA_SIZE
                // shouldn't happen
                copy_bytes = MIN(copy_bytes, USB_CMD_DATA_SIZE);

                // extended bounds check2.
                if (offset + copy_bytes > bytes) {
                    PrintAndLogEx(FAILED, "ERROR: Out of bounds when downloading from device,  offset %u | len %u | total len %u > buf_size %u", offset, copy_bytes,  offset + copy_bytes,  bytes);
                    break;
                }

                memcpy(dest + offset, response->data.asBytes, copy_bytes);
                bytes_completed += copy_bytes;
            } else if (response->cmd == CMD_ACK) {
                return true;
            }
        }

        if (msclock() - timeout_start_time > ms_timeout) {
            PrintAndLogEx(FAILED, "Timed out while trying to download data from device");
            break;
        }

        if (msclock() - timeout_start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(NORMAL, "Waiting for a response from the Proxmark3...");
            PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}
