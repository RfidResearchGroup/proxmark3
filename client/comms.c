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

static communication_arg_t conn;

static pthread_t USB_communication_thread;
//static pthread_t FPC_communication_thread;

// Transmit buffer.
static UsbCommand txBuffer;
static uint8_t txBufferNG[USB_COMMANDNG_MAXLEN];
size_t txBufferNGLen;
static bool txBuffer_pending = false;
static pthread_mutex_t txBufferMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t txBufferSig = PTHREAD_COND_INITIALIZER;

// Used by UsbReceiveCommand as a ring buffer for messages that are yet to be
// processed by a command handler (WaitForResponse{,Timeout})
static uint8_t rxBuffer[CMD_BUFFER_SIZE][USB_REPLYNG_MAXLEN];

// Points to the next empty position to write to
static int cmd_head = 0;

// Points to the position of the last unread command
static int cmd_tail = 0;

// to lock rxBuffer operations from different threads
static pthread_mutex_t rxBufferMutex = PTHREAD_MUTEX_INITIALIZER;

// These wrappers are required because it is not possible to access a static
// global variable outside of the context of a single file.
void SetOffline(bool value) {
    offline = value;
}

bool IsOffline() {
    return offline;
}

void SendCommand(UsbCommand *c) {

#ifdef COMMS_DEBUG
    PrintAndLogEx(NORMAL, "Sending %d bytes | cmd %04x\n", sizeof(UsbCommand), c->cmd);
#endif

    if (offline) {
        PrintAndLogEx(WARNING, "Sending bytes to Proxmark3 failed." _YELLOW_("offline") );
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

void SendCommandNG(uint16_t cmd, uint8_t *data, size_t len) {

#ifdef COMMS_DEBUG
    PrintAndLogEx(NORMAL, "Sending %d bytes of payload | cmd %04x\n", len, cmd);
#endif

    if (offline) {
        PrintAndLogEx(NORMAL, "Sending bytes to proxmark failed - offline");
        return;
    }
    if (len > USB_DATANG_SIZE) {
        PrintAndLogEx(WARNING, "Sending %d bytes of payload is too much, abort", len);
        return;
    }

    UsbCommandNGPreamble *tx_pre = (UsbCommandNGPreamble *)txBufferNG;
    UsbCommandNGPostamble *tx_post = (UsbCommandNGPostamble *)(txBufferNG + sizeof(UsbCommandNGPreamble) + len);

    pthread_mutex_lock(&txBufferMutex);
    /**
    This causes hangups at times, when the pm3 unit is unresponsive or disconnected. The main console thread is alive,
    but comm thread just spins here. Not good.../holiman
    **/
    while (txBuffer_pending) {
        // wait for communication thread to complete sending a previous commmand
        pthread_cond_wait(&txBufferSig, &txBufferMutex);
    }

    tx_pre->magic = USB_COMMANDNG_PREAMBLE_MAGIC;
    tx_pre->length = len;
    tx_pre->cmd = cmd;
    memcpy(txBufferNG + sizeof(UsbCommandNGPreamble), data, len);
    uint8_t first, second;
    compute_crc(CRC_14443_A, txBufferNG, sizeof(UsbCommandNGPreamble) + len, &first, &second);
    tx_post->crc = (first << 8) + second;
    txBufferNGLen = sizeof(UsbCommandNGPreamble) + len + sizeof(UsbCommandNGPostamble);
    txBuffer_pending = true;

    // tell communication thread that a new command can be send
    pthread_cond_signal(&txBufferSig);

    pthread_mutex_unlock(&txBufferMutex);

//__atomic_test_and_set(&txcmd_pending, __ATOMIC_SEQ_CST);
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
static void storeReply(uint8_t *packet) {
    pthread_mutex_lock(&rxBufferMutex);
    if ((cmd_head + 1) % CMD_BUFFER_SIZE == cmd_tail) {
        //If these two are equal, we're about to overwrite in the
        // circular buffer.
        PrintAndLogEx(FAILED, "WARNING: Command buffer about to overwrite command! This needs to be fixed!");
        fflush(stdout);
    }
    //Store the command at the 'head' location
    uint8_t *destination = rxBuffer[cmd_head];
    memcpy(destination, packet, USB_REPLYNG_MAXLEN);

    //increment head and wrap
    cmd_head = (cmd_head + 1) % CMD_BUFFER_SIZE;
    pthread_mutex_unlock(&rxBufferMutex);
}
/**
 * @brief getCommand gets a command from an internal circular buffer.
 * @param response location to write command
 * @return 1 if response was returned, 0 if nothing has been received
 */
static int getReply(uint8_t *response) {
    pthread_mutex_lock(&rxBufferMutex);
    //If head == tail, there's nothing to read, or if we just got initialized
    if (cmd_head == cmd_tail)  {
        pthread_mutex_unlock(&rxBufferMutex);
        return 0;
    }

    //Pick out the next unread command
    uint8_t *last_unread = rxBuffer[cmd_tail];
    memcpy(response, last_unread, USB_REPLYNG_MAXLEN);

    //Increment tail - this is a circular buffer, so modulo buffer size
    cmd_tail = (cmd_tail + 1) % CMD_BUFFER_SIZE;

    pthread_mutex_unlock(&rxBufferMutex);
    return 1;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
static void UsbReplyReceived(bool reply_ng, uint8_t *packet) {

    uint64_t cmd; // To accommodate old cmd, can be reduced to uint16_t once all old cmds are gone.
    UsbReplyNGPreamble *pre_ng = (UsbReplyNGPreamble *)packet;

    // For cmd handlers still using old cmd format:
    UsbCommand *c = (UsbCommand *)packet;
    if (reply_ng) {
        cmd = pre_ng->cmd;
    } else {
        cmd = c->cmd;
    }

    switch (cmd) {
        // First check if we are handling a debug message
        case CMD_DEBUG_PRINT_STRING: {

            char s[USB_CMD_DATA_SIZE + 1];
            memset(s, 0x00, sizeof(s));
            size_t len = MIN(c->arg[0], USB_CMD_DATA_SIZE);
            memcpy(s, c->d.asBytes, len);
            uint64_t flag = c->arg[1];

            switch (flag) {
                case FLAG_RAWPRINT:
                    printf("%s", s);
                    break;
                case FLAG_NONEWLINE:
                    printf("\r%s", s);
                    break;
                case FLAG_NOLOG:
                    printf("%s\r\n", s);
                    break;
                //case FLAG_NOPROMPT:
                //  break;
                case FLAG_NOOPT:
                default:
                    PrintAndLogEx(NORMAL, "#db# %s", s);
                    break;
            }
            fflush(stdout);
            break;
        }
        case CMD_DEBUG_PRINT_INTEGERS: {
            PrintAndLogEx(NORMAL, "#db# %" PRIx64 ", %" PRIx64 ", %" PRIx64 "", c->arg[0], c->arg[1], c->arg[2]);
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
    size_t rxlen;

    uint8_t rx[USB_REPLYNG_MAXLEN];
    UsbReplyNGPreamble *pre = (UsbReplyNGPreamble *)rx;
    UsbReplyNGPostamble *post = (UsbReplyNGPostamble *)(rx + sizeof(UsbReplyNGPreamble) + USB_DATANG_SIZE);
    //int counter_to_offline = 0;

#if defined(__MACH__) && defined(__APPLE__)
    disableAppNap("Proxmark3 polling UART");
#endif

    while (connection->run) {
        rxlen = 0;
        bool ACK_received = false;
        bool error = false;
        if (uart_receive(sp, rx, sizeof(UsbReplyNGPreamble), &rxlen) && (rxlen == sizeof(UsbReplyNGPreamble))) {
            if (pre->magic == USB_REPLYNG_PREAMBLE_MAGIC) { // New style NG reply
                if (pre->length > USB_DATANG_SIZE) {
                    PrintAndLogEx(WARNING, "Received packet frame with incompatible length: 0x%04x", pre->length);
                    error = true;
                }
                if ((!error) && (pre->length > 0)) { // Get the variable length payload
                    if ((!uart_receive(sp, rx + sizeof(UsbReplyNGPreamble), pre->length, &rxlen)) || (rxlen != pre->length)) {
                        PrintAndLogEx(WARNING, "Received packet frame error variable part too short? %d/%d", rxlen, pre->length);
                        error = true;
                    }
                }
                if (!error) {                        // Get the postamble
                    if ((!uart_receive(sp, rx + sizeof(UsbReplyNGPreamble) + USB_DATANG_SIZE, sizeof(UsbReplyNGPostamble), &rxlen)) || (rxlen != sizeof(UsbReplyNGPostamble))) {
                        PrintAndLogEx(WARNING, "Received packet frame error fetching postamble");
                        error = true;
                    }
                    uint8_t first, second;
                    compute_crc(CRC_14443_A, rx, sizeof(UsbReplyNGPreamble) + pre->length, &first, &second);
                    if ((first << 8) + second != post->crc) {
                        PrintAndLogEx(WARNING, "Received packet frame CRC error %02X%02X <> %04X", first, second, post->crc);
                        error = true;
                    }
                }
                if (!error) {
//                    PrintAndLogEx(NORMAL, "Received reply NG full !!");
                    UsbReplyReceived(true, rx);
//TODO NG don't send ACK anymore but reply with the corresponding cmd, still things seem to work fine...
                    if (pre->cmd == CMD_ACK) {
                        ACK_received = true;
                    }
                }
            } else {                               // Old style reply

                if ((!uart_receive(sp, rx + sizeof(UsbReplyNGPreamble), sizeof(UsbCommand) - sizeof(UsbReplyNGPreamble), &rxlen)) || (rxlen != sizeof(UsbCommand) - sizeof(UsbReplyNGPreamble))) {
                    PrintAndLogEx(WARNING, "Received packet frame error var part too short? %d/%d", rxlen, sizeof(UsbCommand) - sizeof(UsbReplyNGPreamble));
                    error = true;
                }
                if (!error) {
                    UsbReplyReceived(false, rx);
                    if (((UsbCommand *)rx)->cmd == CMD_ACK) {
                        ACK_received = true;
                    }
                }
            }
        } else {
            if (rxlen > 0) {
                PrintAndLogEx(WARNING, "Received packet frame preamble too short: %d/%d", rxlen, sizeof(UsbReplyNGPreamble));
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
                    PrintAndLogEx(WARNING, "sending bytes to Proxmark3 device" _RED_("failed") );
                }
                txBufferNGLen = 0;
            } else {
                if (!uart_send(sp, (uint8_t *) &txBuffer, sizeof(UsbCommand))) {
                    //counter_to_offline++;
                    PrintAndLogEx(WARNING, "sending bytes to Proxmark3 device" _RED_("failed") );
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
    UsbCommand resp;
    UsbCommand c = {CMD_PING, {0, 0, 0}, {{0}}};
    SendCommand(&c);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 5000)) {
        PrintAndLogEx(INFO, "Communicating with PM3 over %s.", resp.arg[0] == 1 ? "FPC" : "USB");
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

/**
 * @brief Waits for a certain response type. This method waits for a maximum of
 * ms_timeout milliseconds for a specified response command.

 * @param cmd command to wait for, or CMD_UNKNOWN to take any command.
 * @param response struct to copy received command into.
 * @param ms_timeout display message after 3 seconds
 * @param show_warning display message after 3 seconds
 * @return true if command was returned, otherwise false
 */
bool WaitForResponseTimeoutW(uint32_t cmd, UsbCommand *response, size_t ms_timeout, bool show_warning) {

    UsbCommand resp;

    if (response == NULL)
        response = &resp;

    uint64_t start_time = msclock();

    // Wait until the command is received
    while (true) {

        while (getReply((uint8_t *)response)) {
            if (cmd == CMD_UNKNOWN || response->cmd == cmd)
                return true;
        }

        if (msclock() - start_time > ms_timeout)
            break;

        if (msclock() - start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(INFO, "Waiting for a response from the proxmark3...");
            PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}

bool WaitForResponseTimeout(uint32_t cmd, UsbCommand *response, size_t ms_timeout) {
    return WaitForResponseTimeoutW(cmd, response, ms_timeout, true);
}

bool WaitForResponse(uint32_t cmd, UsbCommand *response) {
    return WaitForResponseTimeoutW(cmd, response, -1, true);
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
bool WaitForResponseNGTimeoutW(uint32_t cmd, uint8_t *response, size_t ms_timeout, bool show_warning) {

    uint8_t resp[USB_REPLYNG_MAXLEN];
    if (response == NULL)
        response = resp;
    UsbCommandNGPreamble *pre_ng = (UsbCommandNGPreamble *)response;

    uint64_t start_time = msclock();

    // Wait until the command is received
    while (true) {

        while (getReply(response)) {
            if (cmd == CMD_UNKNOWN || pre_ng->cmd == cmd)
                return true;
        }

        if (msclock() - start_time > ms_timeout)
            break;

        if (msclock() - start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(INFO, "Waiting for a response from the proxmark3...");
            PrintAndLogEx(INFO, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}

bool WaitForResponseNGTimeout(uint32_t cmd, uint8_t *response, size_t ms_timeout) {
    return WaitForResponseNGTimeoutW(cmd, response, ms_timeout, true);
}

bool WaitForResponseNG(uint32_t cmd, uint8_t *response) {
    return WaitForResponseNGTimeoutW(cmd, response, -1, true);
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
bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning) {

    if (dest == NULL) return false;
    if (bytes == 0) return true;

    UsbCommand resp;
    if (response == NULL)
        response = &resp;

    // clear
    clearCommandBuffer();

    switch (memtype) {
        case BIG_BUF: {
            UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, bytes, 0}, {{0}}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
        }
        case BIG_BUF_EML: {
            UsbCommand c = {CMD_DOWNLOAD_EML_BIGBUF, {start_index, bytes, 0}, {{0}}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_EML_BIGBUF);
        }
        case FLASH_MEM: {
            UsbCommand c = {CMD_FLASHMEM_DOWNLOAD, {start_index, bytes, 0}, {{0}}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_FLASHMEM_DOWNLOADED);
        }
        case SIM_MEM: {
            //UsbCommand c = {CMD_DOWNLOAD_SIM_MEM, {start_index, bytes, 0}, {{0}}};
            //SendCommand(&c);
            //return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_SIMMEM);
            return false;
        }
    }
    return false;
}

bool dl_it(uint8_t *dest, uint32_t bytes, uint32_t start_index, UsbCommand *response, size_t ms_timeout, bool show_warning, uint32_t rec_cmd) {

    uint32_t bytes_completed = 0;
    uint64_t start_time = msclock();

    while (true) {

        if (getReply((uint8_t *)response)) {

            // sample_buf is a array pointer, located in data.c
            // arg0 = offset in transfer. Startindex of this chunk
            // arg1 = length bytes to transfer
            // arg2 = bigbuff tracelength (?)
            if (response->cmd == rec_cmd) {

                uint32_t offset = response->arg[0];
                uint32_t copy_bytes = MIN(bytes - bytes_completed, response->arg[1]);
                //uint32_t tracelen = c->arg[2];

                // extended bounds check1.  upper limit is USB_CMD_DATA_SIZE
                // shouldn't happen
                copy_bytes = MIN(copy_bytes, USB_CMD_DATA_SIZE);

                // extended bounds check2.
                if (offset + copy_bytes > bytes) {
                    PrintAndLogEx(FAILED, "ERROR: Out of bounds when downloading from device,  offset %u | len %u | total len %u > buf_size %u", offset, copy_bytes,  offset + copy_bytes,  bytes);
                    break;
                }

                memcpy(dest + offset, response->d.asBytes, copy_bytes);
                bytes_completed += copy_bytes;
            } else if (response->cmd == CMD_ACK) {
                return true;
            }
        }

        if (msclock() - start_time > ms_timeout) {
            PrintAndLogEx(FAILED, "Timed out while trying to download data from device");
            break;
        }

        if (msclock() - start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(NORMAL, "Waiting for a response from the Proxmark3...");
            PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}
