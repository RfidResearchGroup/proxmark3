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
static bool txBuffer_pending = false;
static pthread_mutex_t txBufferMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t txBufferSig = PTHREAD_COND_INITIALIZER;

// Used by UsbReceiveCommand as a ring buffer for messages that are yet to be
// processed by a command handler (WaitForResponse{,Timeout})
static UsbCommand rxBuffer[CMD_BUFFER_SIZE];

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
        PrintAndLogEx(NORMAL, "Sending bytes to proxmark failed - offline");
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
static void storeCommand(UsbCommand *command) {

    pthread_mutex_lock(&rxBufferMutex);
    if ((cmd_head + 1) % CMD_BUFFER_SIZE == cmd_tail) {
        //If these two are equal, we're about to overwrite in the
        // circular buffer.
        PrintAndLogEx(FAILED, "WARNING: Command buffer about to overwrite command! This needs to be fixed!");
        fflush(stdout);
    }
    //Store the command at the 'head' location
    UsbCommand *destination = &rxBuffer[cmd_head];
    memcpy(destination, command, sizeof(UsbCommand));

    //increment head and wrap
    cmd_head = (cmd_head + 1) % CMD_BUFFER_SIZE;
    pthread_mutex_unlock(&rxBufferMutex);
}
/**
 * @brief getCommand gets a command from an internal circular buffer.
 * @param response location to write command
 * @return 1 if response was returned, 0 if nothing has been received
 */
static int getCommand(UsbCommand *response) {
    pthread_mutex_lock(&rxBufferMutex);
    //If head == tail, there's nothing to read, or if we just got initialized
    if (cmd_head == cmd_tail)  {
        pthread_mutex_unlock(&rxBufferMutex);
        return 0;
    }

    //Pick out the next unread command
    UsbCommand *last_unread = &rxBuffer[cmd_tail];
    memcpy(response, last_unread, sizeof(UsbCommand));

    //Increment tail - this is a circular buffer, so modulo buffer size
    cmd_tail = (cmd_tail + 1) % CMD_BUFFER_SIZE;

    pthread_mutex_unlock(&rxBufferMutex);
    return 1;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
static void UsbCommandReceived(UsbCommand *c) {

    switch (c->cmd) {
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
            storeCommand(c);
            break;
        }
    }
}

/*
bool hookUpPM3() {
    bool ret = false;
    sp = uart_open( comport );

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
        PrintAndLogEx(SUCCESS, "Proxmark reconnected\n");
        serial_port_name = ;
        ret = true;
        offline = 0;
    }
    return ret;
}
*/

void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*uart_communication(void *targ) {
    communication_arg_t *conn = (communication_arg_t *)targ;
    size_t rxlen, totallen = 0;
    UsbCommand rx;
    UsbCommand *prx = &rx;

    //int counter_to_offline = 0;

#if defined(__MACH__) && defined(__APPLE__)
    disableAppNap("Proxmark3 polling UART");
#endif

    while (conn->run) {
        rxlen = 0;
        bool ACK_received = false;

        if (uart_receive(sp, (uint8_t *)prx, sizeof(UsbCommand) - (prx - &rx), &rxlen) && rxlen) {
            prx += rxlen;
            totallen += rxlen;

            if (totallen < sizeof(UsbCommand)) {

                // iceman: this looping is no working as expected at all. The reassemble of package is nonfunctional.
                // solved so far with increasing the timeouts of the serial port configuration.
                PrintAndLogEx(NORMAL, "Foo %d | %d (loop)", prx - &rx, rxlen);
                continue;
            }

            totallen = 0;
            UsbCommandReceived(&rx);
            if (rx.cmd == CMD_ACK) {
                ACK_received = true;
            }
        }

        prx = &rx;

        pthread_mutex_lock(&txBufferMutex);

        if (conn->block_after_ACK) {
            // if we just received an ACK, wait here until a new command is to be transmitted
            if (ACK_received) {
                while (!txBuffer_pending) {
                    pthread_cond_wait(&txBufferSig, &txBufferMutex);
                }
            }
        }

        if (txBuffer_pending) {
            if (!uart_send(sp, (uint8_t *) &txBuffer, sizeof(UsbCommand))) {
                //counter_to_offline++;
                PrintAndLogEx(WARNING, "sending bytes to proxmark failed");
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

bool OpenProxmark(void *port, bool wait_for_port, int timeout, bool flash_mode) {

    char *portname = (char *)port;
    if (!wait_for_port) {
        sp = uart_open(portname);
    } else {
        PrintAndLogEx(SUCCESS, "Waiting for Proxmark to appear on " _YELLOW_("%s"), portname);
        fflush(stdout);
        int openCount = 0;
        do {
            sp = uart_open(portname);
            msleep(500);
            printf(".");
            fflush(stdout);
        } while (++openCount < timeout && (sp == INVALID_SERIAL_PORT || sp == CLAIMED_SERIAL_PORT));
        //PrintAndLogEx(NORMAL, "\n");
    }

    // check result of uart opening
    if (sp == INVALID_SERIAL_PORT) {
        PrintAndLogEx(WARNING, _RED_("ERROR:") "invalid serial port");
        sp = NULL;
        serial_port_name = NULL;
        return false;
    } else if (sp == CLAIMED_SERIAL_PORT) {
        PrintAndLogEx(WARNING, _RED_("ERROR:") "serial port is claimed by another process");
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

        while (getCommand(response)) {
            if (cmd == CMD_UNKNOWN || response->cmd == cmd)
                return true;
        }

        if (msclock() - start_time > ms_timeout)
            break;

        if (msclock() - start_time > 3000 && show_warning) {
            // 3 seconds elapsed (but this doesn't mean the timeout was exceeded)
            PrintAndLogEx(NORMAL, "Waiting for a response from the proxmark...");
            PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
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
            UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {start_index, bytes, 0}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
        }
        case BIG_BUF_EML: {
            UsbCommand c = {CMD_DOWNLOAD_EML_BIGBUF, {start_index, bytes, 0}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_DOWNLOADED_EML_BIGBUF);
        }
        case FLASH_MEM: {
            UsbCommand c = {CMD_FLASHMEM_DOWNLOAD, {start_index, bytes, 0}};
            SendCommand(&c);
            return dl_it(dest, bytes, start_index, response, ms_timeout, show_warning, CMD_FLASHMEM_DOWNLOADED);
        }
        case SIM_MEM: {
            //UsbCommand c = {CMD_DOWNLOAD_SIM_MEM, {start_index, bytes, 0}};
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

        if (getCommand(response)) {

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
            PrintAndLogEx(NORMAL, "Waiting for a response from the proxmark...");
            PrintAndLogEx(NORMAL, "You can cancel this operation by pressing the pm3 button");
            show_warning = false;
        }
    }
    return false;
}
