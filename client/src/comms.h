//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code for communicating with the Proxmark3 hardware.
//-----------------------------------------------------------------------------

#ifndef COMMS_H_
#define COMMS_H_

#include "common.h"
#include "pm3_cmd.h"    // Packet structs
#include "util.h"       // FILE_PATH_SIZE

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DropField
#define DropField() { \
        clearCommandBuffer(); SendCommandNG(CMD_HF_DROPFIELD, NULL, 0); \
    }
#endif

#ifndef DropFieldEx
#define DropFieldEx(x) { \
        if ( (x) == ECC_CONTACTLESS) { \
            DropField(); \
        } \
    }
#endif

//For storing command that are received from the device
#ifndef CMD_BUFFER_SIZE
#define CMD_BUFFER_SIZE 100
#endif

typedef enum {
    BIG_BUF,
    BIG_BUF_EML,
    FLASH_MEM,
    SIM_MEM,
    SPIFFS,
    FPGA_MEM,
} DeviceMemType_t;


typedef struct {
    bool run; // If TRUE, continue running the uart_communication thread
    bool block_after_ACK; // if true, block after receiving an ACK package
    // Flags to tell where to add CRC on sent replies
    bool send_with_crc_on_usb;
    bool send_with_crc_on_fpc;
    // "Session" flag, to tell via which interface next msgs are sent: USB or FPC USART
    bool send_via_fpc_usart;
    // To memorise baudrate
    uint32_t uart_speed;
    uint16_t last_command;
    char serial_port_name[FILE_PATH_SIZE];
} communication_arg_t;

extern communication_arg_t conn;

void *uart_receiver(void *targ);
void SendCommandBL(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
void SendCommandOLD(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
void SendCommandNG(uint16_t cmd, uint8_t *data, size_t len);
void SendCommandMIX(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
void clearCommandBuffer(void);

#define FLASHMODE_SPEED 460800
bool IsCommunicationThreadDead(void);
typedef struct pm3_device pm3_device;
bool OpenProxmark(pm3_device *current_device, char *port, bool wait_for_port, int timeout, bool flash_mode, uint32_t speed);
int TestProxmark(void);
void CloseProxmark(void);

bool WaitForResponseTimeoutW(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout, bool show_warning);
bool WaitForResponseTimeout(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout);
bool WaitForResponse(uint32_t cmd, PacketResponseNG *response);

//bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, PacketResponseNG *response, size_t ms_timeout, bool show_warning);
bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, uint8_t *data, uint32_t datalen, PacketResponseNG *response, size_t ms_timeout, bool show_warning);

#ifdef __cplusplus
}
#endif
#endif


