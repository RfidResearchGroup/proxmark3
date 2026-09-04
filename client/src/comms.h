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
// Code for communicating with the Proxmark3 hardware.
//-----------------------------------------------------------------------------

#ifndef COMMS_H_
#define COMMS_H_

#include "common.h"
#include "pm3_cmd.h"
#include "util.h"
#include "iso7816/iso7816core.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DropField
#define DropField() { clearCommandBuffer(); SetISODEPState(ISODEP_INACTIVE); SendCommandNG(CMD_HF_DROPFIELD, NULL, 0); }
#endif

#ifndef DropFieldEx
#define DropFieldEx(x) { \
        if ( (x) == CC_CONTACTLESS) { \
            DropField(); \
        } \
    }
#endif

#ifndef CMD_BUFFER_SIZE
#define CMD_BUFFER_SIZE 100
#endif

#define COMM_RAW_RECEIVE_LEN (1024)

typedef enum {
    BIG_BUF,
    BIG_BUF_EML,
    FLASH_MEM,
    SIM_MEM,
    SPIFFS,
    FPGA_MEM,
    MCU_FLASH,
    MCU_MEM,
} DeviceMemType_t;

typedef enum {
    PM3_TCPv4,
    PM3_TCPv6,
    PM3_UDPv4,
    PM3_UDPv6,
    PM3_NONE,
} CommunicationProtocol_t;

typedef struct {
    bool run;
    bool block_after_ACK;
    bool send_with_crc_on_usb;
    bool send_with_crc_on_fpc;
    bool send_via_fpc_usart;
    CommunicationProtocol_t send_via_ip;
    bool send_via_local_ip;
    uint32_t uart_speed;
    uint16_t last_command;
    bool listen_for_incoming;
    char serial_port_name[FILE_PATH_SIZE];
    uint16_t max_cmd_data_size;
} communication_arg_t;

extern communication_arg_t g_conn;

typedef struct pm3_device {
    communication_arg_t *g_conn;
    int script_embedded;
} pm3_device_t;


void *uart_reconnect(void *targ);

void *uart_receiver(void *targ);
void SendCommandBL(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len);
void SendCommandOLD(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, const void *data, size_t len);
void SendCommandNG(uint16_t cmd, uint8_t *data, size_t len);
void clearCommandBuffer(void);

#define FLASHMODE_SPEED 460800

bool IsReconnectedOk(void);
bool IsCommunicationThreadDead(void);
bool SetCommunicationReceiveMode(bool isRawMode);
void SetCommunicationRawReceiveBuffer(uint8_t *buffer, size_t len);
size_t GetCommunicationRawReceiveNum(void);

bool OpenProxmarkSilent(pm3_device_t **dev, const char *port, uint32_t speed);
bool OpenProxmark(pm3_device_t **dev, const char *port, bool wait_for_port, int timeout, bool flash_mode, uint32_t speed);
int TestProxmark(pm3_device_t *dev);
void CloseProxmark(pm3_device_t *dev);
void StartReconnectProxmark(void);

size_t WaitForRawDataTimeout(uint8_t *buffer, size_t len, size_t ms_timeout, bool show_process, bool keep_raw_mode);
bool WaitForResponseTimeoutW(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout, bool show_warning);
bool WaitForResponseTimeout(uint32_t cmd, PacketResponseNG *response, size_t ms_timeout);
bool WaitForTxIdle(uint32_t ms_timeout);
bool WaitForResponse(uint32_t cmd, PacketResponseNG *response);

int SetHfFieldTimeout(uint32_t timeout_sec, bool quiet);

bool GetFromDevice(DeviceMemType_t memtype, uint8_t *dest, uint32_t bytes, uint32_t start_index, uint8_t *data, uint32_t datalen, PacketResponseNG *response, size_t ms_timeout, bool show_warning);

#ifdef __cplusplus
}
#endif
#endif
