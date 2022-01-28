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
// ISO 18002 / FeliCa type prototyping
//-----------------------------------------------------------------------------
#ifndef _ISO18_H_
#define _ISO18_H_

#include "common.h"

typedef enum FELICA_COMMAND {
    FELICA_CONNECT = (1 << 0),
    FELICA_NO_DISCONNECT = (1 << 1),
    FELICA_RAW = (1 << 3),
    FELICA_APPEND_CRC = (1 << 5),
    FELICA_NO_SELECT = (1 << 6),
} felica_command_t;

//-----------------------------------------------------------------------------
// FeliCa
//-----------------------------------------------------------------------------
// IDm  = ID manufacturer
// mc = manufactureCode
// mc1 mc2 u1 u2 u3 u4 u5 u6
// PMm  = Product manufacturer
// icCode =
//    ic1 = ROM
//    ic2 = IC
// maximum response time =
//    B3(request service)
//    B4(request response)
//    B5(authenticate)
//    B6(read)
//    B7(write)
//    B8()

// ServiceCode  2bytes  (access-rights)
// FileSystem = 1 Block = 16 bytes


typedef struct {
    uint8_t IDm[8];
    uint8_t code[2];
    uint8_t uid[6];
    uint8_t PMm[8];
    uint8_t iccode[2];
    uint8_t mrt[6];
    uint8_t servicecode[2];
} PACKED felica_card_select_t;

typedef struct {
    uint8_t sync[2];
    uint8_t length[1];
    uint8_t cmd_code[1];
    uint8_t IDm[8];
} PACKED felica_frame_response_t;

typedef struct {
    uint8_t status_flag1[1];
    uint8_t status_flag2[1];
} PACKED felica_status_flags_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t node_number[1];
    uint8_t node_key_versions[2];
} PACKED felica_request_service_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t mode[1];
} PACKED felica_request_request_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    felica_status_flags_t status_flags;
    uint8_t number_of_block[1];
    uint8_t block_data[16];
    uint8_t block_element_number[1];
} PACKED felica_read_without_encryption_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    felica_status_flags_t status_flags;
} PACKED felica_status_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t number_of_systems[1];
    uint8_t system_code_list[32];
} PACKED felica_syscode_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    felica_status_flags_t status_flags;
    uint8_t format_version[1];
    uint8_t basic_version[2];
    uint8_t number_of_option[1];
    uint8_t option_version_list[4];
} PACKED felica_request_spec_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t m2c[8];
    uint8_t m3c[8];
} PACKED felica_auth1_response_t;

typedef struct {
    uint8_t code[1];
    uint8_t IDtc[8];
    uint8_t IDi[8];
    uint8_t PMi[8];
} PACKED felica_auth2_response_t;

#endif // _ISO18_H_
