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

// FeliCa length byte includes itself, so application-level payload max is 254 bytes.
#define FELICA_MAX_DATA_SIZE 254U
// 255 base length (max 254 data + 1 len byte) + 2 sync + 2 crc + 1 extra for safety.
#define FELICA_MAX_RF_FRAME_SIZE 260U
#define FELICA_SPECIFICATION_VERSION_MAX_OPTIONS 16U
#define FELICA_SYSTEM_NODE 0xFFFFU

#define FELICA_SERVICE_ATTRIBUTE_UNAUTH_READ    0x01U
#define FELICA_SERVICE_ATTRIBUTE_READ_ONLY      0x02U
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_ACCESS  0x08U
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC         0x0CU
#define FELICA_SERVICE_ATTRIBUTE_PURSE          0x10U
#define FELICA_SERVICE_ATTRIBUTE_PIN_REQUIRED   0x20U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_SUBFIELD 0x06U
#define FELICA_NODE_ATTRIBUTE_MASK              0x3FU

#define FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA             0x00U
#define FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA          0x01U
#define FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA_WITH_PIN    0x20U
#define FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA_WITH_PIN 0x21U
#define FELICA_AREA_ATTRIBUTE_END_ROOT_AREA                  0x3EU
#define FELICA_AREA_ATTRIBUTE_END_SUB_AREA                   0x3FU

#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITH_KEY            0x08U
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITHOUT_KEY         0x09U
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITH_KEY            0x0AU
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITHOUT_KEY         0x0BU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITH_KEY            0x0CU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITHOUT_KEY         0x0DU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITH_KEY            0x0EU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITHOUT_KEY         0x0FU
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITH_KEY             0x10U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITHOUT_KEY          0x11U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITH_KEY       0x12U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITHOUT_KEY    0x13U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITH_KEY      0x14U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITHOUT_KEY   0x15U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITH_KEY             0x16U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITHOUT_KEY          0x17U

#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITH_KEY_WITH_PIN          0x28U
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITHOUT_KEY_WITH_PIN       0x29U
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITH_KEY_WITH_PIN          0x2AU
#define FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITHOUT_KEY_WITH_PIN       0x2BU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITH_KEY_WITH_PIN          0x2CU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITHOUT_KEY_WITH_PIN       0x2DU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITH_KEY_WITH_PIN          0x2EU
#define FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITHOUT_KEY_WITH_PIN       0x2FU
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITH_KEY_WITH_PIN           0x30U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITHOUT_KEY_WITH_PIN        0x31U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITH_KEY_WITH_PIN     0x32U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITHOUT_KEY_WITH_PIN  0x33U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITH_KEY_WITH_PIN    0x34U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITHOUT_KEY_WITH_PIN 0x35U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITH_KEY_WITH_PIN           0x36U
#define FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITHOUT_KEY_WITH_PIN        0x37U

#define FELICA_ENCRYPTION_IDENTIFIER_AES128        0x4FU
#define FELICA_ENCRYPTION_IDENTIFIER_AES128_DES112 0x43U
#define FELICA_ENCRYPTION_IDENTIFIER_AES128_DES56  0x41U
#define FELICA_ENCRYPTION_IDENTIFIER_DES112        0x3FU
#define FELICA_ENCRYPTION_IDENTIFIER_DES56         0x2FU

typedef enum FELICA_COMMAND {
    FELICA_CONNECT = (1 << 0),
    FELICA_NO_DISCONNECT = (1 << 1),
    FELICA_RAW = (1 << 3),
    FELICA_APPEND_CRC = (1 << 5),
    FELICA_NO_SELECT = (1 << 6),
    FELICA_CLEARTRACE = (1 << 7),
} felica_command_t;

typedef struct {
    uint8_t flags;      // PM3 flags, see felica_command_t
    uint16_t numbits;   // optional number of bits for raw exchange
    uint16_t rawlen;    // bytes in raw[]
    uint8_t raw[];
} PACKED felica_raw_cmd_t;

#define FELICA_RAW_LEN(x) (sizeof(felica_raw_cmd_t) + (x))

typedef struct {
    uint8_t completed;
    uint16_t tracelen;
} PACKED felica_lite_dump_resp_t;

typedef enum FELICA_SIM_SUBCOMMAND {
    FELICA_SIM_CLEAR = 0x00,
    FELICA_SIM_LOAD = 0x01,
    FELICA_SIM_START = 0x02,
} felica_sim_subcommand_t;

typedef enum FELICA_SIM_RWE_ERROR_LOCATION_INDICATION {
    FELICA_SIM_RWE_ERROR_LOCATION_MASK = 0x00,
    FELICA_SIM_RWE_ERROR_LOCATION_INDEX = 0x01,
    FELICA_SIM_RWE_ERROR_LOCATION_FLAG = 0x02,
} felica_sim_rwe_error_location_indication_t;

#define FELICA_SIM_MODEL_MAGIC 0x31465346U // FSF1
#define FELICA_SIM_MODEL_VERSION 3U
#define FELICA_SIM_UPLOAD_CHUNK_MAX (PM3_CMD_DATA_SIZE - sizeof(felica_sim_upload_t))
#define FELICA_SIM_RUNTIME_RESERVE 512U
#define FELICA_SIM_SPECIFICATION_VERSION_MAX_LEN (4U + (FELICA_SPECIFICATION_VERSION_MAX_OPTIONS * 2U))
#define FELICA_SIM_PRODUCT_INFORMATION_MAX_LEN 64U
#define FELICA_SIM_CONTAINER_ISSUE_INFORMATION_LEN 16U

#define FELICA_SIM_NODE_TYPE_MASK    0x03U
#define FELICA_SIM_NODE_TYPE_SERVICE 0x01U
#define FELICA_SIM_NODE_TYPE_AREA    0x02U
#define FELICA_SIM_NODE_TYPE_SYSTEM  0x03U
#define FELICA_SIM_NODE_HAS_DES_KEY_VERSION 0x04U
#define FELICA_SIM_NODE_HAS_AES_KEY_VERSION 0x08U

typedef struct {
    uint8_t subcommand;
    uint32_t total_len;
    uint32_t offset;
    uint16_t model_crc;
    uint16_t chunk_len;
    uint8_t rwe_error_location_indication;
    uint8_t data[];
} PACKED felica_sim_upload_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t header_len;
    uint32_t total_len;
    uint16_t model_crc;
    uint16_t system_count;
    uint16_t node_count;
    uint16_t block_count;
    uint32_t system_offset;
    uint32_t node_offset;
    uint32_t block_offset;
    uint32_t metadata_offset;
    uint16_t specification_version_len;
    uint16_t product_information_len;
    uint16_t container_issue_information_len;
    uint16_t reserved;
} PACKED felica_sim_model_header_t;

typedef struct {
    uint16_t system_code;
    uint8_t idm[8];
    uint8_t pmm[8];
    uint8_t encryption_identifier;
    uint8_t reserved;
    uint16_t first_node;
    uint16_t node_count;
} PACKED felica_sim_system_record_t;

typedef struct {
    uint16_t system_index;
    uint16_t node_code_le;
    uint16_t end_code_le;
    uint16_t first_block;
    uint16_t block_count;
    uint16_t des_key_version_le;
    uint16_t aes_key_version_le;
    uint8_t flags;
    uint8_t reserved;
} PACKED felica_sim_node_record_t;

typedef struct {
    uint16_t node_index;
    uint16_t block_number;
    uint8_t data[16];
} PACKED felica_sim_block_record_t;

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

typedef struct  {
    uint8_t sync[2];
    uint8_t length[1];
    uint8_t cmd_code[1];
} PACKED felica_frame_response_noidm_t;

typedef struct {
    uint8_t status_flag1[1];
    uint8_t status_flag2[1];
} PACKED felica_status_flags_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t reserved[2];
} PACKED felica_get_container_id_request_t;

typedef struct {
    felica_frame_response_noidm_t frame_response;
    uint8_t container_idm[8];
} PACKED felica_get_container_id_response_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t property_index[2];
} PACKED felica_get_container_property_request_t;

typedef struct {
    felica_frame_response_noidm_t frame_response;
    uint8_t property_data[];
} PACKED felica_get_container_property_response_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t IDm[8];
    uint8_t reserved[2];
} PACKED felica_get_container_issue_info_request_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t format_version_carrier_information[5];
    uint8_t mobile_phone_model_information[11];
} PACKED felica_get_container_issue_info_response_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t IDm[8];
} PACKED felica_get_platform_info_request_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t IDm[8];
    uint8_t reserved[2];
} PACKED felica_request_specification_version_request_t;

typedef struct {
    felica_status_flags_t status_flags;
    bool has_specification_version;
    uint8_t format_version;
    uint8_t basic_version[2];
    uint8_t number_of_option;
    size_t option_version_count;
    uint8_t option_version_list[FELICA_SPECIFICATION_VERSION_MAX_OPTIONS * 2];
} felica_request_specification_version_info_t;

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
    uint8_t block_data[16 * 15];
} PACKED felica_read_without_encryption_response_t;

typedef struct {
    felica_frame_response_t frame_response;
    felica_status_flags_t status_flags;
} PACKED felica_status_response_t;

typedef struct {
    uint8_t length[1];
    uint8_t command_code[1];
    uint8_t IDm[8];
} PACKED felica_request_system_code_request_t;

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t number_of_systems[1];
    uint8_t system_code_list[32];
} PACKED felica_syscode_response_t;

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

typedef struct {
    felica_frame_response_t frame_response;
    uint8_t payload[4];
} PACKED felica_search_service_code_response_t;

typedef struct {
    uint8_t command_code[1];
    uint8_t IDm[8];
    uint8_t number_of_service[1];
    uint8_t service_code_list[2];
    uint8_t number_of_block[1];
} PACKED felica_write_request_haeder_t;

typedef struct {
    uint8_t command_code[1];
    uint8_t IDm[8];
    uint8_t number_of_service[1];
    uint8_t service_code_list[2];
    uint8_t number_of_block[1];
} PACKED felica_read_request_haeder_t;


typedef struct {
    uint8_t random_challenge[16];
    uint8_t session_key[16];
} PACKED felica_auth_context_t;

#endif // _ISO18_H_
