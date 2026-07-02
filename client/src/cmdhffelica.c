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
// High frequency ISO 18002 / FeliCa commands
//-----------------------------------------------------------------------------
#include "cmdhffelica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"   // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "util.h"
#include "fileutils.h"
#include "commonutil.h" // ARRAYLEN
#include "ui.h"
#include "iso18.h"       // felica_card_select_t struct
#include "protocols.h"
#include "des.h"
#include "platform_util.h"
#include "cliparser.h"   // cliparser
#include "util_posix.h"  // msleep, msclock
#include "jansson.h"


#define FELICA_BLK_SIZE 16
#define FELICA_BLK_HALF (FELICA_BLK_SIZE/2)

#define FELICA_BLK_NUMBER_RC    0x80
#define FELICA_BLK_NUMBER_ID    0x82
#define FELICA_BLK_NUMBER_WCNT  0x90
#define FELICA_BLK_NUMBER_MACA  0x91
#define FELICA_BLK_NUMBER_STATE 0x92

#define FELICA_DEFAULT_TIMEOUT_MS 2000U
#define FELICA_DEFAULT_RETRY_COUNT 3U
#define FELICA_DISCOVER_DEFAULT_RETRY_COUNT 5U
#define FELICA_DISCOVERY_RETRY_BACKOFF_MS 1000U
#define FELICA_TARGET_PRESENCE_ATTEMPTS 3U
#define FELICA_PLATFORM_INFO_MAX_LEN 64U
#define FELICA_PLATFORM_INFO_WITH_MAC_INFO_LEN 25U
#define FELICA_PLATFORM_INFO_WITH_MAC_LEN 20U
#define FELICA_PLATFORM_INFO_WITH_MAC_TOTAL_LEN (FELICA_PLATFORM_INFO_WITH_MAC_INFO_LEN + FELICA_PLATFORM_INFO_WITH_MAC_LEN)
#define FELICA_CONTAINER_ISSUE_INFO_LEN 16U
#define FELICA_CONTAINER_PROPERTY_MAX_LEN 64U
#define FELICA_SPECIFICATION_VERSION_MAX_LEN (4U + (FELICA_SPECIFICATION_VERSION_MAX_OPTIONS * 2U))
#define FELICA_OPTIONAL_CMD_TIMEOUT_MS 250U
#define FELICA_OPTIONAL_CMD_RETRIES 3U
// Per FeliCa spec, Polling max response at 16 timeslots is ~25ms; keep extra margin.
#define FELICA_POLL_TIMEOUT_MS 100U
#define FELICA_SEAC_POLL_TIMEOUT_MS 200U
#define FELICA_SEAC_POLL_RETRY_COUNT 5U
#define FELICA_SEAC_POLL_FRAME_LEN 5U
#define FELICA_REQUEST_SYSTEM_CODE_ATTEMPTS 5U
#define FELICA_SYSTEM_CODE_MAX_COUNT 16U
#define FELICA_DISCOVERED_SYSTEM_MAX_COUNT FELICA_SYSTEM_CODE_MAX_COUNT
#define FELICA_SYSTEM_CODE_WILDCARD 0xFFFFU
#define FELICA_SYSTEM_CODE_NFC_TYPE3 0x12FCU
#define FELICA_SYSTEM_CODE_FELICA_LITE 0x88B4U
#define FELICA_SYSTEM_CODE_FELICA_SECURE_ID 0x957AU
#define FELICA_SYSTEM_CODE_FELICA_NETWORKS_COMMON_AREA 0xFE00U
#define FELICA_DUMP_DEFAULT_NODE_CAPACITY 128U
#define FELICA_DUMP_COMMON_AREA_NODE_CAPACITY 256U
#define FELICA_POLL_REQUEST_NO_DATA 0x00U
#define FELICA_POLL_REQUEST_SYSTEM_CODE 0x01U
#define FELICA_SYSTEM_LIST_JSON "felica/felica_system_code_list"
#define FELICA_IC_CODE_LIST_JSON "felica/felica_ic_code_list"

#define FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE 32U
#define FELICA_MAX_NODE_NUMBER 0x03FFU
#define FELICA_LITE_NODE_DISCOVERY_MAX_NODE_NUMBER 16U
#define FELICA_PRESENCE_SERVICE_CODE_LE ((uint16_t)FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITHOUT_KEY)
#define FELICA_LITE_PRIMARY_SERVICE_CODE_LE 0x000BU
#define FELICA_LITE_NDEF_SERVICE_CODE_LE 0x0009U
#define FELICA_SYSTEM_SERVICE_MAX_COUNT 32U
#define FELICA_SYSTEM_SERVICE_NODE_MAX_COUNT 64U
#define FELICA_SYSTEM_SERVICE_NODE_MATCHER_MAX_COUNT 8U
#define FELICA_SYSTEM_SERVICE_BLOCK_LIST_ELEMENT_MAX_LEN 3U
#define FELICA_SERVICE_BLOCK_DATA_CACHE_MAX_COUNT 16U

static const uint16_t FELICA_LITE_DUMP_EXTRA_BLOCKS[] = {
    0x000EU, // REG
    0x0080U, // RC
    0x0081U, // MAC
    0x0082U, // ID
    0x0083U, // D_ID
    0x0084U, // SER_C
    0x0085U, // SYS_C
    0x0086U, // CKV
    0x0087U, // CK
    0x0088U, // MC
    0x0090U, // WCNT
    0x0091U, // MAC_A
    0x0092U, // STATE
    0x0093U, // EXKV
    0x0094U, // EXK
    0x00A0U, // CRC_CHECK
};

static bool felica_is_lite_assumed_node(uint16_t node_code_le) {
    return (node_code_le == FELICA_LITE_PRIMARY_SERVICE_CODE_LE ||
            node_code_le == FELICA_LITE_NDEF_SERVICE_CODE_LE);
}

static bool felica_is_lite_ic_type(uint8_t ic_type) {
    return (ic_type == 0xF0 || ic_type == 0xF1);
}

static bool felica_pmm_is_lite(const uint8_t *pmm) {
    return (pmm != NULL && pmm[0] == 0x00 && felica_is_lite_ic_type(pmm[1]));
}

typedef struct {
    uint8_t identifier;
    const char *name;
    bool has_aes_key_versions;
    bool has_des_key_versions;
} felica_encryption_identifier_info_t;

static const felica_encryption_identifier_info_t FELICA_ENCRYPTION_IDENTIFIER_INFO[] = {
    {FELICA_ENCRYPTION_IDENTIFIER_AES128, "AES128", true, false},
    {FELICA_ENCRYPTION_IDENTIFIER_AES128_DES112, "AES128_DES112", true, true},
    {FELICA_ENCRYPTION_IDENTIFIER_AES128_DES56, "AES128_DES56", true, true},
    {FELICA_ENCRYPTION_IDENTIFIER_DES112, "DES112", false, true},
    {FELICA_ENCRYPTION_IDENTIFIER_DES56, "DES56", false, true},
};

static const felica_encryption_identifier_info_t *felica_encryption_identifier_get_info(uint8_t encryption_identifier) {
    for (size_t i = 0; i < ARRAYLEN(FELICA_ENCRYPTION_IDENTIFIER_INFO); i++) {
        if (FELICA_ENCRYPTION_IDENTIFIER_INFO[i].identifier == encryption_identifier) {
            return &FELICA_ENCRYPTION_IDENTIFIER_INFO[i];
        }
    }

    return NULL;
}

typedef struct {
    uint8_t attribute;
    bool is_area;
    bool with_key;
    bool with_pin;
} felica_request_service_probe_attribute_t;

static const felica_request_service_probe_attribute_t FELICA_REQUEST_SERVICE_PROBE_ATTRIBUTES[] = {
    {FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA, true, true, false},
    {FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA, true, true, false},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITHOUT_KEY, false, false, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITH_KEY, false, true, false},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITHOUT_KEY, false, false, false},
    {FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA_WITH_PIN, true, true, true},
    {FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA_WITH_PIN, true, true, true},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RW_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_RANDOM_RO_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RW_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_CYCLIC_RO_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RW_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_CASHBACK_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_DECREMENT_WITHOUT_KEY_WITH_PIN, false, false, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITH_KEY_WITH_PIN, false, true, true},
    {FELICA_SERVICE_ATTRIBUTE_PURSE_RO_WITHOUT_KEY_WITH_PIN, false, false, true},
};

typedef enum {
    FELICA_NODE_DISCOVERY_NONE = 0,
    FELICA_NODE_DISCOVERY_REQUEST_CODE_LIST,
    FELICA_NODE_DISCOVERY_SEARCH_SERVICE_CODE,
    FELICA_NODE_DISCOVERY_REQUEST_SERVICE,
    FELICA_NODE_DISCOVERY_READ_WITHOUT_ENCRYPTION,
} felica_node_discovery_method_t;

typedef enum {
    FELICA_NODE_TYPE_AREA = 0,
    FELICA_NODE_TYPE_SERVICE,
    FELICA_NODE_TYPE_SYSTEM,
} felica_node_type_t;

typedef struct {
    felica_node_type_t type;
    uint16_t node_code_le;
    bool has_end_code;
    uint16_t end_code_le;
} felica_discovered_node_t;

typedef struct {
    uint16_t block_number;
    uint8_t data[FELICA_BLK_SIZE];
} felica_dump_block_t;

typedef struct {
    bool has_value;
    uint16_t value_le;
} felica_dump_key_version_t;

typedef struct {
    bool has_value;
    uint8_t value;
} felica_dump_encryption_identifier_t;

typedef struct {
    felica_node_type_t type;
    uint16_t node_code_le;
    bool has_end_code;
    uint16_t end_code_le;
    felica_dump_key_version_t des_key_version;
    felica_dump_key_version_t aes_key_version;
    felica_dump_block_t *blocks;
    size_t block_count;
    size_t block_capacity;
} felica_dump_node_t;

typedef struct {
    uint16_t system_code;
    uint8_t idm[8];
    uint8_t pmm[8];
    felica_dump_encryption_identifier_t encryption_identifier;
    felica_dump_node_t *nodes;
    size_t node_count;
    size_t node_capacity;
} felica_dump_system_t;

typedef struct {
    bool has_specification_version;
    uint8_t specification_version[FELICA_SPECIFICATION_VERSION_MAX_LEN];
    size_t specification_version_len;
    bool has_product_information;
    uint8_t product_information[FELICA_PLATFORM_INFO_MAX_LEN];
    size_t product_information_len;
    bool has_container_issue_information;
    uint8_t container_issue_information[FELICA_CONTAINER_ISSUE_INFO_LEN];
} felica_dump_metadata_t;

static uint8_t felica_node_attribute(uint16_t node_code_le) {
    return node_code_le & FELICA_NODE_ATTRIBUTE_MASK;
}

static bool felica_is_area_start_attribute(uint8_t attribute) {
    switch (attribute) {
        case FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA:
        case FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA:
        case FELICA_AREA_ATTRIBUTE_CAN_CREATE_SUBAREA_WITH_PIN:
        case FELICA_AREA_ATTRIBUTE_CANNOT_CREATE_SUBAREA_WITH_PIN:
            return true;
        default:
            return false;
    }
}

static felica_node_type_t felica_node_type_from_code(uint16_t node_code_le) {
    if (node_code_le == FELICA_SYSTEM_NODE) {
        return FELICA_NODE_TYPE_SYSTEM;
    }
    if (felica_is_area_start_attribute(felica_node_attribute(node_code_le))) {
        return FELICA_NODE_TYPE_AREA;
    }
    return FELICA_NODE_TYPE_SERVICE;
}

typedef struct {
    uint8_t encryption_identifier;
    bool has_aes_key_versions;
    bool has_des_key_versions;
    uint16_t aes_key_versions_le[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE];
    uint16_t des_key_versions_le[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE];
} felica_request_service_v2_key_versions_t;

typedef int (*felica_node_discovery_visitor_t)(const felica_discovered_node_t *node, void *ctx);
typedef bool (*felica_node_discovery_runner_t)(uint8_t *flags,
                                               const uint8_t *idm,
                                               uint32_t retry_count,
                                               felica_node_discovery_visitor_t visitor,
                                               void *ctx,
                                               uint32_t *discovered_count,
                                               int *stop_status);

typedef struct {
    felica_node_discovery_method_t method;
    const char *cli_name;
    const char *display_name;
    felica_node_discovery_runner_t run;
} felica_node_discovery_method_info_t;

typedef struct {
    uint32_t area_count;
    uint32_t service_count;
    uint16_t area_end_stack[8];
    int depth;
    bool header_printed;
} felica_scsvcode_context_t;

typedef struct {
    uint8_t *flags;
    felica_dump_system_t *system;
    uint8_t block_frame[PM3_CMD_DATA_SIZE];
    uint16_t block_datalen;
    uint32_t retry_count;
    uint32_t service_count;
    uint32_t public_service_count;
} felica_dump_context_t;

typedef struct {
    uint16_t system_code;
    uint8_t idm[8];
    bool has_idm;
    uint8_t pmm[8];
    bool has_pmm;
} felica_discovered_system_t;

typedef struct {
    size_t count;
    felica_discovered_system_t systems[FELICA_DISCOVERED_SYSTEM_MAX_COUNT];
} felica_discovered_system_list_t;

typedef struct {
    uint16_t system_code;
    const char *label;
} felica_system_probe_target_t;

static const felica_system_probe_target_t FELICA_MANUAL_SYSTEM_PROBE_TARGETS[] = {
    {FELICA_SYSTEM_CODE_NFC_TYPE3, "NDEF"},
    {FELICA_SYSTEM_CODE_FELICA_LITE, "FeliCa Lite"},
    {FELICA_SYSTEM_CODE_FELICA_SECURE_ID, "FeliCa Secure ID"},
};

typedef struct {
    const char *name;
    const char *type;
    size_t required_node_count;
    size_t present_node_count;
} felica_system_service_t;

typedef struct {
    uint8_t block_list_element[FELICA_SYSTEM_SERVICE_BLOCK_LIST_ELEMENT_MAX_LEN];
    uint8_t block_list_element_len;
    const char *data_regex;
} felica_system_service_node_matcher_t;

typedef struct {
    uint16_t node_code_le;
    size_t service_index;
    size_t matcher_count;
    felica_system_service_node_matcher_t matchers[FELICA_SYSTEM_SERVICE_NODE_MATCHER_MAX_COUNT];
} felica_system_service_node_t;

typedef struct {
    bool valid;
    uint8_t idm[8];
    uint16_t service_code_le;
    uint16_t block_number;
    uint8_t block_data[FELICA_BLK_SIZE];
} felica_service_block_data_cache_entry_t;

typedef struct {
    size_t count;
    felica_service_block_data_cache_entry_t entries[FELICA_SERVICE_BLOCK_DATA_CACHE_MAX_COUNT];
} felica_service_block_data_cache_t;

typedef enum {
    FELICA_IDM_RESOLVE_STANDALONE = 0,
    FELICA_IDM_RESOLVE_CHAINED,
} felica_idm_resolution_mode_t;



static int CmdHelp(const char *Cmd);
static void clear_and_send_command(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose);
static int send_felica_payload_with_retries(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                            int expected_response_cmd, uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms, bool logging,
                                            PacketResponseNG *resp, const char *request_name);
static int send_read_without_encryption_ex(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                           felica_read_without_encryption_response_t *rd_noCry_resp,
                                           uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms, bool logging);
static bool felica_discover_nodes_with_request_code_list(uint8_t *flags,
                                                         const uint8_t *idm,
                                                         uint32_t retry_count,
                                                         felica_node_discovery_visitor_t visitor,
                                                         void *ctx,
                                                         uint32_t *discovered_count,
                                                         int *stop_status);
static bool felica_discover_nodes_with_search_service_code(uint8_t *flags,
                                                           const uint8_t *idm,
                                                           uint32_t retry_count,
                                                           felica_node_discovery_visitor_t visitor,
                                                           void *ctx,
                                                           uint32_t *discovered_count,
                                                           int *stop_status);
static bool felica_discover_nodes_with_request_service(uint8_t *flags,
                                                       const uint8_t *idm,
                                                       uint32_t retry_count,
                                                       felica_node_discovery_visitor_t visitor,
                                                       void *ctx,
                                                       uint32_t *discovered_count,
                                                       int *stop_status);
static bool felica_discover_nodes_with_read_without_encryption(uint8_t *flags,
        const uint8_t *idm,
        uint32_t retry_count,
        felica_node_discovery_visitor_t visitor,
        void *ctx,
        uint32_t *discovered_count,
        int *stop_status);
static bool felica_discover_nodes_with_read_without_encryption_ex(uint8_t *flags,
        const uint8_t *idm,
        uint32_t retry_count,
        const uint8_t *pmm,
        felica_node_discovery_visitor_t visitor,
        void *ctx,
        uint32_t *discovered_count,
        int *stop_status);
static int send_polling(uint8_t flags, uint16_t system_code, uint8_t request_code,
                        uint32_t timeout_ms, uint32_t retries, bool logging,
                        uint8_t *idm_out, uint8_t *pmm_out, uint16_t *returned_system_code);
static const felica_node_discovery_method_info_t *felica_get_node_discovery_method_info(felica_node_discovery_method_t method);
static const char *felica_node_discovery_method_display_name(felica_node_discovery_method_t method);
static void felica_print_node_discovery_method_used(felica_node_discovery_method_t method);
static int felica_compare_discovered_nodes(const void *lhs, const void *rhs);
static const char *felica_get_json_string(const json_t *obj, const char *key);
static const char *felica_ic_code_name(uint8_t rom_type, uint8_t ic_type);
static felica_card_select_t last_known_card;
static json_t *felica_system_list = NULL;
static bool felica_system_list_loaded = false;
static json_t *felica_ic_code_list = NULL;
static bool felica_ic_code_list_loaded = false;

static void set_last_known_card(felica_card_select_t card) {
    last_known_card = card;
}

static void felica_set_last_known_idm(const uint8_t *idm) {
    if (idm == NULL) {
        return;
    }

    if (memcmp(last_known_card.IDm, idm, sizeof(last_known_card.IDm)) == 0) {
        return;
    }

    memset(&last_known_card, 0, sizeof(last_known_card));
    memcpy(last_known_card.IDm, idm, sizeof(last_known_card.IDm));
}

static void print_status_flag1_interpretation(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _CYAN_("Status Flag 1"));
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(INFO, " 00 | Indicates the successful completion of a command.");
    PrintAndLogEx(INFO, " FF | If an error occurs during the processing of a command that includes no list in the command packet, \n"
                        "    | or if an error occurs independently of any list, the card returns a response by setting FFh to Status Flag1.");
    PrintAndLogEx(INFO, " XX | If an error occurs while processing a command that includes Service Code List or Block List \n"
                        "    | in the command packet, the card returns a response by setting a number in the list to Status Flag1,\n"
                        "    | indicating the location of the error.");
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
}

static void print_status_flag2_interpration(void) {
    PrintAndLogEx(INFO, _CYAN_("Status Flag 2"));
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(INFO, " 00 | Indicates the successful completion of a command.");
    PrintAndLogEx(INFO, " 01 | The calculated result is either less than zero when the purse data is decremented, or exceeds 4\n"
                        "    | Bytes when the purse data is incremented.");
    PrintAndLogEx(INFO, " 02 | The specified data exceeds the value of cashback data at cashback of purse.");
    PrintAndLogEx(INFO, " 70 | Memory error (fatal error).");
    PrintAndLogEx(INFO, " 71 | The number of memory rewrites exceeds the upper limit (this is only a warning; data writing is performed as normal).\n"
                        "    | The maximum number of rewrites can differ, depending on the product being used.\n"
                        "    | In addition, Status Flag1 is either 00h or FFh depending on the product being used.");

    PrintAndLogEx(INFO, " A1 | Illegal Number of Service| Number of Service or Number of Node specified by the command \n"
                        "    | falls outside the range of the prescribed value.");
    PrintAndLogEx(INFO, " A2 | Illegal command packet (specified Number of Block) : Number of Block specified by the \n"
                        "    | command falls outside the range of the prescribed values for the product.");
    PrintAndLogEx(INFO, " A3 | Illegal Block List (specified order of Service) : Service Code List Order specified by \n"
                        "    | Block List Element falls outside the Number of Service specified by the command \n"
                        "    | (or the Number of Service specified at the times of mutual authentication).");
    PrintAndLogEx(INFO, " A4 | Illegal Service type : Area Attribute specified by the command or Service Attribute of Service Code is incorrect.");
    PrintAndLogEx(INFO, " A5 | Access is not allowed : Area or Service specified by the command cannot be accessed.\n"
                        "    | The parameter specified by the command does not satisfy the conditions for success.");
    PrintAndLogEx(INFO, " A6 | Illegal Service Code List : Target to be accessed, identified by Service Code List Order, specified by Block\n"
                        "    | List Element does not exist. Or, Node specified by Node Code List does not exist.");
    PrintAndLogEx(INFO, " A7 | Illegal Block List (Access Mode) : Access Mode specified by Block List Element is incorrect.");
    PrintAndLogEx(INFO, " A8 | Illegal Block Number Block Number (access to the specified data is inhibited) :\n"
                        "    | specified by Block List Element exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(INFO, " A9 | Data write failure : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AA | Key-change failure : Key change failed.");
    PrintAndLogEx(INFO, " AB | Illegal Package Parity or illegal Package MAC : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AC | Illegal parameter : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AD | Service exists already : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AE | Illegal System Code : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " AF | Too many simultaneous cyclic write operations : Number of simultaneous write Blocks\n"
                        "    | specified by the command to Cyclic Service exceeds the number of Blocks assigned to Service.");
    PrintAndLogEx(INFO, " C0 | Illegal Package Identifier : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " C1 | Discrepancy of parameters inside and outside Package : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, " C2 | Command is disabled already : This is the error that occurs in issuance commands.");
    PrintAndLogEx(INFO, "----+--------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
}

static void print_block_list_element_constraints(void) {
    PrintAndLogEx(INFO, "    - Each Block List Element shall satisfy the following conditions:");
    PrintAndLogEx(INFO, "        - The value of Service Code List Order shall not exceed Number of Service.");
    PrintAndLogEx(INFO, "        - Access Mode shall be 000b.");
    PrintAndLogEx(INFO, "        - The target specified by Service Code shall not be Area or System.");
    PrintAndLogEx(INFO, "        - Service specified in Service Code List shall exist in System.");
    PrintAndLogEx(INFO, "        - Service Attribute of Service specified in Service Code List shall be authentication-not-required Service.");
    PrintAndLogEx(INFO, "        - Block Number shall be in the range of the number of Blocks assigned to the specified Service.");
}

static void print_number_of_service_constraints(void) {
    PrintAndLogEx(INFO, "    - Number of Service: shall be a positive integer in the range of 1 to 16, inclusive.");
}

static void print_number_of_block_constraints(void) {
    PrintAndLogEx(INFO, "    - Number of Block: shall be less than or equal to the maximum number of Blocks that can be read simultaneously.\n"
                        "            The maximum number of Blocks that can be read simultaneously can differ, depending on the product being used.\n"
                        "            Use as default 01");
}

static void print_service_code_list_constraints(void) {
    PrintAndLogEx(INFO, "    - Service Code List: For Service Code List, only Service Code existing in the product shall be specified:");
    PrintAndLogEx(INFO, "        - Even when Service Code exists in the product, Service Code not referenced from Block List shall not \n"
                        "          be specified to Service Code List.");
    PrintAndLogEx(INFO, "        - For existence or nonexistence of Service in a product, please check using the Request Service \n"
                        "          (or Request Service v2) command.");
}

/*
static int usage_hf_felica_sim(void) {
    PrintAndLogEx(INFO, "\n Emulating ISO/18092 FeliCa tag \n");
    PrintAndLogEx(INFO, "Usage: hf felica sim -t <type> [-v]");
    PrintAndLogEx(INFO, "Options:");
    PrintAndLogEx(INFO, "    t     : 1 = FeliCa");
    PrintAndLogEx(INFO, "          : 2 = FeliCaLiteS");
    PrintAndLogEx(INFO, "    v     : (Optional) Verbose");
    PrintAndLogEx(INFO, "Examples:");
    PrintAndLogEx(INFO, "          hf felica sim -t 1");
    return PM3_SUCCESS;
}
*/

static int print_authentication1(void) {
    PrintAndLogEx(INFO, "Initiate mutual authentication. This command must always be executed before Auth2 command");
    PrintAndLogEx(INFO, "and mutual authentication is achieve only after Auth2 command has succeeded.");
    PrintAndLogEx(INFO, "  - Auth1 Parameters:");
    PrintAndLogEx(INFO, "    - Number of Areas n: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(INFO, "    - Area Code List: 2n byte");
    PrintAndLogEx(INFO, "    - Number of Services m: 1-byte (1 <= n <= 8)");
    PrintAndLogEx(INFO, "    - Service Code List: 2n byte");
    PrintAndLogEx(INFO, "    - 3DES-Key: 128-bit master secret used for the encryption");
    PrintAndLogEx(INFO, "    - M1c: Encrypted random number - challenge for tag authentication (8-byte)");
    PrintAndLogEx(INFO, "  - Response:");
    PrintAndLogEx(INFO, "    - Response Code: 11h 1-byte");
    PrintAndLogEx(INFO, "    - Manufacture ID(IDm): 8-byte");
    PrintAndLogEx(INFO, "    - M2c: 8-byte");
    PrintAndLogEx(INFO, "    - M3c: 8-byte");
    PrintAndLogEx(INFO, "  - Success: Card Mode switches to Mode1. You can check this with the request response command.");
    PrintAndLogEx(INFO, "  - Unsuccessful: Card should not respond at all.");
    return PM3_SUCCESS;
}

static int print_authentication2(void) {
    PrintAndLogEx(INFO, "Complete mutual authentication.");
    PrintAndLogEx(INFO, "This command can only be executed subsquent to Auth1 command.");
    PrintAndLogEx(INFO, "  - Auth2 Parameters:");
    PrintAndLogEx(INFO, "    - Manufacturer IDm: (8-byte)");
    PrintAndLogEx(INFO, "    - M3c: card challenge (8-byte)");
    PrintAndLogEx(INFO, "    - 3DES Key: key used for decryption of M3c (16-byte)");
    PrintAndLogEx(INFO, "  - Response (encrypted):");
    PrintAndLogEx(INFO, "    - Response Code: 13h (1-byte)");
    PrintAndLogEx(INFO, "    - IDtc:  (8-byte)");
    PrintAndLogEx(INFO, "    - IDi (encrypted):  (8-byte)");
    PrintAndLogEx(INFO, "    - PMi (encrypted):  (8-byte)");
    PrintAndLogEx(INFO, "  - Success: Card switches to mode2 and sends response frame.");
    PrintAndLogEx(INFO, "  - Unsuccessful: Card should not respond at all.");
    return PM3_SUCCESS;
}

static const char *felica_specification_option_name(size_t option_index) {
    switch (option_index) {
        case 0:
            return "DES.....................";
        case 1:
            return "Special.................";
        case 2:
            return "Extended Overlap........";
        case 3:
            return "Value-Limited Purse.....";
        case 4:
            return "Communication with MAC..";
        default:
            return "Unknown.................";
    }
}

static void print_specification_versions(int level,
                                         const felica_request_specification_version_info_t *specification_version_info,
                                         bool include_hex) {
    if (specification_version_info == NULL || specification_version_info->has_specification_version == false) {
        return;
    }

    uint8_t basic_major = specification_version_info->basic_version[1] & 0x0F;
    uint8_t basic_minor = (specification_version_info->basic_version[0] >> 4) & 0x0F;
    uint8_t basic_patch = specification_version_info->basic_version[0] & 0x0F;
    PrintAndLogEx(level, "Versions:");

    PrintAndLogEx(level, "  Format version.......... " _GREEN_("%02X"), specification_version_info->format_version);

    PrintAndLogEx(level, "  Option count............ " _GREEN_("%u"), specification_version_info->number_of_option);

    if (include_hex) {
        PrintAndLogEx(level, "  Specification........... " _GREEN_("%u.%u.%u") " (" _YELLOW_("0x%02X%02X") ")",
                      basic_major, basic_minor, basic_patch,
                      specification_version_info->basic_version[0],
                      specification_version_info->basic_version[1]);
    } else {
        PrintAndLogEx(level, "  Specification........... " _GREEN_("%u.%u.%u"), basic_major, basic_minor, basic_patch);
    }

    for (size_t i = 0; i < specification_version_info->option_version_count; i++) {
        const uint8_t *option = specification_version_info->option_version_list + (i * 2);
        uint8_t option_major = option[1] & 0x0F;
        uint8_t option_minor = (option[0] >> 4) & 0x0F;
        uint8_t option_patch = option[0] & 0x0F;
        const char *option_name = felica_specification_option_name(i);

        if (include_hex) {
            PrintAndLogEx(level, "  %s " _GREEN_("%u.%u.%u") " (" _YELLOW_("0x%02X%02X") ")",
                          option_name, option_major, option_minor, option_patch,
                          option[0], option[1]);
        } else {
            PrintAndLogEx(level, "  %s " _GREEN_("%u.%u.%u"),
                          option_name, option_major, option_minor, option_patch);
        }
    }
}

static void print_platform_information(const uint8_t *platform_information_data,
                                       size_t platform_information_data_len) {
    if (platform_information_data == NULL || platform_information_data_len == 0) {
        return;
    }

    if (platform_information_data_len == FELICA_PLATFORM_INFO_WITH_MAC_TOTAL_LEN) {
        PrintAndLogEx(INFO, "Platform info:");
        PrintAndLogEx(INFO, "  Info.......... " _GREEN_("%s"),
                      sprint_hex_inrow(platform_information_data, FELICA_PLATFORM_INFO_WITH_MAC_INFO_LEN));
        PrintAndLogEx(INFO, "  MAC........... " _GREEN_("%s"),
                      sprint_hex_inrow(platform_information_data + FELICA_PLATFORM_INFO_WITH_MAC_INFO_LEN,
                                       FELICA_PLATFORM_INFO_WITH_MAC_LEN));
        return;
    }

    PrintAndLogEx(INFO, "Platform info.. " _YELLOW_("%s"),
                  sprint_hex_inrow(platform_information_data, platform_information_data_len));
}

static json_t *felica_get_system_list(void) {
    if (felica_system_list_loaded) {
        return felica_system_list;
    }

    felica_system_list_loaded = true;

    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, FELICA_SYSTEM_LIST_JSON, ".json", true) != PM3_SUCCESS) {
        return NULL;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (root == NULL) {
        PrintAndLogEx(WARNING, "Failed to parse `%s` line %d: %s", path, error.line, error.text);
        free(path);
        return NULL;
    }

    if (json_is_array(root) == false) {
        PrintAndLogEx(WARNING, "Invalid `%s` format, expected array root", path);
        json_decref(root);
        free(path);
        return NULL;
    }

    felica_system_list = root;
    free(path);
    return felica_system_list;
}

static const char *felica_get_json_string(const json_t *obj, const char *key) {
    if (obj == NULL || key == NULL) {
        return NULL;
    }

    json_t *value = json_object_get(obj, key);
    if (json_is_string(value) == false) {
        return NULL;
    }

    const char *str = json_string_value(value);
    if (str == NULL || str[0] == '\0') {
        return NULL;
    }

    return str;
}

static json_t *felica_get_ic_code_list(void) {
    if (felica_ic_code_list_loaded) {
        return felica_ic_code_list;
    }

    felica_ic_code_list_loaded = true;

    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, FELICA_IC_CODE_LIST_JSON, ".json", true) != PM3_SUCCESS) {
        return NULL;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (root == NULL) {
        PrintAndLogEx(WARNING, "Failed to parse `%s` line %d: %s", path, error.line, error.text);
        free(path);
        return NULL;
    }

    if (json_is_array(root) == false) {
        PrintAndLogEx(WARNING, "Invalid `%s` format, expected array root", path);
        json_decref(root);
        free(path);
        return NULL;
    }

    felica_ic_code_list = root;
    free(path);
    return felica_ic_code_list;
}

static const json_t *felica_find_ic_annotation(uint8_t rom_type, uint8_t ic_type) {
    json_t *ic_code_list = felica_get_ic_code_list();
    if (ic_code_list == NULL) {
        return NULL;
    }

    char rom_hex[3] = {0};
    char ic_hex[3] = {0};
    snprintf(rom_hex, sizeof(rom_hex), "%02X", rom_type);
    snprintf(ic_hex, sizeof(ic_hex), "%02X", ic_type);

    size_t index = 0;
    json_t *entry = NULL;
    const json_t *ic_fallback = NULL;
    json_array_foreach(ic_code_list, index, entry) {
        if (json_is_object(entry) == false) {
            continue;
        }

        const char *entry_ic = felica_get_json_string(entry, "ic");
        if (entry_ic == NULL || strcmp(entry_ic, ic_hex) != 0) {
            continue;
        }

        if (ic_fallback == NULL) {
            ic_fallback = entry;
        }

        const char *entry_rom = felica_get_json_string(entry, "rom");
        if (entry_rom != NULL && strcmp(entry_rom, rom_hex) == 0) {
            return entry;
        }
    }

    return ic_fallback;
}

static const char *felica_ic_code_name(uint8_t rom_type, uint8_t ic_type) {
    if (ic_type == 0xFF && rom_type != 0xFF) {
        return "Unknown IC Type";
    }

    const json_t *entry = felica_find_ic_annotation(rom_type, ic_type);
    const char *name = felica_get_json_string(entry, "name");
    return name ? name : "Unknown IC Type";
}

static const char *felica_idm_prefix_name(const uint8_t *idm, char *buf, size_t buf_len) {
    if (idm == NULL) {
        return NULL;
    }

    const uint16_t prefix = ((uint16_t)idm[0] << 8) | idm[1];
    switch (prefix) {
        case 0x01FE:
            return "NFCIP-1 / peer-to-peer";
        case 0x02FE:
            return "Open ID assignment";
        case 0x03FE:
            return "FeliCa Plug ID with DFC";
        case 0x05FE:
            return "Unregistered mobile device random ID";
        default:
            break;
    }

    if (idm[1] == 0xFE && (idm[0] & 0x0F) == 0x04) {
        if (buf == NULL || buf_len == 0) {
            return "Sony FeliCa Standard random ID";
        }
        snprintf(buf, buf_len, "Sony FeliCa Standard random ID (system %u)", idm[0] >> 4);
        return buf;
    }

    return NULL;
}

static const json_t *felica_find_system_annotation(uint16_t system_code) {
    json_t *system_list = felica_get_system_list();
    if (system_list == NULL) {
        return NULL;
    }

    char code_hex[5] = {0};
    snprintf(code_hex, sizeof(code_hex), "%04X", system_code);

    size_t index = 0;
    json_t *entry = NULL;
    json_array_foreach(system_list, index, entry) {
        if (json_is_object(entry) == false) {
            continue;
        }

        const char *entry_code = felica_get_json_string(entry, "code");
        if (entry_code && strcmp(entry_code, code_hex) == 0) {
            return entry;
        }
    }

    return NULL;
}

static void felica_print_system_code_annotation(int level, const uint8_t *system_code_bytes) {
    if (system_code_bytes == NULL) {
        return;
    }

    uint16_t system_code = ((uint16_t)system_code_bytes[0] << 8) | system_code_bytes[1];
    char code_hex[5] = {0};
    snprintf(code_hex, sizeof(code_hex), "%04X", system_code);

    const json_t *entry = felica_find_system_annotation(system_code);
    if (entry == NULL) {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. UNKNOWN (" _RED_("Report to Iceman!") ")", code_hex);
        return;
    }

    const char *name = felica_get_json_string(entry, "name");
    const char *region = felica_get_json_string(entry, "region");
    const char *card_type = felica_get_json_string(entry, "type");

    if (name == NULL) {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. UNKNOWN (" _RED_("Report to Iceman!") ")", code_hex);
        return;
    }

    if (region && card_type) {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. %s (" _YELLOW_("%s, %s") ")", code_hex, name, region, card_type);
    } else if (region) {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. %s (" _YELLOW_("%s") ")", code_hex, name, region);
    } else if (card_type) {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. %s (" _YELLOW_("%s") ")", code_hex, name, card_type);
    } else {
        PrintAndLogEx(level, "  " _YELLOW_("%s") "............. %s", code_hex, name);
    }
}

static bool felica_parse_service_node_code(const char *code_hex, uint16_t *node_code_le_out) {
    if (code_hex == NULL || node_code_le_out == NULL) {
        return false;
    }

    const size_t len = strlen(code_hex);
    if (len != 4U && len != 8U) {
        return false;
    }

    uint8_t code_bytes[4] = {0};
    size_t code_bytes_len = 0;
    if (hexstr_to_byte_array(code_hex, code_bytes, &code_bytes_len) == false) {
        return false;
    }

    if (code_bytes_len != 2U && code_bytes_len != 4U) {
        return false;
    }

    /*
     * JSON stores node codes in network order.
     * Request Service packet builder expects a LE scalar and then writes it LE on wire,
     * so keep original wire byte order by storing swapped scalar here.
     */
    *node_code_le_out = (uint16_t)((uint16_t)code_bytes[1] << 8) | code_bytes[0];
    return true;
}

static bool felica_parse_block_list_element(const char *ble_hex, uint8_t *ble_out, uint8_t *ble_len_out) {
    if (ble_hex == NULL || ble_out == NULL || ble_len_out == NULL) {
        return false;
    }

    const bool explicit_raw_ble = str_startswith(ble_hex, "ble:") || str_startswith(ble_hex, "BLE:");
    const char *value_hex = explicit_raw_ble ? (ble_hex + 4) : ble_hex;
    const size_t len = strlen(value_hex);

    if (explicit_raw_ble) {
        if (len != 4U && len != 6U) {
            return false;
        }

        uint8_t ble_bytes[FELICA_SYSTEM_SERVICE_BLOCK_LIST_ELEMENT_MAX_LEN] = {0};
        size_t ble_bytes_len = 0;
        if (hexstr_to_byte_array(value_hex, ble_bytes, &ble_bytes_len) == false) {
            return false;
        }

        if (ble_bytes_len != 2U && ble_bytes_len != 3U) {
            return false;
        }

        if (ble_bytes_len == 2U) {
            // For 2-byte BLE form, bit7 must be set.
            ble_bytes[0] |= 0x80U;
        }

        memcpy(ble_out, ble_bytes, ble_bytes_len);
        *ble_len_out = (uint8_t)ble_bytes_len;
        return true;
    }

    // Default matcher key mode: block index in hex (for example "82" or "0082").
    if (len != 2U && len != 4U) {
        return false;
    }

    uint8_t index_bytes[2] = {0};
    size_t index_bytes_len = 0;
    if (hexstr_to_byte_array(value_hex, index_bytes, &index_bytes_len) == false) {
        return false;
    }

    if (index_bytes_len != 1U && index_bytes_len != 2U) {
        return false;
    }

    uint16_t block_index = 0;
    for (size_t i = 0; i < index_bytes_len; i++) {
        block_index = (uint16_t)((block_index << 8) | index_bytes[i]);
    }

    if (block_index > 0xFFU) {
        return false;
    }

    // Short (2-byte) block-list element: access mode/order defaults + 8-bit block index.
    ble_out[0] = 0x80;
    ble_out[1] = (uint8_t)block_index;
    *ble_len_out = 2U;
    return true;
}

static size_t felica_parse_service_node_matchers(const json_t *node_json,
                                                 felica_system_service_node_matcher_t *matchers,
                                                 size_t matcher_capacity) {
    if (node_json == NULL || matchers == NULL || matcher_capacity == 0) {
        return 0;
    }

    json_t *data_json = json_object_get(node_json, "data");
    if (json_is_object(data_json) == false) {
        return 0;
    }

    size_t matcher_count = 0;
    const char *ble_hex = NULL;
    json_t *regex_json = NULL;
    json_object_foreach(data_json, ble_hex, regex_json) {
        if (matcher_count >= matcher_capacity) {
            break;
        }

        if (json_is_string(regex_json) == false) {
            continue;
        }

        const char *data_regex = json_string_value(regex_json);
        if (data_regex == NULL || data_regex[0] == '\0') {
            continue;
        }

        felica_system_service_node_matcher_t *matcher = &matchers[matcher_count];
        memset(matcher, 0, sizeof(*matcher));
        if (felica_parse_block_list_element(ble_hex, matcher->block_list_element, &matcher->block_list_element_len) == false) {
            continue;
        }

        matcher->data_regex = data_regex;
        matcher_count++;
    }

    return matcher_count;
}

static int felica_read_service_block_for_node(uint8_t flags, const uint8_t *idm,
                                              uint16_t node_code_le,
                                              const uint8_t *block_list_element, uint8_t block_list_element_len,
                                              uint8_t *block_data_out, size_t block_data_out_capacity, size_t *block_data_len_out) {
    if (idm == NULL || block_list_element == NULL || block_data_out == NULL || block_data_len_out == NULL) {
        return PM3_EINVARG;
    }

    *block_data_len_out = 0;

    if (block_list_element_len != 2U && block_list_element_len != 3U) {
        return PM3_EINVARG;
    }

    const uint16_t datalen = (uint16_t)(1 + 1 + 8 + 1 + 2 + 1 + block_list_element_len);
    uint8_t data[1 + 1 + 8 + 1 + 2 + 1 + FELICA_SYSTEM_SERVICE_BLOCK_LIST_ELEMENT_MAX_LEN] = {0};
    data[0] = (uint8_t)datalen;
    data[1] = FELICA_RDBLK_REQ;
    memcpy(data + 2, idm, 8);
    data[10] = 0x01;
    data[11] = node_code_le & 0xFF;
    data[12] = (node_code_le >> 8) & 0xFF;
    data[13] = 0x01;
    memcpy(data + 14, block_list_element, block_list_element_len);

    felica_read_without_encryption_response_t rd_resp;
    if (send_read_without_encryption_ex(flags, datalen, data, false, &rd_resp,
                                        FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                        0, false) != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (rd_resp.status_flags.status_flag1[0] != 0x00 || rd_resp.status_flags.status_flag2[0] != 0x00) {
        return PM3_ESOFT;
    }

    if (rd_resp.number_of_block[0] == 0) {
        return PM3_ESOFT;
    }

    size_t copy_len = MIN((size_t)FELICA_BLK_SIZE, block_data_out_capacity);
    memcpy(block_data_out, rd_resp.block_data, copy_len);
    *block_data_len_out = copy_len;
    return PM3_SUCCESS;
}

static bool felica_block_number_from_block_list_element(const uint8_t *block_list_element,
                                                        uint8_t block_list_element_len, uint16_t *block_number) {
    if (block_list_element == NULL || block_number == NULL) {
        return false;
    }

    if (block_list_element_len == 2U) {
        *block_number = block_list_element[1];
        return true;
    }

    if (block_list_element_len == 3U) {
        *block_number = block_list_element[1] | ((uint16_t)block_list_element[2] << 8);
        return true;
    }

    return false;
}

static bool felica_service_block_data_cache_entry_matches(const felica_service_block_data_cache_entry_t *entry,
                                                          const uint8_t *idm, uint16_t service_code_le, uint16_t block_number) {
    return entry && entry->valid &&
           memcmp(entry->idm, idm, sizeof(entry->idm)) == 0 &&
           entry->service_code_le == service_code_le &&
           entry->block_number == block_number;
}

static int felica_read_service_block_for_node_cached(uint8_t flags, const uint8_t *idm,
                                                     uint16_t service_code_le,
                                                     const uint8_t *block_list_element, uint8_t block_list_element_len,
                                                     uint8_t *block_data_out, size_t block_data_out_capacity, size_t *block_data_len_out,
                                                     felica_service_block_data_cache_t *cache) {
    if (idm == NULL || block_list_element == NULL || block_data_out == NULL || block_data_len_out == NULL) {
        return PM3_EINVARG;
    }

    *block_data_len_out = 0;

    if (block_list_element_len != 2U && block_list_element_len != 3U) {
        return PM3_EINVARG;
    }

    uint16_t block_number = 0;
    if (felica_block_number_from_block_list_element(block_list_element,
                                                    block_list_element_len, &block_number) == false) {
        return PM3_EINVARG;
    }

    if (cache) {
        for (size_t i = 0; i < cache->count; i++) {
            const felica_service_block_data_cache_entry_t *entry = &cache->entries[i];
            if (felica_service_block_data_cache_entry_matches(entry, idm, service_code_le, block_number) == false) {
                continue;
            }

            const size_t copy_len = MIN((size_t)FELICA_BLK_SIZE, block_data_out_capacity);
            memcpy(block_data_out, entry->block_data, copy_len);
            *block_data_len_out = copy_len;
            return PM3_SUCCESS;
        }
    }

    uint8_t block_data[FELICA_BLK_SIZE] = {0};
    size_t block_data_len = 0;
    int status = felica_read_service_block_for_node(flags, idm, service_code_le,
                                                    block_list_element, block_list_element_len,
                                                    block_data, sizeof(block_data), &block_data_len);
    if (status != PM3_SUCCESS) {
        return status;
    }

    if (cache && cache->count < ARRAYLEN(cache->entries)) {
        felica_service_block_data_cache_entry_t *entry = &cache->entries[cache->count++];
        memset(entry, 0, sizeof(*entry));
        entry->valid = true;
        memcpy(entry->idm, idm, sizeof(entry->idm));
        entry->service_code_le = service_code_le;
        entry->block_number = block_number;
        memcpy(entry->block_data, block_data, sizeof(entry->block_data));
    }

    const size_t copy_len = MIN(block_data_len, block_data_out_capacity);
    memcpy(block_data_out, block_data, copy_len);
    *block_data_len_out = copy_len;
    return PM3_SUCCESS;
}

static bool felica_match_service_node_data(uint8_t flags, const uint8_t *idm, uint16_t node_code_le,
                                           const felica_system_service_node_matcher_t *matchers, size_t matcher_count,
                                           felica_service_block_data_cache_t *block_data_cache) {
    if (idm == NULL || matchers == NULL || matcher_count == 0) {
        return true;
    }

    for (size_t i = 0; i < matcher_count; i++) {
        if (matchers[i].data_regex == NULL || matchers[i].data_regex[0] == '\0') {
            return false;
        }

        uint8_t block_data[FELICA_BLK_SIZE] = {0};
        size_t block_data_len = 0;
        if (felica_read_service_block_for_node_cached(flags, idm, node_code_le,
                                                      matchers[i].block_list_element, matchers[i].block_list_element_len,
                                                      block_data, sizeof(block_data), &block_data_len,
                                                      block_data_cache) != PM3_SUCCESS) {
            return false;
        }

        char block_hex[(FELICA_BLK_SIZE * 2) + 1] = {0};
        hex_to_buffer((uint8_t *)block_hex, block_data, block_data_len, sizeof(block_hex) - 1, 0, 0, true);
        if (str_regex_match_case_insensitive(matchers[i].data_regex, block_hex) == false) {
            return false;
        }
    }

    return true;
}

static int felica_build_request_service_payload(uint8_t command, const uint8_t *idm,
                                                const uint16_t *node_codes_le, size_t node_count,
                                                uint8_t *data, size_t data_size, uint16_t *datalen_out) {
    if (idm == NULL || node_codes_le == NULL || data == NULL || datalen_out == NULL ||
            node_count == 0 || node_count > FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE) {
        return PM3_EINVARG;
    }

    const uint16_t datalen = (uint16_t)(1 + 1 + 8 + 1 + (node_count * 2U));
    if (data_size < datalen) {
        return PM3_EINVARG;
    }

    memset(data, 0, datalen);
    data[0] = (uint8_t)datalen;
    data[1] = command;
    memcpy(data + 2, idm, 8);
    data[10] = (uint8_t)node_count;
    for (size_t i = 0; i < node_count; i++) {
        data[11 + i * 2] = node_codes_le[i] & 0xFF;
        data[12 + i * 2] = (node_codes_le[i] >> 8) & 0xFF;
    }

    *datalen_out = datalen;
    return PM3_SUCCESS;
}

static int felica_request_service_key_versions(uint8_t flags, const uint8_t *idm,
                                               const uint16_t *node_codes_le, size_t node_count,
                                               uint32_t retries, uint16_t *key_versions_le_out, size_t *returned_nodes_out) {
    if (idm == NULL || node_codes_le == NULL || key_versions_le_out == NULL) {
        return PM3_EINVARG;
    }

    if (node_count == 0 || node_count > FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE) {
        return PM3_EINVARG;
    }

    if (returned_nodes_out) {
        *returned_nodes_out = 0;
    }

    uint8_t data[1 + 1 + 8 + 1 + (FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE * 2)] = {0};
    uint16_t datalen = 0;
    int ret = felica_build_request_service_payload(FELICA_REQSRV_REQ, idm, node_codes_le, node_count,
                                                   data, sizeof(data), &datalen);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_REQSRV_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, retries,
                                         0, false, &resp, "request service") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    size_t offset = sizeof(felica_frame_response_t);
    if (resp.length < (offset + 1U)) {
        return PM3_ESOFT;
    }

    size_t returned_nodes = resp.data.asBytes[offset++];
    size_t available_nodes = (resp.length > offset) ? ((resp.length - offset) / 2U) : 0;
    if (returned_nodes > available_nodes) {
        returned_nodes = available_nodes;
    }
    if (returned_nodes > node_count) {
        returned_nodes = node_count;
    }

    for (size_t i = 0; i < returned_nodes; i++) {
        key_versions_le_out[i] = (uint16_t)resp.data.asBytes[offset + i * 2] |
                                 ((uint16_t)resp.data.asBytes[offset + i * 2 + 1] << 8);
    }

    if (returned_nodes_out) {
        *returned_nodes_out = returned_nodes;
    }
    return PM3_SUCCESS;
}

static int felica_request_service_v2_key_versions(uint8_t flags, const uint8_t *idm,
                                                  const uint16_t *node_codes_le, size_t node_count,
                                                  uint32_t retries,
                                                  felica_request_service_v2_key_versions_t *key_versions_out) {
    if (idm == NULL || node_codes_le == NULL || key_versions_out == NULL) {
        return PM3_EINVARG;
    }

    if (node_count == 0 || node_count > FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE) {
        return PM3_EINVARG;
    }

    memset(key_versions_out, 0, sizeof(*key_versions_out));

    uint8_t data[1 + 1 + 8 + 1 + (FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE * 2)] = {0};
    uint16_t datalen = 0;
    int ret = felica_build_request_service_payload(FELICA_REQSRV2_REQ, idm, node_codes_le, node_count,
                                                   data, sizeof(data), &datalen);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_REQSRV2_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, retries,
                                         0, false, &resp, "request service v2") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    size_t offset = sizeof(felica_frame_response_t);
    if (resp.length < (offset + 2U)) {
        return PM3_ESOFT;
    }

    const uint8_t status_flag1 = resp.data.asBytes[offset++];
    const uint8_t status_flag2 = resp.data.asBytes[offset++];
    if (status_flag1 != 0x00 || status_flag2 != 0x00) {
        return PM3_ERFTRANS;
    }

    if (resp.length < (offset + 2U)) {
        return PM3_ESOFT;
    }

    const uint8_t encryption_identifier = resp.data.asBytes[offset++];
    const felica_encryption_identifier_info_t *encryption_identifier_info =
        felica_encryption_identifier_get_info(encryption_identifier);
    const bool has_aes_key_versions = encryption_identifier_info ? encryption_identifier_info->has_aes_key_versions : false;
    const bool has_des_key_versions = encryption_identifier_info ? encryption_identifier_info->has_des_key_versions : false;

    const size_t returned_nodes = resp.data.asBytes[offset++];
    if (returned_nodes != node_count) {
        return PM3_ESOFT;
    }

    const size_t aes_bytes = returned_nodes * 2U;
    const size_t des_bytes = has_des_key_versions ? (returned_nodes * 2U) : 0U;
    if (resp.length < (offset + aes_bytes + des_bytes)) {
        return PM3_ESOFT;
    }

    key_versions_out->encryption_identifier = encryption_identifier;
    key_versions_out->has_aes_key_versions = has_aes_key_versions;
    key_versions_out->has_des_key_versions = has_des_key_versions;

    for (size_t i = 0; i < returned_nodes; i++) {
        key_versions_out->aes_key_versions_le[i] = (uint16_t)resp.data.asBytes[offset + i * 2] |
                                                   ((uint16_t)resp.data.asBytes[offset + i * 2 + 1] << 8);
    }
    offset += aes_bytes;

    if (has_des_key_versions) {
        for (size_t i = 0; i < returned_nodes; i++) {
            key_versions_out->des_key_versions_le[i] = (uint16_t)resp.data.asBytes[offset + i * 2] |
                                                       ((uint16_t)resp.data.asBytes[offset + i * 2 + 1] << 8);
        }
    }

    return PM3_SUCCESS;
}

static void felica_info_process_system_services(int level, uint8_t flags,
                                                uint16_t system_code, const uint8_t *idm, const json_t *system_entry,
                                                felica_service_block_data_cache_t *block_data_cache) {
    if (idm == NULL || system_entry == NULL) {
        return;
    }

    json_t *services_json = json_object_get(system_entry, "services");
    if (json_is_array(services_json) == false || json_array_size(services_json) == 0) {
        return;
    }

    felica_system_service_t services[FELICA_SYSTEM_SERVICE_MAX_COUNT];
    memset(services, 0, sizeof(services));

    felica_system_service_node_t nodes[FELICA_SYSTEM_SERVICE_NODE_MAX_COUNT];
    memset(nodes, 0, sizeof(nodes));

    size_t service_count = 0;
    size_t node_count = 0;

    size_t service_index_json = 0;
    json_t *service_json = NULL;
    json_array_foreach(services_json, service_index_json, service_json) {
        if (json_is_object(service_json) == false) {
            continue;
        }
        if (service_count >= FELICA_SYSTEM_SERVICE_MAX_COUNT) {
            break;
        }

        json_t *nodes_json = json_object_get(service_json, "nodes");
        if (json_is_array(nodes_json) == false || json_array_size(nodes_json) == 0) {
            continue;
        }

        felica_system_service_t *service = &services[service_count];
        service->name = felica_get_json_string(service_json, "name");
        service->type = felica_get_json_string(service_json, "type");

        const size_t this_service_index = service_count;
        size_t node_index_json = 0;
        json_t *node_json = NULL;
        json_array_foreach(nodes_json, node_index_json, node_json) {
            if (json_is_object(node_json) == false) {
                continue;
            }
            if (node_count >= FELICA_SYSTEM_SERVICE_NODE_MAX_COUNT) {
                break;
            }

            uint16_t node_code_le = 0;
            if (felica_parse_service_node_code(felica_get_json_string(node_json, "code"), &node_code_le) == false) {
                continue;
            }

            json_t *data_json = json_object_get(node_json, "data");
            const bool has_data_matchers = json_is_object(data_json) && (json_object_size(data_json) > 0);
            const size_t matcher_count = felica_parse_service_node_matchers(node_json,
                                         nodes[node_count].matchers,
                                         ARRAYLEN(nodes[node_count].matchers));
            if (has_data_matchers && matcher_count == 0) {
                continue;
            }

            nodes[node_count].node_code_le = node_code_le;
            nodes[node_count].service_index = this_service_index;
            nodes[node_count].matcher_count = matcher_count;
            node_count++;
            service->required_node_count++;
        }

        if (service->required_node_count > 0) {
            service_count++;
        }

        if (node_count >= FELICA_SYSTEM_SERVICE_NODE_MAX_COUNT) {
            break;
        }
    }

    if (service_count == 0 || node_count == 0) {
        return;
    }

    if (system_code == FELICA_SYSTEM_CODE_FELICA_LITE) {
        for (size_t i = 0; i < node_count; i++) {
            const felica_system_service_node_t *node = &nodes[i];
            if (felica_is_lite_assumed_node(node->node_code_le) == false) {
                continue;
            }

            if (node->matcher_count > 0 &&
                    felica_match_service_node_data(flags, idm, node->node_code_le,
                                                   node->matchers, node->matcher_count, block_data_cache) == false) {
                continue;
            }

            const size_t service_index = node->service_index;
            if (service_index < service_count) {
                services[service_index].present_node_count++;
            }
        }
    } else {
        size_t processed_nodes = 0;
        while (processed_nodes < node_count) {
            const size_t batch_count = MIN(FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE, node_count - processed_nodes);
            uint16_t batch_codes[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
            uint16_t key_versions[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};

            for (size_t i = 0; i < batch_count; i++) {
                batch_codes[i] = nodes[processed_nodes + i].node_code_le;
            }

            size_t returned_nodes = 0;
            if (felica_request_service_key_versions(flags, idm, batch_codes, batch_count,
                                                    FELICA_OPTIONAL_CMD_RETRIES,
                                                    key_versions, &returned_nodes) != PM3_SUCCESS) {
                return;
            }

            for (size_t i = 0; i < returned_nodes; i++) {
                if (key_versions[i] == 0xFFFFU) {
                    continue;
                }

                const felica_system_service_node_t *node = &nodes[processed_nodes + i];
                if (node->matcher_count > 0 &&
                        felica_match_service_node_data(flags, idm, node->node_code_le,
                                                       node->matchers, node->matcher_count, block_data_cache) == false) {
                    continue;
                }

                const size_t service_index = node->service_index;
                if (service_index < service_count) {
                    services[service_index].present_node_count++;
                }
            }

            processed_nodes += batch_count;
        }
    }

    size_t present_services_count = 0;
    for (size_t i = 0; i < service_count; i++) {
        if (services[i].present_node_count > 0) {
            present_services_count++;
        }
    }

    if (present_services_count == 0) {
        return;
    }

    PrintAndLogEx(level, "    Services...... " _GREEN_("%u:"), (unsigned int)present_services_count);
    for (size_t i = 0; i < service_count; i++) {
        if (services[i].present_node_count == 0) {
            continue;
        }
        const char *name = (services[i].name != NULL) ? services[i].name : "Unknown service";
        if (services[i].type) {
            PrintAndLogEx(level, "    - %s (" _YELLOW_("%s") ")", name, services[i].type);
        } else {
            PrintAndLogEx(level, "    - %s", name);
        }
    }
}

static void felica_info_process_system(int level, uint8_t flags, const felica_discovered_system_t *system) {
    if (system == NULL) {
        return;
    }

    const json_t *entry = felica_find_system_annotation(system->system_code);
    const char *name = NULL;
    const char *region = NULL;
    const char *card_type = NULL;

    if (entry) {
        name = felica_get_json_string(entry, "name");
        region = felica_get_json_string(entry, "region");
        card_type = felica_get_json_string(entry, "type");
    }

    if (name == NULL) {
        PrintAndLogEx(level, "  " _YELLOW_("UNKNOWN") " (" _RED_("REPORT TO ICEMAN") ")");
    } else if (region && card_type) {
        PrintAndLogEx(level, "  %s (" _YELLOW_("%s, %s") ")", name, region, card_type);
    } else if (region) {
        PrintAndLogEx(level, "  %s (" _YELLOW_("%s") ")", name, region);
    } else if (card_type) {
        PrintAndLogEx(level, "  %s (" _YELLOW_("%s") ")", name, card_type);
    } else {
        PrintAndLogEx(level, "  %s", name);
    }

    PrintAndLogEx(level, "    System Code.... " _YELLOW_("%04X"), system->system_code);
    if (system->has_idm) {
        PrintAndLogEx(level, "    IDM............ " _GREEN_("%s"),
                      sprint_hex_inrow(system->idm, sizeof(system->idm)));
    } else {
        PrintAndLogEx(level, "    IDM............ " _RED_("N/A"));
    }

    if (system->has_idm) {
        felica_service_block_data_cache_t block_data_cache;
        memset(&block_data_cache, 0, sizeof(block_data_cache));

        if (system->system_code == FELICA_SYSTEM_CODE_FELICA_LITE) {
            static const uint8_t lite_id_block_list_element[] = {0x80U, FELICA_BLK_NUMBER_ID};
            uint8_t lite_id_block[FELICA_BLK_SIZE] = {0};
            size_t lite_id_block_len = 0;

            if (felica_read_service_block_for_node_cached(flags, system->idm, FELICA_PRESENCE_SERVICE_CODE_LE,
                                                          lite_id_block_list_element, sizeof(lite_id_block_list_element),
                                                          lite_id_block, sizeof(lite_id_block), &lite_id_block_len,
                                                          &block_data_cache) == PM3_SUCCESS &&
                    lite_id_block_len >= FELICA_BLK_SIZE) {
                const uint8_t *lite_tail = lite_id_block + FELICA_BLK_HALF;
                const uint16_t dfc = (uint16_t)((uint16_t)lite_tail[0] << 8) | lite_tail[1];
                if (dfc == 0x0000U) {
                    PrintAndLogEx(level, "    DFC............ " _YELLOW_("%02X%02X") " ( Unused )", lite_tail[0], lite_tail[1]);
                } else {
                    PrintAndLogEx(level, "    DFC............ " _YELLOW_("%02X%02X"), lite_tail[0], lite_tail[1]);
                }
                PrintAndLogEx(level, "    ARB............ " _YELLOW_("%s"), sprint_hex_inrow(lite_tail + 2, 6));
            } else {
                PrintAndLogEx(level, "    DFC............ " _RED_("N/A"));
                PrintAndLogEx(level, "    ARB............ " _RED_("N/A"));
            }
        }

        felica_info_process_system_services(level, flags, system->system_code, system->idm, entry, &block_data_cache);
    }
}

static int send_request_system_code(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                    uint32_t timeout_ms, uint32_t retries, bool logging,
                                    felica_syscode_response_t *system_code_response) {
    if (system_code_response == NULL) {
        return PM3_EINVARG;
    }

    memset(system_code_response, 0, sizeof(*system_code_response));

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         FELICA_REQSYSCODE_ACK,
                                         timeout_ms, retries,
                                         0, logging, &resp, "request system code") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < (sizeof(felica_frame_response_t) + 1 + 2)) {
        return PM3_ESOFT;
    }

    const size_t payload_length = resp.length - 2;
    const size_t number_of_systems_offset = sizeof(felica_frame_response_t);
    if (payload_length < (number_of_systems_offset + 1)) {
        return PM3_ESOFT;
    }

    uint8_t reported_system_count = resp.data.asBytes[number_of_systems_offset];
    const size_t available_system_count = (payload_length - number_of_systems_offset - 1) / 2;
    if (reported_system_count > available_system_count) {
        return PM3_ESOFT;
    }

    if (reported_system_count > FELICA_SYSTEM_CODE_MAX_COUNT) {
        return PM3_ESOFT;
    }

    if (reported_system_count == 0) {
        memcpy(system_code_response, resp.data.asBytes, sizeof(felica_frame_response_t) + 1);
        return PM3_SUCCESS;
    }

    memcpy(system_code_response, resp.data.asBytes, sizeof(felica_frame_response_t) + 1);
    memcpy(system_code_response->system_code_list,
           resp.data.asBytes + number_of_systems_offset + 1,
           (size_t)reported_system_count * 2U);
    return PM3_SUCCESS;
}

static uint16_t felica_system_code_from_bytes(const uint8_t *system_code_bytes) {
    if (system_code_bytes == NULL) {
        return 0;
    }
    return (uint16_t)((uint16_t)system_code_bytes[0] << 8) | system_code_bytes[1];
}

static void felica_system_code_to_bytes(uint16_t system_code, uint8_t *system_code_bytes_out) {
    if (system_code_bytes_out == NULL) {
        return;
    }
    system_code_bytes_out[0] = (uint8_t)((system_code >> 8) & 0xFFU);
    system_code_bytes_out[1] = (uint8_t)(system_code & 0xFFU);
}

static bool felica_add_unique_discovered_system(felica_discovered_system_t *systems, size_t *count,
                                                uint16_t system_code, const uint8_t *idm, const uint8_t *pmm) {
    if (systems == NULL || count == NULL) {
        return false;
    }

    for (size_t i = 0; i < *count; i++) {
        if (systems[i].system_code != system_code) {
            continue;
        }

        if (idm) {
            memcpy(systems[i].idm, idm, sizeof(systems[i].idm));
            systems[i].has_idm = true;
        }
        if (pmm) {
            memcpy(systems[i].pmm, pmm, sizeof(systems[i].pmm));
            systems[i].has_pmm = true;
        }
        return true;
    }

    if (*count >= FELICA_DISCOVERED_SYSTEM_MAX_COUNT) {
        return false;
    }

    felica_discovered_system_t *system = &systems[*count];
    memset(system, 0, sizeof(*system));
    system->system_code = system_code;
    if (idm) {
        memcpy(system->idm, idm, sizeof(system->idm));
        system->has_idm = true;
    }
    if (pmm) {
        memcpy(system->pmm, pmm, sizeof(system->pmm));
        system->has_pmm = true;
    }

    (*count)++;
    return true;
}

static int send_polling(uint8_t flags, uint16_t system_code, uint8_t request_code,
                        uint32_t timeout_ms, uint32_t retries, bool logging,
                        uint8_t *idm_out, uint8_t *pmm_out, uint16_t *returned_system_code) {
    if (idm_out == NULL) {
        return PM3_EINVARG;
    }

    uint8_t polling_request[6] = {0};
    polling_request[0] = sizeof(polling_request);
    polling_request[1] = FELICA_POLL_REQ;
    felica_system_code_to_bytes(system_code, polling_request + 2);
    polling_request[4] = request_code;
    polling_request[5] = 0x00; // one target at a time

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, sizeof(polling_request), polling_request, false,
                                         FELICA_POLL_ACK,
                                         timeout_ms, retries,
                                         0, logging, &resp, "polling") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    static const size_t poll_response_min_len = 22U;
    static const size_t poll_response_idm_offset = 4U;
    static const size_t poll_response_pmm_offset = 12U;
    static const size_t poll_response_system_code_offset = 20U;

    if (resp.length < poll_response_min_len) {
        return PM3_ESOFT;
    }

    memcpy(idm_out, resp.data.asBytes + poll_response_idm_offset, 8);
    if (pmm_out) {
        memcpy(pmm_out, resp.data.asBytes + poll_response_pmm_offset, 8);
    }

    if (returned_system_code) {
        if (request_code == FELICA_POLL_REQUEST_SYSTEM_CODE) {
            if (resp.length < (poll_response_min_len + 2U)) {
                return PM3_ESOFT;
            }
            *returned_system_code = felica_system_code_from_bytes(resp.data.asBytes + poll_response_system_code_offset);
        } else {
            *returned_system_code = system_code;
        }
    }

    return PM3_SUCCESS;
}

static int discover_systems(uint8_t flags, const uint8_t *primary_idm, bool request_system_code_supported,
                            uint32_t polling_retries,
                            felica_discovered_system_list_t *discovered_systems) {
    if (primary_idm == NULL || discovered_systems == NULL) {
        return PM3_EINVARG;
    }

    memset(discovered_systems, 0, sizeof(*discovered_systems));

    if (request_system_code_supported) {
        felica_request_system_code_request_t request_system_code_request;
        memset(&request_system_code_request, 0, sizeof(request_system_code_request));
        request_system_code_request.length[0] = sizeof(request_system_code_request);
        request_system_code_request.command_code[0] = FELICA_REQSYSCODE_REQ;
        memcpy(request_system_code_request.IDm, primary_idm, sizeof(request_system_code_request.IDm));

        for (uint32_t attempt = 0; attempt < FELICA_REQUEST_SYSTEM_CODE_ATTEMPTS; attempt++) {
            felica_syscode_response_t system_code_response;
            const int request_system_code_status = send_request_system_code(flags,
                                                   sizeof(request_system_code_request), (uint8_t *)&request_system_code_request,
                                                   false, FELICA_OPTIONAL_CMD_TIMEOUT_MS, 0, false,
                                                   &system_code_response);

            if (request_system_code_status != PM3_SUCCESS) {
                continue;
            }

            const size_t reported_systems = system_code_response.number_of_systems[0];
            for (size_t i = 0; i < reported_systems; i++) {
                const uint16_t system_code = felica_system_code_from_bytes(system_code_response.system_code_list + (i * 2U));
                if (felica_add_unique_discovered_system(discovered_systems->systems, &discovered_systems->count,
                                                        system_code, NULL, NULL) == false) {
                    break;
                }
            }
        }
    }

    uint16_t primary_system_code = 0;
    uint8_t primary_idm_polled[8] = {0};
    uint8_t primary_pmm_polled[8] = {0};
    if (send_polling(flags, FELICA_SYSTEM_CODE_WILDCARD, FELICA_POLL_REQUEST_SYSTEM_CODE,
                     FELICA_POLL_TIMEOUT_MS, polling_retries, false,
                     primary_idm_polled, primary_pmm_polled, &primary_system_code) == PM3_SUCCESS) {
        felica_add_unique_discovered_system(discovered_systems->systems, &discovered_systems->count,
                                            primary_system_code, primary_idm_polled, primary_pmm_polled);
    }

    for (size_t i = 0; i < ARRAYLEN(FELICA_MANUAL_SYSTEM_PROBE_TARGETS); i++) {
        uint8_t probed_idm[8] = {0};
        uint8_t probed_pmm[8] = {0};
        const uint16_t system_code = FELICA_MANUAL_SYSTEM_PROBE_TARGETS[i].system_code;
        if (send_polling(flags, system_code, FELICA_POLL_REQUEST_NO_DATA,
                         FELICA_POLL_TIMEOUT_MS, polling_retries, false,
                         probed_idm, probed_pmm, NULL) != PM3_SUCCESS) {
            continue;
        }

        felica_add_unique_discovered_system(discovered_systems->systems, &discovered_systems->count,
                                            system_code, probed_idm, probed_pmm);
    }

    if (discovered_systems->count == 0) {
        return PM3_ERFTRANS;
    }

    for (size_t i = 0; i < discovered_systems->count; i++) {
        uint8_t resolved_idm[8] = {0};
        uint8_t resolved_pmm[8] = {0};
        if (send_polling(flags,
                         discovered_systems->systems[i].system_code,
                         FELICA_POLL_REQUEST_NO_DATA,
                         FELICA_POLL_TIMEOUT_MS,
                         polling_retries,
                         false,
                         resolved_idm, resolved_pmm, NULL) != PM3_SUCCESS) {
            continue;
        }

        memcpy(discovered_systems->systems[i].idm, resolved_idm, sizeof(discovered_systems->systems[i].idm));
        discovered_systems->systems[i].has_idm = true;
        memcpy(discovered_systems->systems[i].pmm, resolved_pmm, sizeof(discovered_systems->systems[i].pmm));
        discovered_systems->systems[i].has_pmm = true;
    }

    size_t write_index = 0;
    for (size_t i = 0; i < discovered_systems->count; i++) {
        if (discovered_systems->systems[i].has_idm == false) {
            continue;
        }

        if (write_index != i) {
            discovered_systems->systems[write_index] = discovered_systems->systems[i];
        }
        write_index++;
    }
    discovered_systems->count = write_index;

    if (discovered_systems->count == 0) {
        return PM3_ERFTRANS;
    }

    return PM3_SUCCESS;
}

/**
 * Wait for response from pm3 or timeout.
 * Checks if receveid bytes have a valid CRC.
 * @param verbose prints out the response received.
 * @param logging prints warning/error logs.
 */
static bool waitCmdFelicaEx(bool iSelect, PacketResponseNG *resp, bool verbose, bool logging, uint32_t timeout_ms) {
    if (WaitForResponseTimeout(CMD_HF_FELICA_COMMAND, resp, timeout_ms) == false) {
        if (logging) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        return false;
    }

    if (resp->status != PM3_SUCCESS) {
        if (logging) {
            PrintAndLogEx(WARNING, "FeliCa command failed (%d)", resp->status);
        }
        return false;
    }

    uint16_t len = resp->length;

    if (len == 0 || len == 1) {
        if (logging) {
            PrintAndLogEx(ERR, "Could not receive data correctly!");
        }
        return false;
    }

    if (iSelect == false) {
        if (len < 4) {
            if (logging) {
                PrintAndLogEx(ERR, "received too short frame!");
            }
            return false;
        }

        if (check_crc(CRC_FELICA, resp->data.asBytes + 2, len - 2) == false) {
            if (logging) {
                PrintAndLogEx(WARNING, "CRC ( " _RED_("fail") " )");
            }
            return false;
        }

        if (resp->data.asBytes[0] != 0xB2 || resp->data.asBytes[1] != 0x4D) {
            if (logging) {
                PrintAndLogEx(ERR, "received incorrect frame format!");
            }
            return false;
        }
    }

    if (verbose && logging) {
        PrintAndLogEx(SUCCESS, "(%u) %s", len, sprint_hex(resp->data.asBytes, len));
    }
    return true;
}

static bool waitCmdFelica(bool iSelect, PacketResponseNG *resp, bool verbose) {
    return waitCmdFelicaEx(iSelect, resp, verbose, true, FELICA_DEFAULT_TIMEOUT_MS);
}

// SEAC responses appear to echo the full command payload before card-specific bytes.
static bool get_seac_response_data(const PacketResponseNG *resp, const uint8_t *cmd_frame,
                                   size_t cmd_frame_len, const uint8_t **response_data,
                                   size_t *response_data_len) {
    if (resp == NULL || cmd_frame == NULL || response_data == NULL || response_data_len == NULL) {
        return false;
    }

    *response_data = NULL;
    *response_data_len = 0;

    if (cmd_frame_len < 2 || resp->length < (3U + (cmd_frame_len - 1U) + 2U)) {
        return false;
    }

    if (resp->data.asBytes[0] != 0xB2 || resp->data.asBytes[1] != 0x4D) {
        return false;
    }

    if (check_crc(CRC_FELICA, resp->data.asBytes + 2, resp->length - 2) == false) {
        return false;
    }

    const size_t frame_len = resp->data.asBytes[2];
    const size_t echoed_payload_len = cmd_frame_len - 1U;
    if (frame_len <= (1U + echoed_payload_len)) {
        return false;
    }

    const size_t decoded_frame_len = frame_len + 4U;
    if (decoded_frame_len > resp->length) {
        return false;
    }

    // Unlike standard FeliCa, SEAC keeps the response code equal to the request code.
    if (resp->data.asBytes[3] != cmd_frame[1]) {
        return false;
    }

    if (memcmp(resp->data.asBytes + 3, cmd_frame + 1, echoed_payload_len) != 0) {
        return false;
    }

    const size_t response_offset = 3U + echoed_payload_len;
    const size_t response_len = frame_len - 1U - echoed_payload_len;
    if ((response_offset + response_len + 2U) > decoded_frame_len) {
        return false;
    }

    *response_data = resp->data.asBytes + response_offset;
    *response_data_len = response_len;
    return true;
}

static int info_seac(void) {
    static const uint8_t seac_poll_frames[][FELICA_SEAC_POLL_FRAME_LEN] = {
        // {0x05, FELICA_POLL_REQ, 0x01, 0x01, 0x0F},
        {0x05, FELICA_POLL_REQ, 0x01, 0x01, 0x01},
    };
    const uint8_t seac_flags = FELICA_CONNECT | FELICA_CLEARTRACE | FELICA_RAW | FELICA_APPEND_CRC | FELICA_NO_SELECT;

    for (size_t i = 0; i < ARRAYLEN(seac_poll_frames); i++) {
        PacketResponseNG resp;
        if (send_felica_payload_with_retries(seac_flags, sizeof(seac_poll_frames[i]),
                                             (uint8_t *)seac_poll_frames[i], false,
                                             -1, FELICA_SEAC_POLL_TIMEOUT_MS, FELICA_SEAC_POLL_RETRY_COUNT,
                                             0, false, &resp, NULL) != PM3_SUCCESS) {
            continue;
        }

        const uint8_t *response_data = NULL;
        size_t response_data_len = 0;
        if (get_seac_response_data(&resp, seac_poll_frames[i], sizeof(seac_poll_frames[i]),
                                   &response_data, &response_data_len) == false) {
            continue;
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
        PrintAndLogEx(INFO, "Type........... " _YELLOW_("FeliCa SEAC"));
        PrintAndLogEx(INFO, "IDSEAC......... " _YELLOW_("%s"),
                      sprint_hex_inrow(response_data, response_data_len));
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    return PM3_ETIMEOUT;
}


static int CmdHFFelicaList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf felica", "felica");
}

int read_felica_uid(bool loop, bool verbose) {

    int res = PM3_ETIMEOUT;

    do {
        clear_and_send_command(FELICA_CONNECT | FELICA_CLEARTRACE, 0, NULL, false);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_FELICA_COMMAND, &resp, 2500)) {

            int status = resp.status;

            if (loop) {
                if (status != PM3_SUCCESS) {
                    continue;
                }
            } else {
                // when not in continuous mode
                if (status != PM3_SUCCESS) {
                    if (verbose) {
                        PrintAndLogEx(WARNING, "FeliCa card select failed (%d)", status);
                    }
                    res = status;
                    break;
                }
            }

            if (resp.length < sizeof(felica_card_select_t)) {
                if (verbose) {
                    PrintAndLogEx(WARNING, "FeliCa card select returned invalid payload");
                }
                res = PM3_ESOFT;
                break;
            }

            felica_card_select_t card;
            memcpy(&card, (felica_card_select_t *)resp.data.asBytes, sizeof(felica_card_select_t));
            if (loop == false) {
                PrintAndLogEx(NORMAL, "");
            }
            PrintAndLogEx(SUCCESS, "IDm: " _GREEN_("%s"), sprint_hex_inrow(card.IDm, sizeof(card.IDm)));
            set_last_known_card(card);

            res = PM3_SUCCESS;
        }

    } while (loop && (kbd_enter_pressed() == false));

    DropField();
    return res;
}

static int CmdHFFelicaReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica reader",
                  "Act as a ISO 18092 / FeliCa reader. Look for FeliCa tags until Enter or the pm3 button is pressed",
                  "hf felica reader -@    -> Continuous mode");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "silent", "silent (no messages)"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = (arg_get_lit(ctx, 1) == false);
    bool cm = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return read_felica_uid(cm, verbose);
}

static int send_get_container_id(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                 felica_get_container_id_response_t *container_id_response) {
    (void)verbose;
    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_GET_CONTAINER_ID_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                         0, false, &resp, "get container id") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < sizeof(*container_id_response)) {
        return PM3_ESOFT;
    }

    memcpy(container_id_response, (felica_get_container_id_response_t *)resp.data.asBytes, sizeof(*container_id_response));
    return PM3_SUCCESS;
}

static int send_get_container_property(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                       uint8_t *container_property_data, size_t container_property_data_capacity,
                                       size_t *container_property_data_len) {
    (void)verbose;
    if (container_property_data == NULL || container_property_data_len == NULL) {
        return PM3_EINVARG;
    }

    *container_property_data_len = 0;

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_GET_CONTAINER_PROPERTY_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                         0, false, &resp, "get container property") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < sizeof(felica_get_container_property_response_t)) {
        return PM3_ESOFT;
    }

    const size_t frame_len_offset = 2;
    if (resp.data.asBytes[frame_len_offset] < 2) {
        return PM3_ESOFT;
    }

    const size_t property_data_len = resp.data.asBytes[frame_len_offset] - 2;
    if (property_data_len == 0 || property_data_len > FELICA_CONTAINER_PROPERTY_MAX_LEN) {
        return PM3_ESOFT;
    }

    const size_t property_data_offset = sizeof(felica_frame_response_noidm_t);
    if (resp.length < property_data_offset + property_data_len) {
        return PM3_ESOFT;
    }

    size_t copy_len = property_data_len;
    if (copy_len > container_property_data_capacity) {
        copy_len = container_property_data_capacity;
    }

    memcpy(container_property_data, resp.data.asBytes + property_data_offset, copy_len);
    *container_property_data_len = copy_len;
    return PM3_SUCCESS;
}

static int send_get_container_issue_information(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                                felica_get_container_issue_info_response_t *container_issue_info_response) {
    (void)verbose;
    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_GET_CONTAINER_ISSUE_INFO_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                         0, false, &resp, "get container issue info") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < sizeof(*container_issue_info_response)) {
        return PM3_ESOFT;
    }

    memcpy(container_issue_info_response, (felica_get_container_issue_info_response_t *)resp.data.asBytes, sizeof(*container_issue_info_response));
    return PM3_SUCCESS;
}

static int send_get_platform_information(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                         felica_status_flags_t *status_flags, uint8_t *platform_information_data,
                                         size_t platform_information_data_capacity, size_t *platform_information_data_len) {
    (void)verbose;
    if (status_flags == NULL || platform_information_data == NULL || platform_information_data_len == NULL) {
        return PM3_EINVARG;
    }

    *platform_information_data_len = 0;

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, false,
                                         FELICA_GETPLATFORMINFO_ACK,
                                         FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                         0, false, &resp, "get platform info") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < (sizeof(felica_frame_response_t) + sizeof(felica_status_flags_t))) {
        return PM3_ESOFT;
    }

    const size_t status_offset = sizeof(felica_frame_response_t);
    memcpy(status_flags, resp.data.asBytes + status_offset, sizeof(*status_flags));

    if (status_flags->status_flag1[0] != 0x00 || status_flags->status_flag2[0] != 0x00) {
        return PM3_SUCCESS;
    }

    const size_t data_len_offset = sizeof(felica_frame_response_t) + sizeof(felica_status_flags_t);
    if (resp.length < (data_len_offset + 1)) {
        return PM3_ESOFT;
    }

    const size_t payload_len = resp.length - (data_len_offset + 1);
    const size_t data_len = resp.data.asBytes[data_len_offset];
    if (data_len > FELICA_PLATFORM_INFO_MAX_LEN) {
        return PM3_ESOFT;
    }
    if (payload_len < data_len) {
        return PM3_ESOFT;
    }

    size_t copy_len = data_len;
    if (copy_len > platform_information_data_capacity) {
        copy_len = platform_information_data_capacity;
    }

    memcpy(platform_information_data, resp.data.asBytes + data_len_offset + 1, copy_len);
    *platform_information_data_len = copy_len;
    return PM3_SUCCESS;
}

static int send_request_specification_version(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                              bool logging, uint32_t timeout_ms, uint32_t retries,
                                              felica_request_specification_version_info_t *specification_version_info) {
    if (specification_version_info == NULL) {
        return PM3_EINVARG;
    }

    memset(specification_version_info, 0, sizeof(*specification_version_info));

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         FELICA_REQUEST_SPEC_VERSION_ACK,
                                         timeout_ms, retries,
                                         0, logging, &resp, "request specification version") != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (resp.length < sizeof(felica_status_response_t)) {
        return PM3_ESOFT;
    }

    const size_t status_offset = sizeof(felica_frame_response_t);
    memcpy(&specification_version_info->status_flags,
           resp.data.asBytes + status_offset,
           sizeof(specification_version_info->status_flags));

    if (specification_version_info->status_flags.status_flag1[0] != 0x00) {
        return PM3_SUCCESS;
    }

    const size_t specification_offset = sizeof(felica_status_response_t);
    if (resp.length < specification_offset + 4) {
        return PM3_ESOFT;
    }

    specification_version_info->has_specification_version = true;
    specification_version_info->format_version = resp.data.asBytes[specification_offset];
    memcpy(specification_version_info->basic_version,
           resp.data.asBytes + specification_offset + 1,
           sizeof(specification_version_info->basic_version));
    specification_version_info->number_of_option = resp.data.asBytes[specification_offset + 3];

    const size_t option_bytes = (size_t)specification_version_info->number_of_option * 2U;
    const size_t payload_bytes = resp.length - (specification_offset + 4);
    if (payload_bytes < option_bytes) {
        return PM3_ESOFT;
    }

    size_t copy_option_bytes = option_bytes;
    if (copy_option_bytes > sizeof(specification_version_info->option_version_list)) {
        copy_option_bytes = sizeof(specification_version_info->option_version_list);
    }

    memcpy(specification_version_info->option_version_list,
           resp.data.asBytes + specification_offset + 4,
           copy_option_bytes);
    specification_version_info->option_version_count = copy_option_bytes / 2U;
    return PM3_SUCCESS;
}

static int info_felica(bool verbose) {

    clear_and_send_command(FELICA_CONNECT | FELICA_CLEARTRACE | FELICA_NO_DISCONNECT, 0, NULL, false);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_FELICA_COMMAND, &resp, 2500) == false) {
        DropField();
        if (verbose) PrintAndLogEx(WARNING, "FeliCa card select failed");
        return PM3_ESOFT;
    }

    if (resp.status != PM3_SUCCESS) {
        switch (resp.status) {
            case PM3_ETIMEOUT:
                if (verbose) {
                    PrintAndLogEx(WARNING, "card timeout");
                }
                break;
            case PM3_EWRONGANSWER:
                if (verbose) {
                    PrintAndLogEx(WARNING, "card answered wrong");
                }
                break;
            case PM3_ECRC:
                if (verbose) {
                    PrintAndLogEx(WARNING, "CRC check failed");
                }
                break;
            default:
                if (verbose) {
                    PrintAndLogEx(WARNING, "FeliCa card select failed (%d)", resp.status);
                }
                break;
        }
        DropField();
        return resp.status;
    }

    if (resp.length < sizeof(felica_card_select_t)) {
        if (verbose) {
            PrintAndLogEx(WARNING, "FeliCa card select returned invalid payload");
        }
        DropField();
        return PM3_ESOFT;
    }

    felica_card_select_t card;
    memcpy(&card, (felica_card_select_t *)resp.data.asBytes, sizeof(felica_card_select_t));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "Primary IDm.... " _YELLOW_("%s"), sprint_hex_inrow(card.IDm, sizeof(card.IDm)));
    char idm_prefix_buf[64] = {0};
    const char *idm_prefix_name = felica_idm_prefix_name(card.IDm, idm_prefix_buf, sizeof(idm_prefix_buf));
    if (idm_prefix_name) {
        PrintAndLogEx(INFO, "  Code......... " _GREEN_("%s") " ( %s )",
                      sprint_hex_inrow(card.code, sizeof(card.code)), idm_prefix_name);
    } else {
        PrintAndLogEx(INFO, "  Code......... " _GREEN_("%s"), sprint_hex_inrow(card.code, sizeof(card.code)));
    }
    PrintAndLogEx(INFO, "  NFCID2.......     " _GREEN_("%s"), sprint_hex_inrow(card.uid, sizeof(card.uid)));
    PrintAndLogEx(INFO, "PMM............ " _YELLOW_("%s"), sprint_hex_inrow(card.PMm, sizeof(card.PMm)));
    PrintAndLogEx(INFO, "  IC code...... " _GREEN_("%s") " ( %s )",
                  sprint_hex_inrow(card.iccode, sizeof(card.iccode)),
                  felica_ic_code_name(card.iccode[0], card.iccode[1]));
    PrintAndLogEx(INFO, "  MRT..........     " _GREEN_("%s"), sprint_hex_inrow(card.mrt, sizeof(card.mrt)));
    set_last_known_card(card);
    const uint8_t optional_flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    const bool is_felica_lite = felica_is_lite_ic_type(card.iccode[1]);

    if (is_felica_lite == false) {
        felica_get_platform_info_request_t platform_info_request;
        memset(&platform_info_request, 0, sizeof(platform_info_request));
        platform_info_request.length[0] = sizeof(platform_info_request);
        platform_info_request.command_code[0] = FELICA_GETPLATFORMINFO_REQ;
        memcpy(platform_info_request.IDm, card.IDm, sizeof(platform_info_request.IDm));

        felica_status_flags_t platform_status_flags;
        uint8_t platform_information_data[FELICA_PLATFORM_INFO_MAX_LEN] = {0};
        size_t platform_information_data_len = 0;
        if (send_get_platform_information(optional_flags,
                                          sizeof(platform_info_request), (uint8_t *)&platform_info_request,
                                          false, &platform_status_flags, platform_information_data,
                                          sizeof(platform_information_data),
                                          &platform_information_data_len) == PM3_SUCCESS &&
                platform_information_data_len > 0) {
            print_platform_information(platform_information_data, platform_information_data_len);
        }

        felica_request_specification_version_request_t request_specification_version_request;
        memset(&request_specification_version_request, 0, sizeof(request_specification_version_request));
        request_specification_version_request.length[0] = sizeof(request_specification_version_request);
        request_specification_version_request.command_code[0] = FELICA_REQUEST_SPEC_VERSION_REQ;
        memcpy(request_specification_version_request.IDm, card.IDm, sizeof(request_specification_version_request.IDm));

        felica_request_specification_version_info_t specification_version_info;
        if (send_request_specification_version(optional_flags, sizeof(request_specification_version_request),
                                               (uint8_t *)&request_specification_version_request, false,
                                               false, FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                               &specification_version_info) == PM3_SUCCESS &&
                specification_version_info.has_specification_version) {
            print_specification_versions(INFO, &specification_version_info, true);
        }

        felica_get_container_id_request_t container_id_request;
        memset(&container_id_request, 0, sizeof(container_id_request));
        container_id_request.length[0] = sizeof(container_id_request);
        container_id_request.command_code[0] = FELICA_GET_CONTAINER_ID_REQ;

        felica_get_container_id_response_t container_id_response;
        if (send_get_container_id(optional_flags, sizeof(container_id_request),
                                  (uint8_t *)&container_id_request, false,
                                  &container_id_response) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Container IDm.. " _YELLOW_("%s"),
                          sprint_hex_inrow(container_id_response.container_idm, sizeof(container_id_response.container_idm)));
        }

        felica_get_container_issue_info_request_t container_issue_info_request;
        memset(&container_issue_info_request, 0, sizeof(container_issue_info_request));
        container_issue_info_request.length[0] = sizeof(container_issue_info_request);
        container_issue_info_request.command_code[0] = FELICA_GET_CONTAINER_ISSUE_INFO_REQ;
        memcpy(container_issue_info_request.IDm, card.IDm, sizeof(container_issue_info_request.IDm));

        felica_get_container_issue_info_response_t container_issue_info_response;
        if (send_get_container_issue_information(optional_flags,
                                                 sizeof(container_issue_info_request), (uint8_t *)&container_issue_info_request, false,
                                                 &container_issue_info_response) == PM3_SUCCESS) {
            char model_ascii[sizeof(container_issue_info_response.mobile_phone_model_information) + 1] = {0};
            bool model_is_ascii = decode_zero_padded_ascii(
                                      container_issue_info_response.mobile_phone_model_information,
                                      sizeof(container_issue_info_response.mobile_phone_model_information),
                                      model_ascii,
                                      sizeof(model_ascii)
                                  );
            PrintAndLogEx(INFO, "Container issue info:");
            PrintAndLogEx(INFO, "  Format/Carrier... " _YELLOW_("%s"),
                          sprint_hex_inrow(container_issue_info_response.format_version_carrier_information,
                                           sizeof(container_issue_info_response.format_version_carrier_information)));
            if (model_is_ascii) {
                PrintAndLogEx(INFO, "  Model............ " _GREEN_("%s") " (ASCII)", model_ascii);
            } else {
                PrintAndLogEx(INFO, "  Model............ " _YELLOW_("%s") " (HEX)",
                              sprint_hex_inrow(container_issue_info_response.mobile_phone_model_information,
                                               sizeof(container_issue_info_response.mobile_phone_model_information)));
            }
        }

        const uint16_t container_properties[] = {0x0000, 0x0001};
        uint8_t container_property_data[FELICA_CONTAINER_PROPERTY_MAX_LEN] = {0};
        bool has_container_properties = false;
        for (size_t i = 0; i < ARRAYLEN(container_properties); i++) {
            felica_get_container_property_request_t container_property_request;
            memset(&container_property_request, 0, sizeof(container_property_request));
            container_property_request.length[0] = sizeof(container_property_request);
            container_property_request.command_code[0] = FELICA_GET_CONTAINER_PROPERTY_REQ;
            container_property_request.property_index[0] = container_properties[i] & 0xFF;
            container_property_request.property_index[1] = (container_properties[i] >> 8) & 0xFF;

            size_t container_property_data_len = 0;
            int container_property_status = send_get_container_property(optional_flags, sizeof(container_property_request),
                                                                        (uint8_t *)&container_property_request, false,
                                                                        container_property_data, sizeof(container_property_data),
                                                                        &container_property_data_len);
            if (container_property_status != PM3_SUCCESS) {
                if (i == 0) {
                    break;
                }
                continue;
            }

            if (container_property_data_len > 0) {
                if (has_container_properties == false) {
                    PrintAndLogEx(INFO, "Container properties:");
                    has_container_properties = true;
                }
                PrintAndLogEx(INFO, "  0x%04X........... " _YELLOW_("%s"), container_properties[i],
                              sprint_hex_inrow(container_property_data, container_property_data_len));
            }
        }
    }

    felica_discovered_system_list_t discovered_systems;
    if (discover_systems(optional_flags, card.IDm, is_felica_lite == false, FELICA_OPTIONAL_CMD_RETRIES, &discovered_systems) == PM3_SUCCESS &&
            discovered_systems.count > 0) {
        PrintAndLogEx(INFO, "Systems........ " _GREEN_("%u:"), (unsigned int)discovered_systems.count);
        for (size_t i = 0; i < discovered_systems.count; i++) {
            felica_info_process_system(INFO, optional_flags, &discovered_systems.systems[i]);
        }
    }

    DropField();
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFFelicaInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica info",
                  "Reader for FeliCa based tags",
                  "hf felica info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return info_felica(false);
}

static int CmdHFFelicaSeacInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica seacinfo",
                  "Get info about FeliCa SEAC cards",
                  "hf felica seacinfo");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return info_seac();
}

/**
 * Clears command buffer and sends the given data to pm3 with NG mode.
 */
static void clear_and_send_command_ex(uint8_t flags, uint16_t datalen, uint8_t *data, uint16_t numbits, bool verbose, bool normalize_frame) {
    uint16_t payload_len = 0;
    uint8_t *payload = data;

    // ARMSRC implementation adds FeliCa preamble and length automatically (felica_sendraw:575-576)
    // A bunch of code in this module adds length byte at data[0] regardless of that, which is wrong
    // This is a workaround to extract the actual payload correctly so that length byte isn't repeated
    // It also strips CRC if present, as ARMSRC adds it too
    if (normalize_frame && data && datalen) {
        if (datalen >= data[0] && data[0] > 0) {
            payload_len = data[0] - 1;
            if (payload_len > datalen - 1) {
                payload_len = datalen - 1;
            }
            payload = data + 1;
        } else {
            payload_len = datalen;
        }
    } else {
        payload_len = datalen;
    }

    clearCommandBuffer();
    if (verbose) {
        PrintAndLogEx(INFO, "Send raw command - Frame: %s", sprint_hex(payload, payload_len));
    }

    uint8_t packet_buf[sizeof(felica_raw_cmd_t) + PM3_CMD_DATA_SIZE] = {0};
    felica_raw_cmd_t *packet = (felica_raw_cmd_t *)packet_buf;
    packet->flags = flags;
    packet->numbits = numbits;
    packet->rawlen = payload_len;
    if (payload_len) {
        memcpy(packet->raw, payload, payload_len);
    }

    SendCommandNG(CMD_HF_FELICA_COMMAND, packet_buf, FELICA_RAW_LEN(payload_len));
}

static void clear_and_send_command(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {
    clear_and_send_command_ex(flags, datalen, data, 0, verbose, true);
}

static int felica_select_target_keep_field(const uint8_t *custom_idm, size_t custom_idm_len, uint8_t *idm_out) {
    if (idm_out == NULL) {
        return PM3_EINVARG;
    }

    if (custom_idm_len > 0 && custom_idm_len != sizeof(last_known_card.IDm)) {
        return PM3_EINVARG;
    }

    clear_and_send_command(FELICA_CONNECT | FELICA_CLEARTRACE | FELICA_NO_DISCONNECT, 0, NULL, false);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_FELICA_COMMAND, &resp, 2500) == false) {
        DropField();
        PrintAndLogEx(FAILED, "No FeliCa tag detected while polling.");
        return PM3_ESOFT;
    }

    if (resp.status != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "FeliCa card select failed (%d).", resp.status);
        return resp.status;
    }

    if (resp.length < sizeof(felica_card_select_t)) {
        DropField();
        PrintAndLogEx(FAILED, "FeliCa card select returned invalid payload.");
        return PM3_ESOFT;
    }

    felica_card_select_t card;
    memcpy(&card, (felica_card_select_t *)resp.data.asBytes, sizeof(card));

    if (custom_idm_len == sizeof(card.IDm) && memcmp(custom_idm, card.IDm, sizeof(card.IDm)) != 0) {
        DropField();
        PrintAndLogEx(FAILED, "Tag with explicit IDm not detected: " _YELLOW_("%s"),
                      sprint_hex_inrow(custom_idm, sizeof(card.IDm)));
        return PM3_ERFTRANS;
    }

    set_last_known_card(card);
    memcpy(idm_out, card.IDm, sizeof(card.IDm));
    if (custom_idm_len == sizeof(card.IDm)) {
        PrintAndLogEx(INFO, "Using explicit IDm... " _GREEN_("%s"),
                      sprint_hex_inrow(idm_out, sizeof(card.IDm)));
    } else {
        PrintAndLogEx(INFO, "Using selected IDm... " _GREEN_("%s"),
                      sprint_hex_inrow(idm_out, sizeof(card.IDm)));
    }

    return PM3_SUCCESS;
}

/**
 * Prints read-without-encryption response.
 * @param rd_noCry_resp Response frame.
 * @param block_index Optional explicit block index (UINT16_MAX to use tag value)
 */
static void print_read_without_encryption_response(felica_read_without_encryption_response_t *rd_noCry_resp, uint16_t block_index) {

    uint16_t display_block = block_index;

    if (rd_noCry_resp->status_flags.status_flag1[0] == 00 &&
            rd_noCry_resp->status_flags.status_flag2[0] == 00) {

        char *temp = sprint_hex(rd_noCry_resp->block_data, FELICA_BLK_SIZE);

        char bl_data[256];
        strncpy(bl_data, temp, sizeof(bl_data) - 1);


        PrintAndLogEx(INFO, "  %04X | %s  ", display_block, bl_data);
    } else {
        char sf1[8];
        char sf2[8];
        snprintf(sf1, sizeof(sf1), "%02X", rd_noCry_resp->status_flags.status_flag1[0]);
        snprintf(sf2, sizeof(sf2), "%02X", rd_noCry_resp->status_flags.status_flag2[0]);
        PrintAndLogEx(INFO, "  %04X | Status flag 1... %s; Status flag 2... %s", display_block, sf1, sf2);
    }
}

/**
 * Generic FeliCa command sender with timeout and retries.
 * @param flags command flags
 * @param datalen command payload length
 * @param data command payload
 * @param verbose verbose output
 * @param expected_response_cmd expected command code in response, -1 to skip check
 * @param timeout_ms timeout in milliseconds for each attempt
 * @param retries retry count after the first attempt
 * @param resp response output
 * @param request_name request label used in retry logs
 * @return PM3_SUCCESS on success
 */
static int send_felica_payload_with_retries(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                            int expected_response_cmd, uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms, bool logging,
                                            PacketResponseNG *resp, const char *request_name) {
    for (uint32_t attempt = 0; attempt <= retries; attempt++) {
        if (attempt > 0) {
            if (logging) {
                if (request_name) {
                    PrintAndLogEx(WARNING, "Retrying %s (%" PRIu32 "/%" PRIu32 ")",
                                  request_name, attempt, retries);
                } else {
                    PrintAndLogEx(WARNING, "Retrying request (%" PRIu32 "/%" PRIu32 ")",
                                  attempt, retries);
                }
            }
            uint32_t backoff_delay_ms = 0;
            if (backoff_ms > 0) {
                static const uint32_t schedule_ms[] = {0U, 100U, 200U, 500U, 1000U};
                size_t index = (size_t)(attempt - 1U);
                if (index >= ARRAYLEN(schedule_ms)) {
                    index = ARRAYLEN(schedule_ms) - 1U;
                }
                backoff_delay_ms = schedule_ms[index];
                if (backoff_delay_ms > backoff_ms) {
                    backoff_delay_ms = backoff_ms;
                }
            }
            if (backoff_delay_ms > 0) {
                msleep(backoff_delay_ms);
            }
        }

        clear_and_send_command(flags, datalen, data, verbose);
        if (waitCmdFelicaEx(false, resp, verbose, logging, timeout_ms) == false) {
            continue;
        }

        if (expected_response_cmd >= 0) {
            if (resp->length < sizeof(felica_frame_response_noidm_t)) {
                continue;
            }

            const felica_frame_response_noidm_t *frame_response = (const felica_frame_response_noidm_t *)resp->data.asBytes;
            if (frame_response->cmd_code[0] != (uint8_t)expected_response_cmd) {
                if (logging && attempt == retries) {
                    PrintAndLogEx(FAILED, "Bad response cmd 0x%02X (expected 0x%02X).",
                                  frame_response->cmd_code[0], (uint8_t)expected_response_cmd);
                }
                continue;
            }
        }

        return PM3_SUCCESS;
    }

    return PM3_ERFTRANS;
}

/**
 * Sends a request service frame to the pm3 and prints response.
 */
int send_request_service(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose) {
    if (!datalen) {
        return PM3_ERFTRANS;
    }
    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         0x03,
                                         FELICA_DEFAULT_TIMEOUT_MS, 0,
                                         0, true,
                                         &resp, "request service") != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "\nGot no response from card");
        return PM3_ERFTRANS;
    }

    felica_request_service_response_t r;
    memcpy(&r, (felica_request_service_response_t *)resp.data.asBytes, sizeof(felica_request_service_response_t));

    if (r.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Service Response:");
        PrintAndLogEx(SUCCESS, "IDm... %s", sprint_hex_inrow(r.frame_response.IDm, sizeof(r.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "  Node number............. %s", sprint_hex(r.node_number, sizeof(r.node_number)));
        PrintAndLogEx(SUCCESS, "  Node key version list... %s\n", sprint_hex(r.node_key_versions, sizeof(r.node_key_versions)));
    }
    return PM3_SUCCESS;
}

/**
 * Sends a read_without_encryption frame to pm3 and stores the response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be sent.
 * @param verbose display additional output.
 * @param rd_noCry_resp frame in which the response will be saved.
 * @return success if response was received.
 */
static int send_read_without_encryption_ex(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                           felica_read_without_encryption_response_t *rd_noCry_resp,
                                           uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms, bool logging) {
    if (rd_noCry_resp == NULL) {
        return PM3_EINVARG;
    }

    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         0x07, timeout_ms, retries,
                                         backoff_ms, logging,
                                         &resp, "read without encryption") != PM3_SUCCESS) {
        if (logging) {
            PrintAndLogEx(ERR, "No response from card");
        }
        return PM3_ERFTRANS;
    }

    const size_t min_response_len = sizeof(felica_frame_response_t) + sizeof(felica_status_flags_t) + 1U;
    if (resp.length < min_response_len) {
        return PM3_ESOFT;
    }

    memset(rd_noCry_resp, 0, sizeof(*rd_noCry_resp));
    const size_t copy_len = MIN(resp.length, sizeof(*rd_noCry_resp));
    memcpy(rd_noCry_resp, resp.data.asBytes, copy_len);

    if (rd_noCry_resp->status_flags.status_flag1[0] == 0x00 && rd_noCry_resp->status_flags.status_flag2[0] == 0x00) {
        const size_t block_count = rd_noCry_resp->number_of_block[0];
        if (block_count == 0 || block_count > 15U) {
            return PM3_ESOFT;
        }

        const size_t expected_len = min_response_len + (block_count * FELICA_BLK_SIZE);
        if (resp.length < expected_len) {
            return PM3_ESOFT;
        }
    }

    return PM3_SUCCESS;
}

/**
 * Sends a read_without_encryption frame to pm3 and stores the response.
 * Uses default timeout and no retries.
 */
static int send_read_without_encryption(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                        felica_read_without_encryption_response_t *rd_noCry_resp) {
    return send_read_without_encryption_ex(flags, datalen, data, verbose, rd_noCry_resp,
                                           FELICA_DEFAULT_TIMEOUT_MS, 0, 0, true);
}

static int felica_discover_target(felica_card_select_t *card) {
    if (card == NULL) {
        return PM3_EINVARG;
    }

    int last_status = PM3_ETIMEOUT;
    for (uint32_t attempt = 0; attempt < FELICA_TARGET_PRESENCE_ATTEMPTS; attempt++) {
        clear_and_send_command(FELICA_CONNECT | FELICA_CLEARTRACE, 0, NULL, false);

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_FELICA_COMMAND, &resp, 2500) == false) {
            last_status = PM3_ETIMEOUT;
            DropField();
            continue;
        }

        if (resp.status != PM3_SUCCESS) {
            last_status = resp.status;
            DropField();
            continue;
        }

        if (resp.length < sizeof(*card)) {
            last_status = PM3_ESOFT;
            DropField();
            continue;
        }

        memcpy(card, resp.data.asBytes, sizeof(*card));
        set_last_known_card(*card);
        DropField();
        return PM3_SUCCESS;
    }

    return last_status;
}

// Presence is checked by issuing ReadWithoutEncryption against service number 0
// with the unauthenticated random-read attribute and verifying the response IDm.
static int felica_presence_check_idm(const uint8_t *idm) {
    if (idm == NULL) {
        return PM3_EINVARG;
    }

    uint8_t data[16] = {0};
    data[0] = sizeof(data);
    data[1] = FELICA_RDBLK_REQ;
    memcpy(data + 2, idm, 8);
    data[10] = 0x01;
    data[11] = FELICA_PRESENCE_SERVICE_CODE_LE & 0xFF;
    data[12] = (FELICA_PRESENCE_SERVICE_CODE_LE >> 8) & 0xFF;
    data[13] = 0x01;
    data[14] = 0x80;
    data[15] = 0x00;

    PacketResponseNG resp;
    const uint8_t flags = FELICA_CONNECT | FELICA_CLEARTRACE | FELICA_NO_SELECT | FELICA_APPEND_CRC | FELICA_RAW;
    const int ret = send_felica_payload_with_retries(flags, sizeof(data), data, false,
                                                     FELICA_RDBLK_ACK,
                                                     FELICA_DEFAULT_TIMEOUT_MS, FELICA_TARGET_PRESENCE_ATTEMPTS - 1U,
                                                     0, false,
                                                     &resp, "presence check");
    DropField();
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    if (resp.length < sizeof(felica_frame_response_t)) {
        return PM3_ESOFT;
    }

    const felica_frame_response_t *frame_response = (const felica_frame_response_t *)resp.data.asBytes;
    if (memcmp(frame_response->IDm, idm, sizeof(frame_response->IDm)) != 0) {
        return PM3_ERFTRANS;
    }

    return PM3_SUCCESS;
}

static int felica_ensure_target_present(const uint8_t *custom_idm,
                                        size_t custom_idm_len,
                                        felica_idm_resolution_mode_t mode,
                                        uint8_t *idm_out) {
    if (idm_out == NULL) {
        return PM3_EINVARG;
    }

    if (custom_idm_len > 0 && custom_idm_len != sizeof(last_known_card.IDm)) {
        return PM3_EINVARG;
    }

    if (custom_idm_len == sizeof(last_known_card.IDm)) {
        memcpy(idm_out, custom_idm, sizeof(last_known_card.IDm));

        if (mode == FELICA_IDM_RESOLVE_CHAINED) {
            PrintAndLogEx(INFO, "Using explicit IDm... " _GREEN_("%s"),
                          sprint_hex_inrow(idm_out, sizeof(last_known_card.IDm)));
            return PM3_SUCCESS;
        }

        if (felica_presence_check_idm(idm_out) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Tag with explicit IDm not detected: " _YELLOW_("%s"),
                          sprint_hex_inrow(idm_out, sizeof(last_known_card.IDm)));
            return PM3_ERFTRANS;
        }

        felica_set_last_known_idm(idm_out);
        PrintAndLogEx(INFO, "Using explicit IDm... " _GREEN_("%s"),
                      sprint_hex_inrow(idm_out, sizeof(last_known_card.IDm)));
        return PM3_SUCCESS;
    }

    if (mode == FELICA_IDM_RESOLVE_CHAINED) {
        if (last_known_card.IDm[0] == 0 || last_known_card.IDm[1] == 0) {
            PrintAndLogEx(WARNING, "No last known card! Use `" _YELLOW_("hf felica reader") "` first or set a custom IDm");
            return PM3_EINVARG;
        }

        memcpy(idm_out, last_known_card.IDm, sizeof(last_known_card.IDm));
        PrintAndLogEx(INFO, "Using cached IDm.... " _GREEN_("%s"),
                      sprint_hex_inrow(idm_out, sizeof(last_known_card.IDm)));
        return PM3_SUCCESS;
    }

    if (last_known_card.IDm[0] != 0 && last_known_card.IDm[1] != 0) {
        if (felica_presence_check_idm(last_known_card.IDm) == PM3_SUCCESS) {
            memcpy(idm_out, last_known_card.IDm, sizeof(last_known_card.IDm));
            PrintAndLogEx(INFO, "Using cached IDm.... " _GREEN_("%s"),
                          sprint_hex_inrow(idm_out, sizeof(last_known_card.IDm)));
            return PM3_SUCCESS;
        }

        PrintAndLogEx(WARNING, "Cached IDm is no longer present. Polling for a new tag...");
    } else {
        PrintAndLogEx(WARNING, "No cached IDm available. Polling for a new tag...");
    }

    felica_card_select_t card = {0};
    const int ret = felica_discover_target(&card);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "No FeliCa tag detected while polling.");
        return ret;
    }

    memcpy(idm_out, card.IDm, sizeof(card.IDm));
    PrintAndLogEx(INFO, "Using polled IDm.... " _GREEN_("%s"),
                  sprint_hex_inrow(idm_out, sizeof(card.IDm)));
    return PM3_SUCCESS;
}

static int send_request_code_list(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                  uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms,
                                  bool logging, PacketResponseNG *resp) {
    return send_felica_payload_with_retries(flags, datalen, data, verbose,
                                            FELICA_GET_NODE_LIST_ACK,
                                            timeout_ms, retries, backoff_ms,
                                            logging, resp, "request code list");
}

/**
 * Sends a Search Service Code frame to pm3 and stores the response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be sent.
 * @param verbose display additional output.
 * @param timeout_ms timeout in milliseconds for each attempt.
 * @param retries retry count after the first attempt.
 * @param search_sv_resp frame in which the response will be saved.
 * @return success if response was received.
 */
static int send_search_service_code(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose,
                                    uint32_t timeout_ms, uint32_t retries, uint32_t backoff_ms,
                                    bool logging,
                                    felica_search_service_code_response_t *search_sv_resp) {
    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         0x0B, timeout_ms, retries,
                                         backoff_ms, logging,
                                         &resp, "search service") != PM3_SUCCESS) {
        if (logging) {
            PrintAndLogEx(ERR, "No response from card");
        }
        return PM3_ERFTRANS;
    }

    memcpy(search_sv_resp, (felica_search_service_code_response_t *)resp.data.asBytes, sizeof(felica_search_service_code_response_t));
    return PM3_SUCCESS;
}

static uint16_t felica_to_network_order(uint16_t value) {
    return (uint16_t)(((value & 0xFF00U) >> 8) | ((value & 0x00FFU) << 8));
}

static void felica_drop_connect_flag(uint8_t *flags) {
    if (flags) {
        *flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    }
}

static void felica_set_discovered_count(uint32_t *discovered_count, uint32_t count) {
    if (discovered_count) {
        *discovered_count = count;
    }
}

static void felica_set_stop_status(int *stop_status, int status) {
    if (stop_status) {
        *stop_status = status;
    }
}

static bool felica_discovery_aborted(int *stop_status) {
    if (kbd_enter_pressed()) {
        felica_set_stop_status(stop_status, PM3_EOPABORTED);
        return true;
    }
    return false;
}

static int felica_emit_discovered_node(const felica_discovered_node_t *node,
                                       felica_node_discovery_visitor_t visitor,
                                       void *ctx,
                                       uint32_t *discovered_count,
                                       int *stop_status) {
    int ret = visitor(node, ctx);
    if (ret != PM3_SUCCESS) {
        felica_set_stop_status(stop_status, ret);
        return ret;
    }

    if (discovered_count) {
        (*discovered_count)++;
    }

    return PM3_SUCCESS;
}

static const felica_node_discovery_method_info_t FELICA_NODE_DISCOVERY_METHODS[] = {
    {
        .method = FELICA_NODE_DISCOVERY_REQUEST_CODE_LIST,
        .cli_name = "request_code_list",
        .display_name = "RequestCodeList",
        .run = felica_discover_nodes_with_request_code_list
    },
    {
        .method = FELICA_NODE_DISCOVERY_SEARCH_SERVICE_CODE,
        .cli_name = "search_service_code",
        .display_name = "SearchServiceCode",
        .run = felica_discover_nodes_with_search_service_code
    },
    {
        .method = FELICA_NODE_DISCOVERY_REQUEST_SERVICE,
        .cli_name = "request_service",
        .display_name = "RequestService",
        .run = felica_discover_nodes_with_request_service
    },
    {
        .method = FELICA_NODE_DISCOVERY_READ_WITHOUT_ENCRYPTION,
        .cli_name = "read_without_encryption",
        .display_name = "ReadWithoutEncryption",
        .run = felica_discover_nodes_with_read_without_encryption
    },
};

static const felica_node_discovery_method_info_t *felica_get_node_discovery_method_info(felica_node_discovery_method_t method) {
    for (size_t i = 0; i < ARRAYLEN(FELICA_NODE_DISCOVERY_METHODS); i++) {
        if (FELICA_NODE_DISCOVERY_METHODS[i].method == method) {
            return &FELICA_NODE_DISCOVERY_METHODS[i];
        }
    }
    return NULL;
}

static const char *felica_node_discovery_method_display_name(felica_node_discovery_method_t method) {
    if (method == FELICA_NODE_DISCOVERY_NONE) {
        return "Auto";
    }
    const felica_node_discovery_method_info_t *info = felica_get_node_discovery_method_info(method);
    return info ? info->display_name : "Auto";
}

static void felica_print_node_discovery_method_used(felica_node_discovery_method_t method) {
    const char *name = felica_node_discovery_method_display_name(method);
    if (method == FELICA_NODE_DISCOVERY_REQUEST_CODE_LIST) {
        PrintAndLogEx(INFO, "Node discovery method used: " _GREEN_("%s"), name);
        return;
    }
    if (method == FELICA_NODE_DISCOVERY_REQUEST_SERVICE) {
        PrintAndLogEx(INFO, "Node discovery method used: " _YELLOW_("%s"), name);
        return;
    }
    if (method == FELICA_NODE_DISCOVERY_READ_WITHOUT_ENCRYPTION) {
        PrintAndLogEx(INFO, "Node discovery method used: " _RED_("%s"), name);
        return;
    }
    PrintAndLogEx(INFO, "Node discovery method used: %s", name);
}

static bool felica_discover_nodes_with_request_code_list(uint8_t *flags,
                                                         const uint8_t *idm,
                                                         uint32_t retry_count,
                                                         felica_node_discovery_visitor_t visitor,
                                                         void *ctx,
                                                         uint32_t *discovered_count,
                                                         int *stop_status) {

    uint8_t data[14] = {0};
    data[0] = sizeof(data);
    data[1] = FELICA_GET_NODE_LIST_REQ;
    memcpy(data + 2, idm, 8);
    data[10] = 0x00;
    data[11] = 0x00;

    bool supported = false;
    uint32_t local_count = 0;

    for (uint16_t index = 1; index != 0; index++) {
        if (felica_discovery_aborted(stop_status)) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        data[12] = index & 0xFF;
        data[13] = (index >> 8) & 0xFF;

        PacketResponseNG resp;
        if (send_request_code_list(*flags, sizeof(data), data, false,
                                   FELICA_DEFAULT_TIMEOUT_MS, retry_count,
                                   supported ? FELICA_DISCOVERY_RETRY_BACKOFF_MS : 0, supported, &resp) != PM3_SUCCESS) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        if (supported == false) {
            supported = true;
            felica_print_node_discovery_method_used(FELICA_NODE_DISCOVERY_REQUEST_CODE_LIST);
        }
        felica_drop_connect_flag(flags);

        size_t offset = sizeof(felica_frame_response_t);
        if (resp.length < offset + 4) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        const uint8_t status_flag1 = resp.data.asBytes[offset++];
        const uint8_t status_flag2 = resp.data.asBytes[offset++];
        if (status_flag1 != 0x00 || status_flag2 != 0x00) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        const bool continue_flag = resp.data.asBytes[offset++] != 0x00;
        const uint8_t area_count = resp.data.asBytes[offset++];
        const size_t area_bytes = (size_t)area_count * 4U;

        if (resp.length < offset + area_bytes + 1U) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        felica_discovered_node_t batch_nodes[128];
        size_t batch_count = 0;

        for (uint8_t i = 0; i < area_count; i++) {
            felica_discovered_node_t node = {0};
            node.node_code_le = (uint16_t)resp.data.asBytes[offset] |
                                ((uint16_t)resp.data.asBytes[offset + 1] << 8);
            node.type = felica_node_type_from_code(node.node_code_le);
            node.has_end_code = (node.type == FELICA_NODE_TYPE_AREA);
            node.end_code_le = node.has_end_code
                               ? ((uint16_t)resp.data.asBytes[offset + 2] |
                                  ((uint16_t)resp.data.asBytes[offset + 3] << 8))
                               : 0;
            offset += 4;
            if (batch_count < ARRAYLEN(batch_nodes)) {
                batch_nodes[batch_count++] = node;
            }
        }

        const uint8_t service_count = resp.data.asBytes[offset++];
        const size_t service_bytes = (size_t)service_count * 2U;
        if (resp.length < offset + service_bytes) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        for (uint8_t i = 0; i < service_count; i++) {
            felica_discovered_node_t node = {0};
            node.node_code_le = (uint16_t)resp.data.asBytes[offset] |
                                ((uint16_t)resp.data.asBytes[offset + 1] << 8);
            node.type = felica_node_type_from_code(node.node_code_le);
            node.has_end_code = false;
            node.end_code_le = 0;
            offset += 2;
            if (batch_count < ARRAYLEN(batch_nodes)) {
                batch_nodes[batch_count++] = node;
            }
        }

        qsort(batch_nodes, batch_count, sizeof(batch_nodes[0]), felica_compare_discovered_nodes);
        for (size_t i = 0; i < batch_count; i++) {
            if (felica_emit_discovered_node(&batch_nodes[i], visitor, ctx, &local_count, stop_status) != PM3_SUCCESS) {
                felica_set_discovered_count(discovered_count, local_count);
                return false;
            }
        }

        if (continue_flag == false) {
            break;
        }
    }

    if (supported) {
        felica_discovered_node_t node = {0};
        node.type = FELICA_NODE_TYPE_SYSTEM;
        node.node_code_le = FELICA_SYSTEM_NODE;
        node.has_end_code = false;
        node.end_code_le = 0;
        /*
         * RequestCodeList does not report the system node explicitly, but any
         * target supporting node-list discovery has a system node. Treat it as
         * implicit and emit it last, matching SearchServiceCode ordering.
         */
        if (felica_emit_discovered_node(&node, visitor, ctx, &local_count, stop_status) != PM3_SUCCESS) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }
    }

    felica_set_discovered_count(discovered_count, local_count);

    return supported;
}

static bool felica_discover_nodes_with_search_service_code(uint8_t *flags,
                                                           const uint8_t *idm,
                                                           uint32_t retry_count,
                                                           felica_node_discovery_visitor_t visitor,
                                                           void *ctx,
                                                           uint32_t *discovered_count,
                                                           int *stop_status) {

    uint8_t data[12] = {0};
    data[0] = sizeof(data);
    data[1] = FELICA_SRCHSYSCODE_REQ;
    memcpy(data + 2, idm, 8);

    bool supported = false;
    uint32_t local_count = 0;

    for (uint32_t cursor = 0; cursor <= 0xFFFFU; cursor++) {
        if (felica_discovery_aborted(stop_status)) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        data[10] = cursor & 0xFF;
        data[11] = (cursor >> 8) & 0xFF;

        felica_search_service_code_response_t resp;
        if (send_search_service_code(*flags, sizeof(data), data, false,
                                     FELICA_DEFAULT_TIMEOUT_MS, retry_count,
                                     supported ? FELICA_DISCOVERY_RETRY_BACKOFF_MS : 0,
                                     supported,
                                     &resp) != PM3_SUCCESS) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        if (supported == false) {
            supported = true;
            felica_print_node_discovery_method_used(FELICA_NODE_DISCOVERY_SEARCH_SERVICE_CODE);
        }
        felica_drop_connect_flag(flags);

        const uint8_t frame_len = resp.frame_response.length[0];
        if (frame_len != 0x0C && frame_len != 0x0E) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        const uint16_t node_code_le = (uint16_t)resp.payload[0] | ((uint16_t)resp.payload[1] << 8);
        felica_discovered_node_t node = {0};
        node.node_code_le = node_code_le;
        node.type = felica_node_type_from_code(node_code_le);
        node.has_end_code = (node.type == FELICA_NODE_TYPE_AREA && frame_len == 0x0E);
        node.end_code_le = node.has_end_code ? ((uint16_t)resp.payload[2] | ((uint16_t)resp.payload[3] << 8)) : 0;

        if (felica_emit_discovered_node(&node, visitor, ctx, &local_count, stop_status) != PM3_SUCCESS) {
            felica_set_discovered_count(discovered_count, local_count);
            return false;
        }

        if (node.type == FELICA_NODE_TYPE_SYSTEM) {
            break;
        }
    }

    felica_set_discovered_count(discovered_count, local_count);

    return supported;
}

static bool felica_request_service_send_probe_batch(uint8_t *flags,
                                                    const uint8_t *idm,
                                                    uint32_t retry_count,
                                                    const uint16_t *node_codes_le,
                                                    const felica_node_type_t *node_types,
                                                    size_t node_count,
                                                    felica_node_discovery_visitor_t visitor,
                                                    void *ctx,
                                                    bool *supported,
                                                    uint32_t *discovered_count,
                                                    int *stop_status) {
    if (node_count == 0 || node_count > FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE) {
        return false;
    }

    uint8_t data[1 + 1 + 8 + 1 + (FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE * 2)] = {0};
    uint16_t datalen = 0;
    if (felica_build_request_service_payload(FELICA_REQSRV_REQ, idm, node_codes_le, node_count,
                                             data, sizeof(data), &datalen) != PM3_SUCCESS) {
        return false;
    }

    PacketResponseNG resp;
    const bool logging = (supported != NULL) && (*supported);
    const uint32_t backoff_ms = logging ? FELICA_DISCOVERY_RETRY_BACKOFF_MS : 0;
    if (send_felica_payload_with_retries(*flags, datalen, data, false,
                                         FELICA_REQSRV_ACK,
                                         FELICA_DEFAULT_TIMEOUT_MS, retry_count,
                                         backoff_ms, logging, &resp, "request service") != PM3_SUCCESS) {
        return false;
    }

    if (supported) {
        if (*supported == false) {
            felica_print_node_discovery_method_used(FELICA_NODE_DISCOVERY_REQUEST_SERVICE);
        }
        *supported = true;
    }
    felica_drop_connect_flag(flags);

    size_t offset = sizeof(felica_frame_response_t);
    if (resp.length < offset + 1U) {
        return false;
    }

    size_t returned_nodes = resp.data.asBytes[offset++];
    size_t available_nodes = (resp.length > offset) ? ((resp.length - offset) / 2U) : 0;
    if (returned_nodes > available_nodes) {
        returned_nodes = available_nodes;
    }
    if (returned_nodes > node_count) {
        returned_nodes = node_count;
    }

    for (size_t i = 0; i < returned_nodes; i++) {
        const uint16_t key_version = (uint16_t)resp.data.asBytes[offset + i * 2] |
                                     ((uint16_t)resp.data.asBytes[offset + i * 2 + 1] << 8);
        if (key_version == 0xFFFF && node_types[i] != FELICA_NODE_TYPE_SYSTEM) {
            continue;
        }

        felica_discovered_node_t node = {0};
        node.type = node_types[i];
        node.node_code_le = node_codes_le[i];
        node.has_end_code = false;
        node.end_code_le = 0;

        if (felica_emit_discovered_node(&node, visitor, ctx, discovered_count, stop_status) != PM3_SUCCESS) {
            return false;
        }
    }

    return true;
}

static bool felica_discover_nodes_with_request_service(uint8_t *flags,
                                                       const uint8_t *idm,
                                                       uint32_t retry_count,
                                                       felica_node_discovery_visitor_t visitor,
                                                       void *ctx,
                                                       uint32_t *discovered_count,
                                                       int *stop_status) {
    bool supported = false;
    uint32_t local_count = 0;

    uint16_t batch_codes[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
    felica_node_type_t batch_types[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
    size_t batch_count = 0;

    for (uint16_t number = 0; number <= FELICA_MAX_NODE_NUMBER; number++) {
        for (size_t j = 0; j < ARRAYLEN(FELICA_REQUEST_SERVICE_PROBE_ATTRIBUTES); j++) {
            if (felica_discovery_aborted(stop_status)) {
                felica_set_discovered_count(discovered_count, local_count);
                return false;
            }

            const felica_request_service_probe_attribute_t probe_attr = FELICA_REQUEST_SERVICE_PROBE_ATTRIBUTES[j];
            if (probe_attr.with_pin) {
                // Some cards do not react well to RequestService probes that include
                // unsupported node attributes, so PIN-related nodes supported only on mobile are skipped here.
                continue;
            }

            const uint16_t node_code_le = (uint16_t)((number << 6) | probe_attr.attribute);
            if (node_code_le == FELICA_SYSTEM_NODE) {
                continue;
            }

            batch_codes[batch_count] = node_code_le;
            batch_types[batch_count] = felica_node_type_from_code(node_code_le);
            batch_count++;

            if (batch_count == FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE) {
                if (felica_request_service_send_probe_batch(flags, idm, retry_count,
                                                            batch_codes, batch_types, batch_count,
                                                            visitor, ctx, &supported, &local_count, stop_status) == false) {
                    felica_set_discovered_count(discovered_count, local_count);
                    if (stop_status && *stop_status == PM3_EOPABORTED) {
                        return false;
                    }
                    if (supported) {
                        PrintAndLogEx(WARNING, "Node discovery interrupted due to communication loss.");
                    }
                    return false;
                }
                batch_count = 0;
            }
        }
    }

    batch_codes[batch_count] = FELICA_SYSTEM_NODE;
    batch_types[batch_count] = FELICA_NODE_TYPE_SYSTEM;
    batch_count++;

    if (batch_count > 0) {
        if (felica_request_service_send_probe_batch(flags, idm, retry_count,
                                                    batch_codes, batch_types, batch_count,
                                                    visitor, ctx, &supported, &local_count, stop_status) == false) {
            felica_set_discovered_count(discovered_count, local_count);
            if (stop_status && *stop_status == PM3_EOPABORTED) {
                return false;
            }
            if (supported) {
                PrintAndLogEx(WARNING, "Node discovery interrupted due to communication loss.");
            }
            return false;
        }
    }

    felica_set_discovered_count(discovered_count, local_count);

    return supported;
}

static bool felica_discover_nodes_with_read_without_encryption_ex(uint8_t *flags,
        const uint8_t *idm,
        uint32_t retry_count,
        const uint8_t *pmm,
        felica_node_discovery_visitor_t visitor,
        void *ctx,
        uint32_t *discovered_count,
        int *stop_status) {
    uint8_t data[16] = {0};
    data[0] = sizeof(data);
    data[1] = FELICA_RDBLK_REQ;
    memcpy(data + 2, idm, 8);
    data[10] = 0x01;
    data[13] = 0x01;
    data[14] = 0x80;
    data[15] = 0x00;

    bool supported = false;
    uint32_t local_count = 0;
    // FeliCa Lite normally needs node 0; keep 16 for odd mode-node declarations.
    const uint16_t max_node_number = felica_pmm_is_lite(pmm) ? FELICA_LITE_NODE_DISCOVERY_MAX_NODE_NUMBER : FELICA_MAX_NODE_NUMBER;

    for (uint16_t node_number = 0; node_number <= max_node_number; node_number++) {
        for (size_t i = 0; i < ARRAYLEN(FELICA_REQUEST_SERVICE_PROBE_ATTRIBUTES); i++) {
            if (felica_discovery_aborted(stop_status)) {
                felica_set_discovered_count(discovered_count, local_count);
                return false;
            }

            const felica_request_service_probe_attribute_t probe_attr = FELICA_REQUEST_SERVICE_PROBE_ATTRIBUTES[i];
            if (probe_attr.is_area || probe_attr.with_key || probe_attr.with_pin) {
                continue;
            }

            const uint16_t service_code_le = (uint16_t)((node_number << 6) | probe_attr.attribute);
            data[11] = service_code_le & 0xFF;
            data[12] = (service_code_le >> 8) & 0xFF;

            felica_read_without_encryption_response_t resp;
            if (send_read_without_encryption_ex(*flags, sizeof(data), data, false,
                                                &resp,
                                                FELICA_DEFAULT_TIMEOUT_MS, retry_count,
                                                supported ? FELICA_DISCOVERY_RETRY_BACKOFF_MS : 0, supported) != PM3_SUCCESS) {
                if (supported == false) {
                    return false;
                }
                PrintAndLogEx(WARNING, "Stopping ReadWithoutEncryption discovery due to communication loss (possible card removed).");
                if (discovered_count) {
                    *discovered_count = local_count;
                }
                return true;
            }

            if (supported == false) {
                supported = true;
                felica_print_node_discovery_method_used(FELICA_NODE_DISCOVERY_READ_WITHOUT_ENCRYPTION);
            }
            felica_drop_connect_flag(flags);

            /*
             * For discovery via ReadWithoutEncryption:
             * - A6 (Illegal Service Code List) is treated as "node does not exist".
             * - Other status codes (for example A8, B1) still imply the node exists.
             */
            if (resp.status_flags.status_flag2[0] == 0xA6) {
                continue;
            }

            felica_discovered_node_t node = {0};
            node.type = FELICA_NODE_TYPE_SERVICE;
            node.node_code_le = service_code_le;
            node.has_end_code = false;
            node.end_code_le = 0;

            if (felica_emit_discovered_node(&node, visitor, ctx, &local_count, stop_status) != PM3_SUCCESS) {
                if (discovered_count) {
                    *discovered_count = local_count;
                }
                return false;
            }
        }
    }

    if (discovered_count) {
        *discovered_count = local_count;
    }

    return supported;
}

static bool felica_discover_nodes_with_read_without_encryption(uint8_t *flags,
        const uint8_t *idm,
        uint32_t retry_count,
        felica_node_discovery_visitor_t visitor,
        void *ctx,
        uint32_t *discovered_count,
        int *stop_status) {
    return felica_discover_nodes_with_read_without_encryption_ex(flags, idm, retry_count, NULL,
            visitor, ctx, discovered_count, stop_status);
}

static const char *felica_node_discovery_method_cli_name(felica_node_discovery_method_t method) {
    if (method == FELICA_NODE_DISCOVERY_NONE) {
        return "auto";
    }
    const felica_node_discovery_method_info_t *info = felica_get_node_discovery_method_info(method);
    return info ? info->cli_name : "auto";
}

static int felica_parse_node_discovery_method(const char *method_str, felica_node_discovery_method_t *method_out) {
    if (method_out == NULL) {
        return PM3_EINVARG;
    }

    *method_out = FELICA_NODE_DISCOVERY_NONE;

    if (method_str == NULL || method_str[0] == '\0' || strcmp(method_str, "auto") == 0) {
        return PM3_SUCCESS;
    }

    for (size_t i = 0; i < ARRAYLEN(FELICA_NODE_DISCOVERY_METHODS); i++) {
        if (strcmp(method_str, FELICA_NODE_DISCOVERY_METHODS[i].cli_name) == 0) {
            *method_out = FELICA_NODE_DISCOVERY_METHODS[i].method;
            return PM3_SUCCESS;
        }
    }

    PrintAndLogEx(ERR, "Unknown --method `%s`.", method_str);
    PrintAndLogEx(INFO, "Valid values: auto, request_code_list, search_service_code, request_service, read_without_encryption");
    return PM3_EINVARG;
}

static int felica_discover_nodes(const uint8_t *idm,
                                 const uint8_t *pmm,
                                 uint8_t *flags,
                                 uint32_t retry_count,
                                 felica_node_discovery_method_t selected_method,
                                 felica_node_discovery_visitor_t visitor,
                                 void *ctx,
                                 felica_node_discovery_method_t *method_out,
                                 uint32_t *discovered_count_out) {
    if (idm == NULL || flags == NULL || visitor == NULL) {
        return PM3_EINVARG;
    }

    felica_node_discovery_method_t ignored_method = FELICA_NODE_DISCOVERY_NONE;
    uint32_t ignored_count = 0;
    felica_node_discovery_method_t *const out_method = method_out ? method_out : &ignored_method;
    uint32_t *const out_count = discovered_count_out ? discovered_count_out : &ignored_count;

    uint32_t discovered_count = 0;
    const bool auto_mode = (selected_method == FELICA_NODE_DISCOVERY_NONE);
    for (size_t i = 0; i < ARRAYLEN(FELICA_NODE_DISCOVERY_METHODS); i++) {
        const felica_node_discovery_method_info_t *info = &FELICA_NODE_DISCOVERY_METHODS[i];
        if (!auto_mode && selected_method != info->method) {
            continue;
        }

        discovered_count = 0;
        int stop_status = PM3_SUCCESS;
        bool discovered = false;
        if (info->method == FELICA_NODE_DISCOVERY_READ_WITHOUT_ENCRYPTION) {
            discovered = felica_discover_nodes_with_read_without_encryption_ex(flags, idm, retry_count, pmm,
                         visitor, ctx, &discovered_count, &stop_status);
        } else {
            discovered = info->run(flags, idm, retry_count, visitor, ctx, &discovered_count, &stop_status);
        }

        if (discovered) {
            *out_method = info->method;
            *out_count = discovered_count;
            return PM3_SUCCESS;
        }

        if (stop_status != PM3_SUCCESS) {
            *out_method = info->method;
            *out_count = discovered_count;
            return stop_status;
        }

        if (discovered_count > 0) {
            *out_method = info->method;
            *out_count = discovered_count;
            return PM3_ERFTRANS;
        }

        if (!auto_mode) {
            *out_method = FELICA_NODE_DISCOVERY_NONE;
            *out_count = discovered_count;
            return PM3_ERFTRANS;
        }
    }

    *out_method = FELICA_NODE_DISCOVERY_NONE;
    *out_count = 0;
    return PM3_ERFTRANS;
}

static bool felica_format_service_attribute(uint16_t service_code_le, char *attrib_str, size_t attrib_str_size) {
    if (attrib_str == NULL || attrib_str_size == 0) {
        return false;
    }

    const uint8_t attribute = service_code_le & 0x3F;
    const bool is_public = (attribute & FELICA_SERVICE_ATTRIBUTE_UNAUTH_READ) != 0;
    const bool is_purse = (attribute & FELICA_SERVICE_ATTRIBUTE_PURSE) != 0;
    const char *visibility = is_public ? "Public " : "Private";
    const char *group = NULL;
    const char *mode = NULL;

    if (is_purse) {
        group = "Purse ";
        switch ((attribute & FELICA_SERVICE_ATTRIBUTE_PURSE_SUBFIELD) >> 1) {
            case 0:
                mode = "Direct";
                break;
            case 1:
                mode = "Cashback";
                break;
            case 2:
                mode = "Decrement";
                break;
            case 3:
                mode = "Read Only";
                break;
            default:
                mode = "Unknown";
                break;
        }
    } else {
        const bool is_random = (attribute & FELICA_SERVICE_ATTRIBUTE_RANDOM_ACCESS) != 0;
        const bool is_readonly = (attribute & FELICA_SERVICE_ATTRIBUTE_READ_ONLY) != 0;
        group = is_random ? "Random" : "Cyclic";
        mode = is_readonly ? "Read Only" : "Read/Write";
    }

    snprintf(attrib_str, attrib_str_size, "| %s | %s | %s |", visibility, group, mode);
    return is_public;
}

static int felica_compare_discovered_nodes(const void *lhs, const void *rhs) {
    const felica_discovered_node_t *a = (const felica_discovered_node_t *)lhs;
    const felica_discovered_node_t *b = (const felica_discovered_node_t *)rhs;

    if (a->node_code_le < b->node_code_le) {
        return -1;
    }
    if (a->node_code_le > b->node_code_le) {
        return 1;
    }

    if (a->type != b->type) {
        return a->type < b->type ? -1 : 1;
    }

    if (a->has_end_code != b->has_end_code) {
        return a->has_end_code ? -1 : 1;
    }

    if (a->end_code_le < b->end_code_le) {
        return -1;
    }
    if (a->end_code_le > b->end_code_le) {
        return 1;
    }

    return 0;
}

static int felica_scsvcode_discovery_visitor(const felica_discovered_node_t *node, void *ctx) {
    if (node == NULL || ctx == NULL) {
        return PM3_EINVARG;
    }

    felica_scsvcode_context_t *scsv_ctx = (felica_scsvcode_context_t *)ctx;
    if (scsv_ctx->header_printed == false) {
        PrintAndLogEx(INFO, "┌───────────────────────────────────────────────");
        scsv_ctx->header_printed = true;
    }

    while (scsv_ctx->depth && node->node_code_le > scsv_ctx->area_end_stack[scsv_ctx->depth]) {
        scsv_ctx->depth--;
    }

    char prefix[64] = "";
    for (int level = 1; level < scsv_ctx->depth; level++) {
        const bool more_siblings = node->node_code_le < scsv_ctx->area_end_stack[level];
        strcat(prefix, more_siblings ? "│   " : "    ");
    }
    strcat(prefix, "├── ");

    const uint16_t node_code_be = felica_to_network_order(node->node_code_le);
    const uint16_t node_number = node->node_code_le >> 6;

    if (node->type == FELICA_NODE_TYPE_SYSTEM) {
        PrintAndLogEx(INFO, "%sSYSTEM_%04X", prefix, node_code_be);
    } else if (node->type == FELICA_NODE_TYPE_AREA) {
        scsv_ctx->area_count++;
        if (node->has_end_code) {
            const uint16_t end_code_be = felica_to_network_order(node->end_code_le);
            const uint16_t end_number = node->end_code_le >> 6;
            PrintAndLogEx(INFO, "%sAREA_%04X%04X (%u-%u)", prefix,
                          node_code_be, end_code_be,
                          node_number, end_number);

            if (scsv_ctx->depth < 7) {
                scsv_ctx->area_end_stack[++scsv_ctx->depth] = node->end_code_le;
            }
        } else {
            PrintAndLogEx(INFO, "%sAREA_%04X (%u-?)", prefix, node_code_be, node_number);
        }
    } else {
        scsv_ctx->service_count++;
        PrintAndLogEx(INFO, "%sSVC_%04X (%u)", prefix, node_code_be, node_number);
    }

    return PM3_SUCCESS;
}

static void felica_scsvcode_print_footer(const felica_scsvcode_context_t *scsv_ctx) {
    if (scsv_ctx == NULL || scsv_ctx->header_printed == false) {
        return;
    }

    char bar[128];
    size_t pos = 0;
    pos += snprintf(bar + pos, sizeof(bar) - pos, "└");
    for (int i = 0; i < scsv_ctx->depth - 1 && pos < sizeof(bar); i++) {
        pos += snprintf(bar + pos, sizeof(bar) - pos, "───┴");
    }
    snprintf(bar + pos, sizeof(bar) - pos, "───────────────────────");
    PrintAndLogEx(INFO, "%s", bar);
}

static void felica_dump_node_free(felica_dump_node_t *node) {
    if (node == NULL) {
        return;
    }
    free(node->blocks);
    memset(node, 0, sizeof(*node));
}

static void felica_dump_system_free(felica_dump_system_t *system) {
    if (system == NULL) {
        return;
    }
    for (size_t i = 0; i < system->node_count; i++) {
        felica_dump_node_free(&system->nodes[i]);
    }
    free(system->nodes);
    memset(system, 0, sizeof(*system));
}

static void felica_dump_systems_free(felica_dump_system_t *systems, size_t system_count) {
    if (systems == NULL) {
        return;
    }
    for (size_t i = 0; i < system_count; i++) {
        felica_dump_system_free(&systems[i]);
    }
}

static felica_dump_node_t *felica_dump_system_add_node(felica_dump_system_t *system,
                                                       const felica_discovered_node_t *node) {
    if (system == NULL || node == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < system->node_count; i++) {
        felica_dump_node_t *dump_node = &system->nodes[i];
        if (dump_node->type == node->type &&
                dump_node->node_code_le == node->node_code_le &&
                dump_node->has_end_code == node->has_end_code &&
                dump_node->end_code_le == node->end_code_le) {
            return dump_node;
        }
    }

    if (system->node_count == system->node_capacity) {
        // Common area is the most populated FeliCa system, it is unlikely that any other one may have more than 128 nodes
        size_t new_capacity = (system->node_capacity == 0)
                              ? (system->system_code == FELICA_SYSTEM_CODE_FELICA_NETWORKS_COMMON_AREA
                                 ? FELICA_DUMP_COMMON_AREA_NODE_CAPACITY
                                 : FELICA_DUMP_DEFAULT_NODE_CAPACITY)
                              : system->node_capacity * 2U;
        felica_dump_node_t *new_nodes = realloc(system->nodes, new_capacity * sizeof(system->nodes[0]));
        if (new_nodes == NULL) {
            return NULL;
        }
        memset(new_nodes + system->node_capacity, 0, (new_capacity - system->node_capacity) * sizeof(new_nodes[0]));
        system->nodes = new_nodes;
        system->node_capacity = new_capacity;
    }

    felica_dump_node_t *dump_node = &system->nodes[system->node_count++];
    memset(dump_node, 0, sizeof(*dump_node));
    dump_node->type = node->type;
    dump_node->node_code_le = node->node_code_le;
    dump_node->has_end_code = node->has_end_code;
    dump_node->end_code_le = node->end_code_le;
    return dump_node;
}

static int felica_dump_node_add_block(felica_dump_node_t *node, uint16_t block_number, const uint8_t *block_data) {
    if (node == NULL || block_data == NULL) {
        return PM3_EINVARG;
    }

    for (size_t i = 0; i < node->block_count; i++) {
        if (node->blocks[i].block_number == block_number) {
            memcpy(node->blocks[i].data, block_data, FELICA_BLK_SIZE);
            return PM3_SUCCESS;
        }
    }

    if (node->block_count == node->block_capacity) {
        const size_t new_capacity = (node->block_capacity == 0) ? 16U : node->block_capacity * 2U;
        felica_dump_block_t *new_blocks = realloc(node->blocks, new_capacity * sizeof(node->blocks[0]));
        if (new_blocks == NULL) {
            return PM3_EMALLOC;
        }
        memset(new_blocks + node->block_capacity, 0, (new_capacity - node->block_capacity) * sizeof(new_blocks[0]));
        node->blocks = new_blocks;
        node->block_capacity = new_capacity;
    }

    felica_dump_block_t *block = &node->blocks[node->block_count++];
    block->block_number = block_number;
    memcpy(block->data, block_data, FELICA_BLK_SIZE);
    return PM3_SUCCESS;
}

static bool felica_dump_node_has_block(const felica_dump_node_t *node, uint16_t block_number) {
    if (node == NULL) {
        return false;
    }

    for (size_t i = 0; i < node->block_count; i++) {
        if (node->blocks[i].block_number == block_number) {
            return true;
        }
    }

    return false;
}

static int felica_dump_try_read_service_block(felica_dump_context_t *dump_ctx, felica_dump_node_t *dump_node,
                                              uint16_t block_number, bool *read_success) {
    if (dump_ctx == NULL || dump_ctx->flags == NULL || read_success == NULL || block_number > 0x00FFU) {
        return PM3_EINVARG;
    }

    *read_success = false;
    dump_ctx->block_frame[15] = (uint8_t)(block_number & 0xFFU);
    felica_read_without_encryption_response_t rd_noCry_resp;
    if (send_read_without_encryption_ex(*(dump_ctx->flags), dump_ctx->block_datalen,
                                        dump_ctx->block_frame, false,
                                        &rd_noCry_resp,
                                        FELICA_DEFAULT_TIMEOUT_MS, dump_ctx->retry_count, 0, true) != PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    if (rd_noCry_resp.status_flags.status_flag1[0] != 0x00 || rd_noCry_resp.status_flags.status_flag2[0] != 0x00) {
        return PM3_SUCCESS;
    }

    print_read_without_encryption_response(&rd_noCry_resp, block_number);
    if (dump_node) {
        int ret = felica_dump_node_add_block(dump_node, block_number, rd_noCry_resp.block_data);
        if (ret != PM3_SUCCESS) {
            return ret;
        }
    }

    *read_success = true;
    return PM3_SUCCESS;
}

static void felica_dump_reset_key_versions(felica_dump_system_t *system) {
    if (system == NULL) {
        return;
    }

    system->encryption_identifier.has_value = false;
    system->encryption_identifier.value = 0;
    for (size_t i = 0; i < system->node_count; i++) {
        system->nodes[i].des_key_version.has_value = false;
        system->nodes[i].des_key_version.value_le = 0;
        system->nodes[i].aes_key_version.has_value = false;
        system->nodes[i].aes_key_version.value_le = 0;
    }
}

static json_t *felica_dump_key_version_json(uint16_t key_version_le) {
    const uint8_t version_bytes[] = {
        key_version_le & 0xFFU,
        (key_version_le >> 8) & 0xFFU
    };

    return json_string(sprint_hex_inrow(version_bytes, sizeof(version_bytes)));
}

static json_t *felica_dump_encryption_identifier_json(uint8_t encryption_identifier) {
    const felica_encryption_identifier_info_t *encryption_identifier_info =
        felica_encryption_identifier_get_info(encryption_identifier);
    if (encryption_identifier_info) {
        return json_string(encryption_identifier_info->name);
    }

    char encryption_identifier_hex[3] = {0};
    snprintf(encryption_identifier_hex, sizeof(encryption_identifier_hex), "%02X", encryption_identifier);
    return json_string(encryption_identifier_hex);
}

static int felica_dump_json_set_new(json_t *object, const char *key, json_t *value) {
    if (object == NULL || key == NULL || value == NULL) {
        json_decref(value);
        return PM3_EMALLOC;
    }

    const int ret = json_object_set(object, key, value);
    json_decref(value);
    return (ret == 0) ? PM3_SUCCESS : PM3_EMALLOC;
}

static int felica_dump_json_set_hex_or_null(json_t *object, const char *key,
                                            const uint8_t *data, size_t data_len, bool has_value) {
    if (has_value == false) {
        return felica_dump_json_set_new(object, key, json_null());
    }
    if (data == NULL) {
        return PM3_EINVARG;
    }

    return felica_dump_json_set_new(object, key, json_string(sprint_hex_inrow(data, data_len)));
}

static json_t *felica_dump_node_json(const felica_dump_node_t *node) {
    if (node == NULL) {
        return NULL;
    }

    json_t *node_json = json_object();
    json_t *data_json = json_object();
    if (node_json == NULL || data_json == NULL) {
        json_decref(node_json);
        json_decref(data_json);
        return NULL;
    }

    char node_code_hex[9] = {0};
    const uint16_t node_code_be = felica_to_network_order(node->node_code_le);
    if (node->type == FELICA_NODE_TYPE_AREA && node->has_end_code) {
        const uint16_t end_code_be = felica_to_network_order(node->end_code_le);
        snprintf(node_code_hex, sizeof(node_code_hex), "%04X%04X", node_code_be, end_code_be);
    } else {
        snprintf(node_code_hex, sizeof(node_code_hex), "%04X", node_code_be);
    }

    const char *node_type = "service";
    if (node->type == FELICA_NODE_TYPE_SYSTEM) {
        node_type = "system";
    } else if (node->type == FELICA_NODE_TYPE_AREA) {
        node_type = "area";
    }

    if (felica_dump_json_set_new(node_json, "type", json_string(node_type)) != PM3_SUCCESS ||
            felica_dump_json_set_new(node_json, "code", json_string(node_code_hex)) != PM3_SUCCESS ||
            felica_dump_json_set_new(node_json, "des_key_version", node->des_key_version.has_value ? felica_dump_key_version_json(node->des_key_version.value_le) : json_null()) != PM3_SUCCESS ||
            felica_dump_json_set_new(node_json, "aes_key_version", node->aes_key_version.has_value ? felica_dump_key_version_json(node->aes_key_version.value_le) : json_null()) != PM3_SUCCESS) {
        json_decref(data_json);
        json_decref(node_json);
        return NULL;
    }

    for (size_t i = 0; i < node->block_count; i++) {
        char block_number_hex[5] = {0};
        snprintf(block_number_hex, sizeof(block_number_hex), "%04X", node->blocks[i].block_number);
        if (felica_dump_json_set_new(data_json, block_number_hex,
                                     json_string(sprint_hex_inrow(node->blocks[i].data, FELICA_BLK_SIZE))) != PM3_SUCCESS) {
            json_decref(data_json);
            json_decref(node_json);
            return NULL;
        }
    }

    if (json_object_set(node_json, "data", data_json) != 0) {
        json_decref(data_json);
        json_decref(node_json);
        return NULL;
    }
    json_decref(data_json);

    return node_json;
}

static json_t *felica_dump_system_json(const felica_dump_system_t *system) {
    if (system == NULL) {
        return NULL;
    }

    json_t *system_json = json_object();
    json_t *nodes_json = json_array();
    if (system_json == NULL || nodes_json == NULL) {
        json_decref(system_json);
        json_decref(nodes_json);
        return NULL;
    }

    char system_code_hex[5] = {0};
    snprintf(system_code_hex, sizeof(system_code_hex), "%04X", system->system_code);

    if (felica_dump_json_set_new(system_json, "code", json_string(system_code_hex)) != PM3_SUCCESS ||
            felica_dump_json_set_new(system_json, "idm", json_string(sprint_hex_inrow(system->idm, sizeof(system->idm)))) != PM3_SUCCESS ||
            felica_dump_json_set_new(system_json, "pmm", json_string(sprint_hex_inrow(system->pmm, sizeof(system->pmm)))) != PM3_SUCCESS) {
        json_decref(nodes_json);
        json_decref(system_json);
        return NULL;
    }

    if (system->encryption_identifier.has_value) {
        if (felica_dump_json_set_new(system_json, "encryption_identifier",
                                     felica_dump_encryption_identifier_json(system->encryption_identifier.value)) != PM3_SUCCESS) {
            json_decref(nodes_json);
            json_decref(system_json);
            return NULL;
        }
    } else if (felica_dump_json_set_new(system_json, "encryption_identifier", json_null()) != PM3_SUCCESS) {
        json_decref(nodes_json);
        json_decref(system_json);
        return NULL;
    }

    for (size_t i = 0; i < system->node_count; i++) {
        const felica_dump_node_t *node = &system->nodes[i];
        if (node->type == FELICA_NODE_TYPE_SYSTEM &&
                node->des_key_version.has_value == false &&
                node->aes_key_version.has_value == false) {
            continue;
        }

        json_t *node_json = felica_dump_node_json(node);
        if (node_json == NULL) {
            json_decref(nodes_json);
            json_decref(system_json);
            return NULL;
        }
        if (json_array_append(nodes_json, node_json) != 0) {
            json_decref(node_json);
            json_decref(nodes_json);
            json_decref(system_json);
            return NULL;
        }
        json_decref(node_json);
    }

    if (json_object_set(system_json, "nodes", nodes_json) != 0) {
        json_decref(nodes_json);
        json_decref(system_json);
        return NULL;
    }
    json_decref(nodes_json);

    return system_json;
}

static json_t *felica_dump_systems_json(const felica_dump_system_t *systems, size_t system_count,
                                        const felica_dump_metadata_t *metadata) {
    if (systems == NULL) {
        return NULL;
    }

    json_t *root = json_object();
    json_t *systems_json = json_array();
    if (root == NULL || systems_json == NULL) {
        json_decref(root);
        json_decref(systems_json);
        return NULL;
    }

    if (felica_dump_json_set_hex_or_null(root, "specification_version",
                                         metadata ? metadata->specification_version : NULL,
                                         metadata ? metadata->specification_version_len : 0,
                                         metadata && metadata->has_specification_version) != PM3_SUCCESS ||
            felica_dump_json_set_hex_or_null(root, "product_information",
                                             metadata ? metadata->product_information : NULL,
                                             metadata ? metadata->product_information_len : 0,
                                             metadata && metadata->has_product_information) != PM3_SUCCESS ||
            felica_dump_json_set_hex_or_null(root, "container_issue_information",
                                             metadata ? metadata->container_issue_information : NULL,
                                             metadata ? sizeof(metadata->container_issue_information) : 0,
                                             metadata && metadata->has_container_issue_information) != PM3_SUCCESS) {
        json_decref(systems_json);
        json_decref(root);
        return NULL;
    }

    for (size_t i = 0; i < system_count; i++) {
        json_t *system_json = felica_dump_system_json(&systems[i]);
        if (system_json == NULL) {
            json_decref(systems_json);
            json_decref(root);
            return NULL;
        }
        if (json_array_append(systems_json, system_json) != 0) {
            json_decref(system_json);
            json_decref(systems_json);
            json_decref(root);
            return NULL;
        }
        json_decref(system_json);
    }

    if (json_object_set(root, "systems", systems_json) != 0) {
        json_decref(systems_json);
        json_decref(root);
        return NULL;
    }
    json_decref(systems_json);

    return root;
}

static bool felica_dump_specification_version_to_bytes(const felica_request_specification_version_info_t *info,
                                                       uint8_t *data, size_t data_capacity, size_t *data_len) {
    if (info == NULL || data == NULL || data_len == NULL || info->has_specification_version == false) {
        return false;
    }

    *data_len = 0;
    if (info->option_version_count < info->number_of_option) {
        return false;
    }

    const size_t option_bytes = (size_t)info->number_of_option * 2U;
    const size_t payload_len = 4U + option_bytes;
    if (payload_len > data_capacity || option_bytes > sizeof(info->option_version_list)) {
        return false;
    }

    data[0] = info->format_version;
    memcpy(data + 1, info->basic_version, sizeof(info->basic_version));
    data[3] = info->number_of_option;
    memcpy(data + 4, info->option_version_list, option_bytes);
    *data_len = payload_len;
    return true;
}

static void felica_dump_collect_metadata(const uint8_t *idm, felica_dump_metadata_t *metadata) {
    if (idm == NULL || metadata == NULL) {
        return;
    }

    memset(metadata, 0, sizeof(*metadata));
    const uint8_t optional_flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;

    felica_request_specification_version_request_t spec_request;
    memset(&spec_request, 0, sizeof(spec_request));
    spec_request.length[0] = sizeof(spec_request);
    spec_request.command_code[0] = FELICA_REQUEST_SPEC_VERSION_REQ;
    memcpy(spec_request.IDm, idm, sizeof(spec_request.IDm));

    felica_request_specification_version_info_t spec_info;
    if (send_request_specification_version(optional_flags, sizeof(spec_request),
                                           (uint8_t *)&spec_request, false, false,
                                           FELICA_OPTIONAL_CMD_TIMEOUT_MS, FELICA_OPTIONAL_CMD_RETRIES,
                                           &spec_info) == PM3_SUCCESS &&
            felica_dump_specification_version_to_bytes(&spec_info,
                                                       metadata->specification_version,
                                                       sizeof(metadata->specification_version),
                                                       &metadata->specification_version_len)) {
        metadata->has_specification_version = true;
    }

    felica_get_platform_info_request_t product_request;
    memset(&product_request, 0, sizeof(product_request));
    product_request.length[0] = sizeof(product_request);
    product_request.command_code[0] = FELICA_GETPLATFORMINFO_REQ;
    memcpy(product_request.IDm, idm, sizeof(product_request.IDm));

    felica_status_flags_t product_status_flags;
    if (send_get_platform_information(optional_flags,
                                      sizeof(product_request), (uint8_t *)&product_request,
                                      false, &product_status_flags,
                                      metadata->product_information,
                                      sizeof(metadata->product_information),
                                      &metadata->product_information_len) == PM3_SUCCESS &&
            metadata->product_information_len > 0) {
        metadata->has_product_information = true;
    }

    felica_get_container_issue_info_request_t container_issue_request;
    memset(&container_issue_request, 0, sizeof(container_issue_request));
    container_issue_request.length[0] = sizeof(container_issue_request);
    container_issue_request.command_code[0] = FELICA_GET_CONTAINER_ISSUE_INFO_REQ;
    memcpy(container_issue_request.IDm, idm, sizeof(container_issue_request.IDm));

    felica_get_container_issue_info_response_t container_issue_response;
    if (send_get_container_issue_information(optional_flags,
                                             sizeof(container_issue_request), (uint8_t *)&container_issue_request,
                                             false, &container_issue_response) == PM3_SUCCESS) {
        memcpy(metadata->container_issue_information,
               container_issue_response.format_version_carrier_information,
               sizeof(container_issue_response.format_version_carrier_information));
        memcpy(metadata->container_issue_information + sizeof(container_issue_response.format_version_carrier_information),
               container_issue_response.mobile_phone_model_information,
               sizeof(container_issue_response.mobile_phone_model_information));
        metadata->has_container_issue_information = true;
    }
}

static int felica_dump_collect_key_versions_v2(felica_dump_system_t *system, uint8_t flags, uint32_t retry_count) {
    if (system == NULL) {
        return PM3_EINVARG;
    }

    for (size_t processed = 0; processed < system->node_count;) {
        const size_t batch_count = MIN(FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE, system->node_count - processed);
        uint16_t batch_codes[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
        for (size_t i = 0; i < batch_count; i++) {
            batch_codes[i] = system->nodes[processed + i].node_code_le;
        }

        felica_request_service_v2_key_versions_t versions;
        int ret = felica_request_service_v2_key_versions(flags, system->idm, batch_codes, batch_count,
                                                         retry_count, &versions);
        if (ret != PM3_SUCCESS) {
            return ret;
        }

        if (system->encryption_identifier.has_value &&
                system->encryption_identifier.value != versions.encryption_identifier) {
            return PM3_ESOFT;
        }
        system->encryption_identifier.has_value = true;
        system->encryption_identifier.value = versions.encryption_identifier;

        for (size_t i = 0; i < batch_count; i++) {
            felica_dump_node_t *node = &system->nodes[processed + i];
            if (versions.has_aes_key_versions) {
                node->aes_key_version.has_value = true;
                node->aes_key_version.value_le = versions.aes_key_versions_le[i];
            }
            if (versions.has_des_key_versions) {
                node->des_key_version.has_value = true;
                node->des_key_version.value_le = versions.des_key_versions_le[i];
            }
        }

        processed += batch_count;
    }

    return PM3_SUCCESS;
}

static int felica_dump_collect_key_versions_v1(felica_dump_system_t *system, uint8_t flags, uint32_t retry_count) {
    if (system == NULL) {
        return PM3_EINVARG;
    }

    for (size_t processed = 0; processed < system->node_count;) {
        const size_t batch_count = MIN(FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE, system->node_count - processed);
        uint16_t batch_codes[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
        uint16_t key_versions[FELICA_REQUEST_SERVICE_DISCOVERY_BATCH_SIZE] = {0};
        for (size_t i = 0; i < batch_count; i++) {
            batch_codes[i] = system->nodes[processed + i].node_code_le;
        }

        size_t returned_nodes = 0;
        int ret = felica_request_service_key_versions(flags, system->idm, batch_codes, batch_count,
                                                      retry_count, key_versions, &returned_nodes);
        if (ret != PM3_SUCCESS) {
            return ret;
        }

        if (returned_nodes < batch_count) {
            return PM3_ESOFT;
        }

        for (size_t i = 0; i < batch_count; i++) {
            felica_dump_node_t *node = &system->nodes[processed + i];
            node->des_key_version.has_value = true;
            node->des_key_version.value_le = key_versions[i];
        }

        processed += batch_count;
    }

    return PM3_SUCCESS;
}

static int felica_dump_collect_key_versions(felica_dump_system_t *system, uint32_t retry_count) {
    if (system == NULL) {
        return PM3_EINVARG;
    }

    if (system->node_count == 0) {
        return PM3_SUCCESS;
    }

    uint8_t flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    int ret = send_polling(flags, system->system_code, FELICA_POLL_REQUEST_NO_DATA,
                           FELICA_POLL_TIMEOUT_MS, retry_count, false,
                           system->idm, system->pmm, NULL);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Unable to poll system " _YELLOW_("%04X") " for key versions.", system->system_code);
        return ret;
    }

    PrintAndLogEx(INFO, "Collecting key versions for system " _YELLOW_("%04X") "...", system->system_code);
    ret = felica_dump_collect_key_versions_v2(system, flags, retry_count);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RequestServiceV2 key versions collected for system " _YELLOW_("%04X") ".", system->system_code);
        return PM3_SUCCESS;
    }

    felica_dump_reset_key_versions(system);

    PrintAndLogEx(INFO, "RequestServiceV2 unavailable for system " _YELLOW_("%04X") "; trying RequestService.", system->system_code);
    ret = felica_dump_collect_key_versions_v1(system, flags, retry_count);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RequestService key versions collected for system " _YELLOW_("%04X") ".", system->system_code);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(WARNING, "Unable to collect key versions for system " _YELLOW_("%04X") ".", system->system_code);
    return ret;
}

static int felica_dump_discovery_visitor(const felica_discovered_node_t *node, void *ctx) {
    if (node == NULL || ctx == NULL) {
        return PM3_EINVARG;
    }

    felica_dump_context_t *dump_ctx = (felica_dump_context_t *)ctx;
    if (dump_ctx->flags == NULL) {
        return PM3_EINVARG;
    }

    felica_dump_node_t *dump_node = NULL;
    if (dump_ctx->system) {
        dump_node = felica_dump_system_add_node(dump_ctx->system, node);
        if (dump_node == NULL) {
            return PM3_EMALLOC;
        }
    }

    if (node->type != FELICA_NODE_TYPE_SERVICE) {
        return PM3_SUCCESS;
    }

    dump_ctx->service_count++;

    char attrib_str[64] = {0};
    const bool is_public = felica_format_service_attribute(node->node_code_le, attrib_str, sizeof(attrib_str));
    PrintAndLogEx(INFO, "Service %04X %s", felica_to_network_order(node->node_code_le), attrib_str);

    if (is_public == false) {
        return PM3_SUCCESS;
    }

    if ((node->node_code_le & FELICA_SERVICE_ATTRIBUTE_PIN_REQUIRED) != 0) {
        PrintAndLogEx(INFO, " PIN protected; skipping unauthenticated read.");
        return PM3_SUCCESS;
    }

    dump_ctx->public_service_count++;

    PrintAndLogEx(INFO, " block | data  ");
    PrintAndLogEx(INFO, "-------+----------------------------------------");

    dump_ctx->block_frame[11] = node->node_code_le & 0xFF;
    dump_ctx->block_frame[12] = (node->node_code_le >> 8) & 0xFF;

    for (uint16_t block = 0x00; block <= 0xFF; block++) {
        if (kbd_enter_pressed()) {
            return PM3_EOPABORTED;
        }

        bool read_success = false;
        int ret = felica_dump_try_read_service_block(dump_ctx, dump_node, block, &read_success);
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        if (read_success == false) {
            break;
        }
    }

    if (felica_is_lite_assumed_node(node->node_code_le)) {
        for (size_t i = 0; i < ARRAYLEN(FELICA_LITE_DUMP_EXTRA_BLOCKS); i++) {
            const uint16_t block = FELICA_LITE_DUMP_EXTRA_BLOCKS[i];
            if (dump_node && felica_dump_node_has_block(dump_node, block)) {
                continue;
            }
            if (kbd_enter_pressed()) {
                return PM3_EOPABORTED;
            }

            bool read_success = false;
            int ret = felica_dump_try_read_service_block(dump_ctx, dump_node, block, &read_success);
            if (ret != PM3_SUCCESS) {
                return ret;
            }
        }
    }

    return PM3_SUCCESS;
}

static int felica_dump_single_system(const felica_discovered_system_t *system,
                                     felica_dump_system_t *dump_system,
                                     uint32_t retry_count,
                                     uint32_t *discovered_nodes_out,
                                     uint32_t *service_count_out,
                                     uint32_t *public_service_count_out) {
    if (system == NULL || dump_system == NULL || discovered_nodes_out == NULL || service_count_out == NULL || public_service_count_out == NULL) {
        return PM3_EINVARG;
    }

    *discovered_nodes_out = 0;
    *service_count_out = 0;
    *public_service_count_out = 0;
    memset(dump_system, 0, sizeof(*dump_system));
    dump_system->system_code = system->system_code;

    const json_t *system_annotation = felica_find_system_annotation(system->system_code);
    const char *system_name = felica_get_json_string(system_annotation, "name");
    if (system_name) {
        PrintAndLogEx(INFO, "--- " _CYAN_("System %04X") " (%s) ---------------------------", system->system_code, system_name);
    } else {
        PrintAndLogEx(INFO, "--- " _CYAN_("System %04X") " ---------------------------", system->system_code);
    }

    uint8_t flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    uint8_t idm[8] = {0};
    uint8_t pmm[8] = {0};
    if (send_polling(flags, system->system_code, FELICA_POLL_REQUEST_NO_DATA,
                     FELICA_POLL_TIMEOUT_MS, retry_count, false,
                     idm, pmm, NULL) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to poll system " _YELLOW_("%04X") ".", system->system_code);
        return PM3_ERFTRANS;
    }

    felica_drop_connect_flag(&flags);
    memcpy(dump_system->idm, idm, sizeof(dump_system->idm));
    memcpy(dump_system->pmm, pmm, sizeof(dump_system->pmm));
    PrintAndLogEx(INFO, "IDm............ " _YELLOW_("%s"), sprint_hex_inrow(idm, sizeof(idm)));

    felica_dump_context_t dump_ctx;
    memset(&dump_ctx, 0, sizeof(dump_ctx));
    dump_ctx.flags = &flags;
    dump_ctx.system = dump_system;
    dump_ctx.retry_count = retry_count;
    dump_ctx.block_datalen = 16;
    dump_ctx.block_frame[0] = dump_ctx.block_datalen;
    dump_ctx.block_frame[1] = FELICA_RDBLK_REQ;
    memcpy(dump_ctx.block_frame + 2, idm, sizeof(idm));
    dump_ctx.block_frame[10] = 0x01;
    dump_ctx.block_frame[13] = 0x01;
    dump_ctx.block_frame[14] = 0x80;

    uint32_t discovered_nodes = 0;
    int ret = felica_discover_nodes(idm, pmm, &flags, retry_count,
                                    FELICA_NODE_DISCOVERY_NONE,
                                    felica_dump_discovery_visitor, &dump_ctx,
                                    NULL, &discovered_nodes);

    if (ret == PM3_EOPABORTED) {
        *discovered_nodes_out = discovered_nodes;
        *service_count_out = dump_ctx.service_count;
        *public_service_count_out = dump_ctx.public_service_count;
        PrintAndLogEx(WARNING, "Unauth service dump aborted by user. Discovered %" PRIu32 " node(s), visited %" PRIu32 " service(s), dumped %" PRIu32 " public service(s).",
                      discovered_nodes, dump_ctx.service_count, dump_ctx.public_service_count);
        return ret;
    }

    if (ret != PM3_SUCCESS) {
        *discovered_nodes_out = discovered_nodes;
        *service_count_out = dump_ctx.service_count;
        *public_service_count_out = dump_ctx.public_service_count;
        PrintAndLogEx(FAILED, "Unable to discover nodes using RequestCodeList/SearchServiceCode/RequestService/ReadWithoutEncryption.");
        return ret;
    }

    *discovered_nodes_out = discovered_nodes;
    *service_count_out = dump_ctx.service_count;
    *public_service_count_out = dump_ctx.public_service_count;

    PrintAndLogEx(SUCCESS, "System dump complete. Discovered %" PRIu32 " node(s), visited %" PRIu32 " service(s), dumped %" PRIu32 " public service(s).",
                  discovered_nodes, dump_ctx.service_count, dump_ctx.public_service_count);

    return PM3_SUCCESS;
}

/**
 * Sends a write_without_encryption frame to pm3 and stores the response.
 * @param flags to use for pm3 communication.
 * @param datalen frame length.
 * @param data frame to be sent.
 * @param verbose display additional output.
 * @param wr_resp frame in which the response will be saved.
 * @return success if response was received.
 */
static int send_write_without_encryption(uint8_t flags, uint16_t datalen, uint8_t *data, bool verbose, felica_status_response_t *wr_resp) {
    PacketResponseNG resp;
    if (send_felica_payload_with_retries(flags, datalen, data, verbose,
                                         -1,
                                         FELICA_DEFAULT_TIMEOUT_MS, 0,
                                         0, true,
                                         &resp, "write block") != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    memcpy(wr_resp, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
    return PM3_SUCCESS;
}

/**
 * Reverses the master secret. Example: AA AA AA AA AA AA AA BB to BB AA AA AA AA AA AA AA
 * @param master_key the secret which order will be reversed.
 * @param length in bytes of the master secret.
 * @param reverse_master_key output in which the reversed secret is stored.
 */
static void reverse_3des_key(const uint8_t *master_key, int length, uint8_t *reverse_master_key) {
    for (int i = 0; i < length; i++) {
        reverse_master_key[i] = master_key[(length - 1) - i];
    }
}

/**
 * Command parser for auth1
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthentication1(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica auth1",
                  "Initiate mutual authentication. This command must always be executed before Auth2 command\n"
                  "and mutual authentication is achieve only after Auth2 command has succeeded.\n"
                  _RED_("INCOMPLETE / EXPERIMENTAL COMMAND!!!"),
                  "hf felica auth1 --an 01 --acl 0000 --sn 01 --scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                  "hf felica auth1 --an 01 --acl 0000 --sn 01 --scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA\n"
                  "hf felica auth1 --idm 11100910C11BC407 --an 01 --acl 0000 --sn 01 ..scl 8B00 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "an",  "<hex>", "number of areas, 1 byte"),
        arg_str0(NULL, "acl", "<hex>", "area code list, 2 bytes"),
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0(NULL, "sn",  "<hex>", "number of service, 1 byte"),
        arg_str0(NULL, "scl", "<hex>", "service code list, 2 bytes"),
        arg_str0("k", "key",  "<hex>", "3des key, 16 bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t an[1] = {0};
    int anlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), an, sizeof(an), &anlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t acl[2] = {0};
    int acllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), acl, sizeof(acl), &acllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[24] = {0};
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);
    if (verbose) {
        print_authentication1();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    // Length (1),
    // Command ID (1),
    // IDm (8),
    // Number of Area (1),
    // Area Code List (2),
    // Number of Service (1),
    // Service Code List (2),
    // M1c (16)
    uint16_t datalen = 32;
    data[0] = (datalen & 0xFF);
    data[1] = 0x10; // Command ID

    uint8_t resolved_idm[8] = {0};
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, resolved_idm);
    if (res != PM3_SUCCESS) {
        return res;
    }
    memcpy(data + 2, resolved_idm, sizeof(resolved_idm));

    if (anlen) {
        data[10] = an[0];
    }
    if (acllen) {
        data[11] = acl[0];
        data[12] = acl[1];
    }
    if (snlen) {
        data[13] = sn[0];
    }
    if (scllen) {
        data[14] = scl[0];
        data[15] = scl[1];
    }
    if (keylen) {
        memcpy(data + 16, key, keylen);
    }

    // READER CHALLENGE - (RANDOM To Encrypt = Rac)
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    PrintAndLogEx(INFO, "Reader challenge (unencrypted): %s", sprint_hex(nonce, 8));

    // Create M1c Challenge with 3DES (3 Keys = 24, 2 Keys = 16)
    uint8_t master_key[24] = {0};
    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);

    if (keylen == 24) {

        mbedtls_des3_set3key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, keylen));

    } else if (keylen == 16) {

        // Assumption: Master secret split in half for Kac, Kbc
        mbedtls_des3_set2key_enc(&des3_ctx, master_key);
        PrintAndLogEx(INFO, "3DES Master Secret: %s", sprint_hex(master_key, keylen));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        mbedtls_des3_free(&des3_ctx);
        return PM3_EINVARG;
    }

    uint8_t output[8];
    mbedtls_des3_crypt_ecb(&des3_ctx, nonce, output);
    mbedtls_des3_free(&des3_ctx);

    PrintAndLogEx(INFO, "3DES ENCRYPTED M1c: %s", sprint_hex(output, sizeof(output)));

    // Add M1c Challenge to frame
    memcpy(data + 16, output, sizeof(output));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "Client send AUTH1 frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, false);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    felica_auth1_response_t auth1_response;
    memcpy(&auth1_response, (felica_auth1_response_t *)resp.data.asBytes, sizeof(felica_auth1_response_t));

    if (auth1_response.frame_response.cmd_code[0] != 0x11) {
        PrintAndLogEx(ERR, "response code does not match");
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Auth1 response:");
    PrintAndLogEx(SUCCESS, "IDm... %s", sprint_hex(auth1_response.frame_response.IDm, sizeof(auth1_response.frame_response.IDm)));
    PrintAndLogEx(SUCCESS, "M2C... %s", sprint_hex(auth1_response.m2c, sizeof(auth1_response.m2c)));
    PrintAndLogEx(SUCCESS, "M3C... %s", sprint_hex(auth1_response.m3c, sizeof(auth1_response.m3c)));


    mbedtls_des3_init(&des3_ctx);

    // Assumption: Key swap method used
    uint8_t rev_master_key[16];
    reverse_3des_key(master_key, 16, rev_master_key);
    mbedtls_des3_set2key_dec(&des3_ctx, rev_master_key);

    uint8_t p2c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx, auth1_response.m2c, p2c);
    mbedtls_des3_free(&des3_ctx);

    bool is_key_correct = memcmp(p2c, nonce, sizeof(nonce)) == 0;

    if (is_key_correct) {
        PrintAndLogEx(SUCCESS, "Auth1 done with correct key material!");
        PrintAndLogEx(SUCCESS, "Use Auth2 now with M3C and same key");
    } else {
        PrintAndLogEx(INFO, "3DES secret (swapped decryption): %s", sprint_hex(rev_master_key, 16));
        PrintAndLogEx(INFO, "P2c: %s", sprint_hex(p2c, 8));
        PrintAndLogEx(ERR, "Can't decrypt M2C with master secret (P1c != P2c)!");
        PrintAndLogEx(ERR, "Probably wrong keys or wrong decryption method");
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for auth2
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthentication2(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica auth2",
                  "Complete mutual authentication. This command can only be executed subsquent to Auth1\n"
                  _RED_("INCOMPLETE / EXPERIMENTAL COMMAND!!!\n")
                  _RED_("EXPERIMENTAL COMMAND - M2c/P2c will be not checked"),
                  "hf felica auth2 --cc 0102030405060708 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                  "hf felica auth2 --idm 11100910C11BC407 --cc 0102030405060708 --key AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0("c", "cc", "<hex>", "M3c card challenge, 8 bytes"),
        arg_str0("k", "key",  "<hex>", "3des M3c decryption key, 16 bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t cc[8] = {0};
    int cclen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), cc, sizeof(cc), &cclen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[16] = {0};
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    if (verbose) {
        print_authentication2();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    uint16_t datalen = 18; // Length (1), Command ID (1), IDm (8), M4c (8)
    data[0] = (datalen & 0xFF);
    data[1] = 0x12; // Command ID

    uint8_t resolved_idm[8] = {0};
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_CHAINED, resolved_idm);
    if (res != PM3_SUCCESS) {
        return res;
    }
    memcpy(data + 2, resolved_idm, sizeof(resolved_idm));

    if (cclen) {
        memcpy(data + 16, cc, cclen);
    }

    if (keylen) {
        memcpy(data + 16, key, keylen);
    }

    // M3c (8) == cc
//    unsigned char m3c[8];  == cc


    mbedtls_des3_context des3_ctx_enc;
    mbedtls_des3_context des3_ctx_dec;

    mbedtls_des3_init(&des3_ctx_enc);
    mbedtls_des3_init(&des3_ctx_dec);

    if (keylen == 16) {

        // set encryption context
        mbedtls_des3_set2key_enc(&des3_ctx_enc, key);

        // Create M4c challenge response with 3DES
        uint8_t rev_key[16];
        reverse_3des_key(key, sizeof(key), rev_key);

        // set decryption context
        mbedtls_des3_set2key_dec(&des3_ctx_dec, rev_key);

        // Assumption: Key swap method used for E2
        PrintAndLogEx(INFO, "3DES Master Secret (encryption)... %s", sprint_hex_inrow(key, sizeof(key)));
        PrintAndLogEx(INFO, "3DES Master Secret (decryption)... %s", sprint_hex_inrow(rev_key, sizeof(rev_key)));
    } else {
        PrintAndLogEx(ERR, "Invalid key length");
        mbedtls_des3_free(&des3_ctx_enc);
        mbedtls_des3_free(&des3_ctx_dec);
        return PM3_EINVARG;
    }

    // Decrypt m3c with reverse_master_key
    unsigned char p3c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx_dec, cc, p3c);
    PrintAndLogEx(INFO, "3DES decrypted M3c = P3c... %s", sprint_hex_inrow(p3c, sizeof(p3c)));

    // Encrypt p3c with master_key
    unsigned char m4c[8];
    mbedtls_des3_crypt_ecb(&des3_ctx_enc, p3c, m4c);
    PrintAndLogEx(INFO, "3DES encrypted M4c......... %s", sprint_hex_inrow(m4c, sizeof(m4c)));

    // free contexts
    mbedtls_des3_free(&des3_ctx_enc);
    mbedtls_des3_free(&des3_ctx_dec);

    // Add M4c Challenge to frame
    memcpy(data + 10, m4c, sizeof(m4c));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "Client Send AUTH2 Frame: %s", sprint_hex(data, datalen));
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "no response from card");
        return PM3_ERFTRANS;
    }

    felica_auth2_response_t auth2_response;
    memcpy(&auth2_response, (felica_auth2_response_t *)resp.data.asBytes, sizeof(felica_auth2_response_t));
    if (auth2_response.code[0] != 0x12) {
        PrintAndLogEx(SUCCESS, "Auth2 response:");
        PrintAndLogEx(SUCCESS, "IDtc.............. %s", sprint_hex(auth2_response.IDtc, sizeof(auth2_response.IDtc)));
        PrintAndLogEx(SUCCESS, "IDi (encrypted)... %s", sprint_hex(auth2_response.IDi, sizeof(auth2_response.IDi)));
        PrintAndLogEx(SUCCESS, "PMi (encrypted)... %s", sprint_hex(auth2_response.PMi, sizeof(auth2_response.PMi)));
    } else {
        PrintAndLogEx(ERR, "Got wrong frame format");
    }
    return PM3_SUCCESS;
}


/**
 * Command parser for wrunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaWritePlain(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica wrbl",
                  "Use this command to write block data to authentication-not-required Service.\n\n"
                  " - Mode shall be Mode0.\n"
                  " - Un-/Ssuccessful == Status Flag1 and Flag2",
                  "hf felica wrbl --sn 01 --scl CB10 --bn 01 --ble 8001 -d 0102030405060708090A0B0C0D0E0F10\n"
                  "hf felica wrbl --idm 01100910c11bc407 --sn 01 --scl CB10 --bn 01 --ble 8001 -d 0102030405060708090A0B0C0D0E0F10\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "data, 16 hex bytes"),
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0(NULL, "sn",  "<hex>", "number of service"),
        arg_str0(NULL, "scl", "<hex>", "service code list"),
        arg_str0(NULL, "bn",  "<hex>", "number of block"),
        arg_str0(NULL, "ble", "<hex>", "block list element (def 2|3 bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t userdata[16] = {0};
    int udlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), userdata, sizeof(userdata), &udlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t bn[1] = {0};
    int bnlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), bn, sizeof(bn), &bnlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t ble[3] = {0};
    int blelen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), ble, sizeof(ble), &blelen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (verbose) {
        print_number_of_service_constraints();
        print_number_of_block_constraints();
        print_service_code_list_constraints();
        print_block_list_element_constraints();
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x20; // Static length
    data[1] = 0x08; // Command ID

    // Length (1)
    // Command ID (1)
    // IDm (8)
    // Number of Service (1)
    // Service Code List(2)
    // Number of Block(1)
    // Block List(3)
    // Block Data(16)

    uint16_t datalen = 32; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3), Block Data(16)
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, data + 2);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (blelen == 3) {
        datalen++;
    }

    // Number of Service 1, Service Code List 2, Number of Block 1, Block List Element 2, Data 16

    // Service Number 1 byte
    if (snlen) {
        data[10] = sn[0];
    }
    // Service Code List 2 bytes
    if (scllen) {
        data[11] = scl[0];
        data[12] = scl[1];
    }

    // Block number 1 byte
    if (bnlen) {
        data[13] = bn[0];
    }

    // Block List Element 2|3 bytes
    if (blelen) {
        memcpy(data + 14, ble, blelen);
    }

    // data to be written, 16 bytes
    if (udlen) {
        memcpy(data + 14 + blelen, userdata, sizeof(userdata));
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    felica_status_response_t wr_noCry_resp;
    if (send_write_without_encryption(flags, datalen, data, 1, &wr_noCry_resp) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "IDm............ %s", sprint_hex(wr_noCry_resp.frame_response.IDm, sizeof(wr_noCry_resp.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1... %s", sprint_hex(wr_noCry_resp.status_flags.status_flag1, sizeof(wr_noCry_resp.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2... %s\n", sprint_hex(wr_noCry_resp.status_flags.status_flag2, sizeof(wr_noCry_resp.status_flags.status_flag2)));
        if (wr_noCry_resp.status_flags.status_flag1[0] == 0x00 && wr_noCry_resp.status_flags.status_flag2[0] == 0x00) {
            PrintAndLogEx(SUCCESS, "Writing data successful!");
        } else {
            PrintAndLogEx(FAILED, "Something went wrong! Check status flags.");
        }
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rdunencrypted.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaReadPlain(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rdbl",
                  "Use this command to read block data from authentication-not-required Service.\n\n"
                  " - Mode shall be Mode0.\n"
                  " - Successful == block data\n"
                  " - Unsuccessful == Status Flag1 and Flag2",
                  "hf felica rdbl --sn 01 --scl 8B00 --bn 01 --ble 8000\n"
                  "hf felica rdbl --sn 01 --scl 4B18 --bn 01 --ble 8000 -b\n"
                  "hf felica rdbl --idm 01100910c11bc407 --sn 01 --scl 8B00 --bn 01 --ble 8000\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("b", NULL, "get all block list elements 00 -> FF"),
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_lit0("l", "long", "use 3 byte block list element block number"),
        arg_str0(NULL, "sn",  "<hex>", "number of service"),
        arg_str0(NULL, "scl", "<hex>", "service code list"),
        arg_str0(NULL, "bn",  "<hex>", "number of block"),
        arg_str0(NULL, "ble", "<hex>", "block list element (def 2|3 bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool all_block_list_elements = arg_get_lit(ctx, 1);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t long_block_numbers = arg_get_lit(ctx, 3);

    uint8_t sn[1] = {0};
    int snlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), sn, sizeof(sn), &snlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t scl[2] = {0};
    int scllen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 5), scl, sizeof(scl), &scllen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t bn[1] = {0};
    int bnlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 6), bn, sizeof(bn), &bnlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t ble[3] = {0};
    int blelen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 7), ble, sizeof(ble), &blelen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);
    if (verbose) {
        print_number_of_service_constraints();
        print_number_of_block_constraints();
        print_service_code_list_constraints();
        print_block_list_element_constraints();
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
        return PM3_SUCCESS;
    }

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x10; // Static length
    data[1] = 0x06; // Command ID

    uint16_t datalen = 16; // Length (1), Command ID (1), IDm (8), Number of Service (1), Service Code List(2), Number of Block(1), Block List(3)
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, data + 2);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (long_block_numbers) {
        datalen++;
    }

    // Number of Service 1, Service Code List 2, Number of Block 1, Block List Element 2|3
    if (snlen) {
        data[10] = sn[0];
    }
    if (scllen) {
        data[11] = scl[0];
        data[12] = scl[1];
    }
    if (bnlen) {
        data[13] = bn[0];
    }
    if (blelen)
        memcpy(data + 14, ble, blelen);

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    PrintAndLogEx(INFO, "block | data  ");
    PrintAndLogEx(INFO, "------+----------------------------------------");

    // main loop block reads
    if (all_block_list_elements) {

        const uint32_t last_blockno = long_block_numbers ? 0xFFFFU : 0xFFU;

        for (uint32_t i = 0x00; i <= last_blockno; i++) {
            if (long_block_numbers) {
                data[14] &= 0x7FU;
                data[15] = (uint8_t)(i & 0xFFU);
                data[16] = (uint8_t)((i >> 8) & 0xFFU);
            } else {
                data[14] |= 0x80U;
                data[15] = (uint8_t)(i & 0xFFU);
            }
            felica_read_without_encryption_response_t rd_noCry_resp;
            if ((send_read_without_encryption(flags, datalen, data, 0, &rd_noCry_resp) == PM3_SUCCESS)) {
                print_read_without_encryption_response(&rd_noCry_resp, (uint16_t)i);
            } else {
                break;
            }
        }
    } else {
        felica_read_without_encryption_response_t rd_noCry_resp;
        if (send_read_without_encryption(flags, datalen, data, 1, &rd_noCry_resp) == PM3_SUCCESS) {
            print_read_without_encryption_response(&rd_noCry_resp, bnlen ? bn[0] : 0);
        }
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqresponse
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestResponse(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqresponse",
                  "Use this command to verify the existence of a card and its Mode.\n"
                  " - current mode of the card is returned",
                  "hf felica rqresponse --idm 11100910C11BC407\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0A; // Static length
    data[1] = 0x04; // Command ID

    uint8_t datalen = 10; // Length (1), Command ID (1), IDm (8)
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, data + 2);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);
    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_request_request_response_t rq_response;
    memcpy(&rq_response, (felica_request_request_response_t *)resp.data.asBytes, sizeof(felica_request_request_response_t));
    if (rq_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Request Response");
        PrintAndLogEx(SUCCESS, "IDm...... %s", sprint_hex(rq_response.frame_response.IDm, sizeof(rq_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "  Mode... %s", sprint_hex(rq_response.mode, sizeof(rq_response.mode)));
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqspecver
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSpecificationVersion(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqspecver",
                  "Use this command to acquire the version of card OS.\n"
                  "Response:\n"
                  " - Format version: Fixed value 00h. Provided only if Status Flag1 = 00h\n"
                  " - Basic version: Each value of version is expressed in BCD notation. Provided only if Status Flag1 = 00h\n"
                  " - Number of Option: number of entries in Option Version List.\n"
                  " - Option version list: BCD notation (major.minor.patch), little-endian, provided only if Status Flag1 = 00h",

                  "hf felica rqspecver\n"
                  "hf felica rqspecver -r 0001\n"
                  "hf felica rqspecver --idm 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0("r", NULL, "<hex>", "set custom reserve"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t reserved[2] = {0, 0};
    int rlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), reserved, sizeof(reserved), &rlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 3);
    if (verbose) {
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
    }
    CLIParserFree(ctx);

    felica_request_specification_version_request_t request_specification_version_request;
    memset(&request_specification_version_request, 0, sizeof(request_specification_version_request));
    request_specification_version_request.length[0] = sizeof(request_specification_version_request);
    request_specification_version_request.command_code[0] = FELICA_REQUEST_SPEC_VERSION_REQ;

    if (rlen) {
        memcpy(request_specification_version_request.reserved, reserved, sizeof(reserved));
    }

    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE,
                                       request_specification_version_request.IDm);
    if (res != PM3_SUCCESS) {
        return res;
    }

    felica_request_specification_version_info_t specification_version_info;
    uint8_t flags = FELICA_APPEND_CRC | FELICA_RAW;
    if (send_request_specification_version(flags, sizeof(request_specification_version_request),
                                           (uint8_t *)&request_specification_version_request,
                                           verbose,
                                           true, FELICA_DEFAULT_TIMEOUT_MS, 0,
                                           &specification_version_info) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Got no response from card");
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Got Request Response");
    PrintAndLogEx(SUCCESS, "IDm............ %s",
                  sprint_hex(request_specification_version_request.IDm, sizeof(request_specification_version_request.IDm)));
    PrintAndLogEx(SUCCESS, "Status Flag1... %s",
                  sprint_hex(specification_version_info.status_flags.status_flag1,
                             sizeof(specification_version_info.status_flags.status_flag1)));
    PrintAndLogEx(SUCCESS, "Status Flag2... %s",
                  sprint_hex(specification_version_info.status_flags.status_flag2,
                             sizeof(specification_version_info.status_flags.status_flag2)));

    if (specification_version_info.has_specification_version) {
        print_specification_versions(SUCCESS, &specification_version_info, true);

        if (specification_version_info.option_version_count < specification_version_info.number_of_option) {
            PrintAndLogEx(WARNING, "Truncated Option Version List: card returned %u entries, showing %zu",
                          specification_version_info.number_of_option,
                          specification_version_info.option_version_count);
        }
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for resetmode
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaResetMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica resetmode",
                  "Use this command to reset Mode to Mode 0.",
                  "hf felica resetmode\n"
                  "hf felica resetmode -r 0001\n"
                  "hf felica resetmode --idm 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0("r", NULL, "<hex>", "set custom reserve"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t reserved[2] = {0, 0};
    int rlen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), reserved, sizeof(reserved), &rlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 3);
    if (verbose) {
        print_status_flag1_interpretation();
        print_status_flag2_interpration();
    }
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));
    data[0] = 0x0C; // Static length
    data[1] = 0x3E; // Command ID

    if (rlen) {
        memcpy(data + 10, reserved, 2);
    } else {
        data[10] = 0x00; // Reserved Value
        data[11] = 0x00; // Reserved Value
    }

    uint16_t datalen = 12; // Length (1), Command ID (1), IDm (8), Reserved (2)
    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, data + 2);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    clear_and_send_command(flags, datalen, data, 0);

    PacketResponseNG resp;
    if (waitCmdFelica(false, &resp, true) == false) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    felica_status_response_t reset_mode_response;
    memcpy(&reset_mode_response, (felica_status_response_t *)resp.data.asBytes, sizeof(felica_status_response_t));
    if (reset_mode_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(SUCCESS, "Request Response");
        PrintAndLogEx(SUCCESS, "IDm............ %s", sprint_hex(reset_mode_response.frame_response.IDm, sizeof(reset_mode_response.frame_response.IDm)));
        PrintAndLogEx(SUCCESS, "Status Flag1... %s", sprint_hex(reset_mode_response.status_flags.status_flag1, sizeof(reset_mode_response.status_flags.status_flag1)));
        PrintAndLogEx(SUCCESS, "Status Flag2... %s", sprint_hex(reset_mode_response.status_flags.status_flag2, sizeof(reset_mode_response.status_flags.status_flag2)));
    }
    return PM3_SUCCESS;
}

/**
 * Command parser for rqsyscode
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestSystemCode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqsyscode",
                  "Use this command to acquire System Code registered to the card."
                  "  - if a card is divided into more than one System, \n"
                  "    this command acquires System Code of each System existing in the card.",
                  "hf felica rqsyscode\n"
                  "hf felica rqsyscode --idm 11100910C11BC407 \n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);


    felica_request_system_code_request_t request_system_code_request;
    memset(&request_system_code_request, 0, sizeof(request_system_code_request));
    request_system_code_request.length[0] = sizeof(request_system_code_request);
    request_system_code_request.command_code[0] = FELICA_REQSYSCODE_REQ;

    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, request_system_code_request.IDm);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);
    felica_syscode_response_t system_code_response;
    if (send_request_system_code(flags,
                                 sizeof(request_system_code_request), (uint8_t *)&request_system_code_request,
                                 false,
                                 FELICA_DEFAULT_TIMEOUT_MS, FELICA_REQUEST_SYSTEM_CODE_ATTEMPTS - 1U, true,
                                 &system_code_response) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Got no response from card");
        return PM3_ERFTRANS;
    }

    if (system_code_response.frame_response.IDm[0] != 0) {
        PrintAndLogEx(INFO, "Systems........ " _GREEN_("%u"), system_code_response.number_of_systems[0]);

        for (size_t i = 0; i < system_code_response.number_of_systems[0]; i++) {
            felica_print_system_code_annotation(INFO, system_code_response.system_code_list + (i * 2));
        }
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica dump",
                  "Dump all existing Area Code and Service Code.\n"
                  "Only works on services that do not require authentication yet.\n",
                  "hf felica dump\n"
                  "hf felica dump --retry 5\n"
                  "hf felica dump --idm 11100910C11BC407\n"
                  "hf felica dump -f my-felica-dump");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "no-auth", "read public services"),
        arg_u64_0("r", "retry", "<dec>", "number of retries"),
        arg_str0(NULL, "idm", "<hex>", "use custom IDm"),
        arg_str0("f", "file", "<fn>", "Specify a filename for JSON dump file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t retry_count = arg_get_u32_def(ctx, 2, FELICA_DEFAULT_RETRY_COUNT);
    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    char filename[FILE_PATH_SIZE] = {0};
    int fnlen = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);
    if (res) {
        return PM3_EINVARG;
    }

    // bool no_auth = arg_get_lit(ctx, 1);

    const uint64_t dump_started_ms = msclock();
    res = felica_select_target_keep_field(idm, (size_t)ilen, idm);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to abort discovery or dumping");

    felica_dump_metadata_t dump_metadata;
    felica_dump_collect_metadata(idm, &dump_metadata);

    uint8_t system_flags = FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    felica_discovered_system_list_t discovered_systems;
    res = discover_systems(system_flags, idm, true, retry_count, &discovered_systems);
    if (res != PM3_SUCCESS || discovered_systems.count == 0) {
        DropField();
        PrintAndLogEx(FAILED, "Unable to discover FeliCa systems.");
        return res;
    }

    PrintAndLogEx(INFO, "Discovered " _GREEN_("%u") " system(s).", (unsigned int)discovered_systems.count);

    uint32_t total_discovered_nodes = 0;
    uint32_t total_service_count = 0;
    uint32_t total_public_service_count = 0;
    int final_ret = PM3_SUCCESS;
    felica_dump_system_t dump_systems[FELICA_DISCOVERED_SYSTEM_MAX_COUNT] = {0};
    size_t dump_system_count = 0;

    for (size_t i = 0; i < discovered_systems.count; i++) {
        uint32_t discovered_nodes = 0;
        uint32_t service_count = 0;
        uint32_t public_service_count = 0;
        felica_dump_system_t *dump_system = &dump_systems[dump_system_count];
        const int ret = felica_dump_single_system(&discovered_systems.systems[i], dump_system,
                                                  retry_count, &discovered_nodes, &service_count, &public_service_count);

        if (ret == PM3_EOPABORTED) {
            DropField();
            felica_dump_system_free(dump_system);
            felica_dump_systems_free(dump_systems, dump_system_count);
            return ret;
        }

        if (ret != PM3_SUCCESS) {
            final_ret = ret;
            felica_dump_system_free(dump_system);
            continue;
        }

        dump_system_count++;
        total_discovered_nodes += discovered_nodes;
        total_service_count += service_count;
        total_public_service_count += public_service_count;
    }

    for (size_t i = 0; i < dump_system_count; i++) {
        (void)felica_dump_collect_key_versions(&dump_systems[i], retry_count);
    }

    DropField();

    if (dump_system_count == 0) {
        felica_dump_systems_free(dump_systems, dump_system_count);
        return final_ret;
    }

    if (fnlen == 0) {
        snprintf(filename, sizeof(filename), "hf-felica-%s-dump", sprint_hex_inrow(idm, sizeof(idm)));
    }

    json_t *root = felica_dump_systems_json(dump_systems, dump_system_count, &dump_metadata);
    if (root == NULL) {
        felica_dump_systems_free(dump_systems, dump_system_count);
        return PM3_EMALLOC;
    }

    int save_res = saveFileJSONroot(filename, root, JSON_INDENT(2), true);
    json_decref(root);
    felica_dump_systems_free(dump_systems, dump_system_count);
    if (save_res != PM3_SUCCESS) {
        return save_res;
    }

    const uint64_t dump_duration_ms = msclock() - dump_started_ms;
    PrintAndLogEx(SUCCESS, "Card dump complete in %" PRIu64 ".%03" PRIu64 " seconds. Dumped %u/%u system(s), discovered %" PRIu32 " node(s), visited %" PRIu32 " service(s), dumped %" PRIu32 " public service(s).",
                  dump_duration_ms / 1000U, dump_duration_ms % 1000U,
                  (unsigned int)dump_system_count, (unsigned int)discovered_systems.count,
                  total_discovered_nodes, total_service_count, total_public_service_count);

    return PM3_SUCCESS;
}


/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaRequestService(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica rqservice",
                  "Use this command to verify the existence of Area and Service, and to acquire Key Version:\n"
                  "       - When the specified Area or Service exists, the card returns Key Version.\n"
                  "       - When the specified Area or Service does not exist, the card returns FFFFh as Key Version.\n"
                  "For Node Code List of a command packet, Area Code or Service Code of the target\n"
                  "of acquisition of Key Version shall be enumerated in Little Endian format.\n"
                  "If Key Version of System is the target of acquisition, FFFFh shall be specified\n"
                  "in the command packet.",
                  "hf felcia rqservice --node 01 --code FFFF\n"
                  "hf felcia rqservice -a --code FFFF\n"
                  "hf felica rqservice --idm 011204126417E405 --node 01 --code FFFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "all", "auto node number mode, iterates through all nodes 1 < n < 32"),
        arg_str0("n", "node", "<hex>", "Number of Node"),
        arg_str0("c", "code", "<hex>", "Node Code List (little endian)"),
        arg_str0(NULL, "idm", "<hex>", "use custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool all_nodes = arg_get_lit(ctx, 1);

    uint8_t node[1] = {0};
    int nlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), node, sizeof(node), &nlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t code[2] = {0, 0};
    int clen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), code, sizeof(code), &clen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8] = {0};
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 4), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    if (all_nodes == false) {
        // Node Number
        if (nlen == 1) {
            memcpy(data + 10, node, sizeof(node));
        }

        // code
        if (clen == 2) {
            memcpy(data + 11, code, sizeof(code));
        }
    }

    uint8_t datalen = 13; // length (1) + CMD (1) + IDm(8) + Node Number (1) + Node Code List (2)

    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, data + 2);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW);

    data[0] = (datalen & 0xFF);
    data[1] = 0x02; // Service Request Command ID
    if (all_nodes) {

        // send 32 calls
        for (uint8_t i = 1; i < 32; i++) {
            data[10] = i;
            send_request_service(flags, datalen, data, 1);
        }

    } else {
        send_request_service(flags, datalen, data, 1);
    }

    return PM3_SUCCESS;
}

/**
 * Command parser for rqservice.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaDiscoverNodes(const char *Cmd) {
    /* -- CLI boilerplate (method-aware discovery) ------------------- */
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica discnodes",
                  "Dump all existing Area Code and Service Code.\n"
                  "Method: auto | request_code_list | search_service_code | request_service | read_without_encryption",
                  "hf felica discnodes\n"
                  "hf felica discnodes --retry 5\n"
                  "hf felica discnodes --method request_service\n"
                  "hf felica discnodes --idm 11100910C11BC407");
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("r", "retry", "<dec>", "number of retries"),
        arg_str0("m", "method", "<str>", "node discovery method"),
        arg_str0(NULL, "idm", "<hex>", "use custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t retry_count = arg_get_u32_def(ctx, 1, FELICA_DISCOVER_DEFAULT_RETRY_COUNT);
    char method_str[64] = {0};
    int method_len = 0;
    int method_str_status = CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)method_str, sizeof(method_str) - 1, &method_len);
    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    felica_node_discovery_method_t selected_method = FELICA_NODE_DISCOVERY_NONE;
    int method_parse_status = PM3_EINVARG;
    if (method_str_status == PM3_SUCCESS) {
        method_str[method_len] = '\0';
        method_parse_status = felica_parse_node_discovery_method(method_str, &selected_method);
    }
    CLIParserFree(ctx);
    if (res != PM3_SUCCESS) {
        return PM3_EINVARG;
    }
    if (method_str_status != PM3_SUCCESS || method_parse_status != PM3_SUCCESS) {
        return method_parse_status;
    }

    res = felica_select_target_keep_field(idm, (size_t)ilen, idm);
    if (res != PM3_SUCCESS) {
        return res;
    }
    const uint8_t *const pmm = (memcmp(last_known_card.IDm, idm, sizeof(idm)) == 0) ? last_known_card.PMm : NULL;

    PrintAndLogEx(HINT, "Area and service codes are printed in network order.");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to abort discovery");

    // Do not set FELICA_CLEARTRACE here; auto discovery may try several methods
    // before finding the supported one, and the trace should include all probes.
    uint8_t flags = FELICA_CONNECT | FELICA_NO_SELECT | FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    felica_scsvcode_context_t scsv_ctx;
    memset(&scsv_ctx, 0, sizeof(scsv_ctx));
    scsv_ctx.area_end_stack[0] = 0xFFFF;

    uint32_t discovered_nodes = 0;
    felica_node_discovery_method_t used_method = FELICA_NODE_DISCOVERY_NONE;
    uint64_t discovery_started = msclock();
    int ret = felica_discover_nodes(idm, pmm, &flags, retry_count,
                                    selected_method,
                                    felica_scsvcode_discovery_visitor, &scsv_ctx,
                                    &used_method, &discovered_nodes);
    uint64_t discovery_duration_ms = msclock() - discovery_started;

    DropField();

    if (ret == PM3_EOPABORTED) {
        felica_scsvcode_print_footer(&scsv_ctx);
        PrintAndLogEx(WARNING, "Node discovery aborted by user after %" PRIu64 " ms. Discovered %" PRIu32 " node(s): %" PRIu32 " area(s), %" PRIu32 " service(s).",
                      discovery_duration_ms, discovered_nodes, scsv_ctx.area_count, scsv_ctx.service_count);
        return ret;
    }

    if (ret != PM3_SUCCESS) {
        if (selected_method != FELICA_NODE_DISCOVERY_NONE) {
            PrintAndLogEx(FAILED, "Node discovery failed with --method %s.", felica_node_discovery_method_cli_name(selected_method));
        } else {
            PrintAndLogEx(FAILED, "Unable to discover nodes using RequestCodeList/SearchServiceCode/RequestService/ReadWithoutEncryption.");
        }
        return ret;
    }

    felica_scsvcode_print_footer(&scsv_ctx);
    PrintAndLogEx(INFO, "Node discovery duration: %" PRIu64 " ms", discovery_duration_ms);

    PrintAndLogEx(SUCCESS, "Service code and area dump complete. Discovered %" PRIu32 " node(s): %" PRIu32 " area(s), %" PRIu32 " service(s).",
                  discovered_nodes, scsv_ctx.area_count, scsv_ctx.service_count);
    return PM3_SUCCESS;
}

/**
 * Command parser for scsvcode.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaDumpServiceArea(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica scsvcode",
                  "Dump all existing Area Code and Service Code.",
                  "hf felica scsvcode\n"
                  "hf felica scsvcode --retry 5\n"
                  "hf felica scsvcode --idm 11100910C11BC407");
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("r", "retry", "<dec>", "number of retries"),
        arg_str0(NULL, "idm", "<hex>", "use custom IDm"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t retry_count = arg_get_u32_def(ctx, 1, FELICA_DEFAULT_RETRY_COUNT);
    uint8_t idm[8] = {0};
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), idm, sizeof(idm), &ilen);
    CLIParserFree(ctx);
    if (res) {
        return PM3_EINVARG;
    }

    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, idm);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(HINT, "Area and service codes are printed in network order.");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to abort discovery");

    uint8_t flags = FELICA_CONNECT | FELICA_CLEARTRACE | FELICA_NO_SELECT | FELICA_NO_DISCONNECT | FELICA_APPEND_CRC | FELICA_RAW;
    felica_scsvcode_context_t scsv_ctx;
    memset(&scsv_ctx, 0, sizeof(scsv_ctx));
    scsv_ctx.area_end_stack[0] = 0xFFFF;

    uint32_t discovered_nodes = 0;
    int ret = felica_discover_nodes(idm, NULL, &flags, retry_count,
                                    FELICA_NODE_DISCOVERY_SEARCH_SERVICE_CODE,
                                    felica_scsvcode_discovery_visitor, &scsv_ctx,
                                    NULL, &discovered_nodes);

    DropField();

    if (ret == PM3_EOPABORTED) {
        felica_scsvcode_print_footer(&scsv_ctx);
        PrintAndLogEx(WARNING, "Service code and area dump aborted by user. Discovered %" PRIu32 " node(s): %" PRIu32 " area(s), %" PRIu32 " service(s).",
                      discovered_nodes, scsv_ctx.area_count, scsv_ctx.service_count);
        return ret;
    }

    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to discover nodes using SearchServiceCode.");
        return ret;
    }

    felica_scsvcode_print_footer(&scsv_ctx);
    PrintAndLogEx(SUCCESS, "Service code and area dump complete. Discovered %" PRIu32 " node(s): %" PRIu32 " area(s), %" PRIu32 " service(s).",
                  discovered_nodes, scsv_ctx.area_count, scsv_ctx.service_count);
    return PM3_SUCCESS;
}

static int CmdHFFelicaSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica sniff",
                  "Collect data from the field and save into command buffer.\n"
                  "Buffer accessible from `hf felica list`",
                  "hf felica sniff\n"
                  "hf felica sniff -s 10 -t 19"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("s", "samples", "<dec>", "samples to skip"),
        arg_u64_0("t", "trig", "<dec>", "triggers to skip "),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct p {
        uint32_t samples;
        uint32_t triggers;
    } PACKED payload;

    payload.samples = arg_get_u32_def(ctx, 1, 10);
    payload.triggers = arg_get_u32_def(ctx, 2, 5000);
    CLIParserFree(ctx);

    if (payload.samples > 9999) {
        payload.samples = 9999;
        PrintAndLogEx(INFO, "Too large samples to skip value, using max value 9999");
    }

    if (payload.triggers  > 9999) {
        payload.triggers  = 9999;
        PrintAndLogEx(INFO, "Too large trigger to skip value, using max value 9999");
    }


    PrintAndLogEx(INFO, "Sniff Felica,  getting first %" PRIu32 " frames, skipping after %" PRIu32 " triggers", payload.samples,   payload.triggers);
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort sniffing");
    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICA_SNIFF, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            msleep(300);
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_FELICA_SNIFF, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                break;
            }
        }
    }

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf felica list") "` to view");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

typedef struct {
    uint8_t *model;
    size_t model_len;
    uint16_t system_count;
    uint16_t node_count;
    uint16_t block_count;
} felica_sim_model_t;

typedef struct {
    felica_sim_system_record_t *systems;
    felica_sim_node_record_t *nodes;
    felica_sim_block_record_t *blocks;
    uint8_t specification_version[FELICA_SIM_SPECIFICATION_VERSION_MAX_LEN];
    size_t specification_version_len;
    uint8_t product_information[FELICA_SIM_PRODUCT_INFORMATION_MAX_LEN];
    size_t product_information_len;
    uint8_t container_issue_information[FELICA_SIM_CONTAINER_ISSUE_INFORMATION_LEN];
    size_t container_issue_information_len;
    size_t system_count;
    size_t system_capacity;
    size_t node_count;
    size_t node_capacity;
    size_t block_count;
    size_t block_capacity;
} felica_sim_model_builder_t;

static void felica_sim_model_free(felica_sim_model_t *model) {
    if (model == NULL) {
        return;
    }
    free(model->model);
    memset(model, 0, sizeof(*model));
}

static void felica_sim_builder_free(felica_sim_model_builder_t *builder) {
    if (builder == NULL) {
        return;
    }
    free(builder->systems);
    free(builder->nodes);
    free(builder->blocks);
    memset(builder, 0, sizeof(*builder));
}

static int felica_sim_reserve(void **ptr, size_t *capacity, size_t elem_size, size_t needed) {
    if (needed <= *capacity) {
        return PM3_SUCCESS;
    }

    size_t new_capacity = (*capacity == 0) ? 16U : *capacity;
    while (new_capacity < needed) {
        if (new_capacity > (SIZE_MAX / 2U)) {
            return PM3_EOVFLOW;
        }
        new_capacity *= 2U;
    }

    if (new_capacity > (SIZE_MAX / elem_size)) {
        return PM3_EOVFLOW;
    }

    void *tmp = realloc(*ptr, new_capacity * elem_size);
    if (tmp == NULL) {
        return PM3_EMALLOC;
    }

    *ptr = tmp;
    *capacity = new_capacity;
    return PM3_SUCCESS;
}

static int felica_sim_builder_add_system(felica_sim_model_builder_t *builder, const felica_sim_system_record_t *system, size_t *index_out) {
    if (builder->system_count >= UINT16_MAX) {
        return PM3_EOVFLOW;
    }
    int ret = felica_sim_reserve((void **)&builder->systems, &builder->system_capacity, sizeof(*builder->systems), builder->system_count + 1U);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    if (index_out) {
        *index_out = builder->system_count;
    }
    builder->systems[builder->system_count++] = *system;
    return PM3_SUCCESS;
}

static int felica_sim_builder_add_node(felica_sim_model_builder_t *builder, const felica_sim_node_record_t *node, size_t *index_out) {
    if (builder->node_count >= UINT16_MAX) {
        return PM3_EOVFLOW;
    }
    int ret = felica_sim_reserve((void **)&builder->nodes, &builder->node_capacity, sizeof(*builder->nodes), builder->node_count + 1U);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    if (index_out) {
        *index_out = builder->node_count;
    }
    builder->nodes[builder->node_count++] = *node;
    return PM3_SUCCESS;
}

static int felica_sim_builder_add_block(felica_sim_model_builder_t *builder, const felica_sim_block_record_t *block) {
    if (builder->block_count >= UINT16_MAX) {
        return PM3_EOVFLOW;
    }
    int ret = felica_sim_reserve((void **)&builder->blocks, &builder->block_capacity, sizeof(*builder->blocks), builder->block_count + 1U);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    builder->blocks[builder->block_count++] = *block;
    return PM3_SUCCESS;
}

static bool felica_sim_hex_to_bytes(const char *hex, uint8_t *out, size_t expected_len) {
    if (hex == NULL || out == NULL || strlen(hex) != expected_len * 2U) {
        return false;
    }

    size_t len = 0;
    return hexstr_to_byte_array(hex, out, &len) && len == expected_len;
}

static bool felica_sim_parse_optional_hex_json(const json_t *value_json, uint8_t *out,
                                               size_t min_len, size_t max_len, size_t *out_len) {
    if (out == NULL || out_len == NULL || min_len > max_len) {
        return false;
    }

    *out_len = 0;
    if (value_json == NULL || json_is_null(value_json)) {
        return true;
    }
    if (json_is_string(value_json) == false) {
        return false;
    }

    const char *hex = json_string_value(value_json);
    const size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1U)) {
        return false;
    }

    const size_t byte_len = hex_len / 2U;
    if (byte_len < min_len || byte_len > max_len) {
        return false;
    }

    size_t parsed_len = 0;
    if (hexstr_to_byte_array(hex, out, &parsed_len) == false || parsed_len != byte_len) {
        return false;
    }

    *out_len = byte_len;
    return true;
}

static bool felica_sim_validate_specification_version_data(const uint8_t *data, size_t data_len) {
    if (data_len == 0) {
        return true;
    }
    if (data == NULL || data_len < 4U) {
        return false;
    }

    const size_t expected_len = 4U + ((size_t)data[3] * 2U);
    return data_len == expected_len && data_len <= FELICA_SIM_SPECIFICATION_VERSION_MAX_LEN;
}

static bool felica_sim_parse_u16_be_hex(const char *hex, uint16_t *value_out) {
    uint8_t bytes[2] = {0};
    if (value_out == NULL || felica_sim_hex_to_bytes(hex, bytes, sizeof(bytes)) == false) {
        return false;
    }
    *value_out = ((uint16_t)bytes[0] << 8) | bytes[1];
    return true;
}

static uint16_t felica_sim_swap16(uint16_t value) {
    return (uint16_t)(((value & 0x00FFU) << 8) | ((value & 0xFF00U) >> 8));
}

static bool felica_sim_parse_key_version_json(const json_t *value_json, uint16_t *value_le_out, bool *has_value_out) {
    if (value_le_out == NULL || has_value_out == NULL) {
        return false;
    }

    *value_le_out = 0;
    *has_value_out = false;
    if (value_json == NULL || json_is_null(value_json)) {
        return true;
    }
    if (json_is_string(value_json) == false) {
        return false;
    }

    uint8_t bytes[2] = {0};
    if (felica_sim_hex_to_bytes(json_string_value(value_json), bytes, sizeof(bytes)) == false) {
        return false;
    }

    *value_le_out = bytes[0] | ((uint16_t)bytes[1] << 8);
    *has_value_out = true;
    return true;
}

static bool felica_sim_parse_encryption_identifier_json(const json_t *value_json, uint8_t *identifier_out) {
    if (identifier_out == NULL) {
        return false;
    }

    *identifier_out = 0;
    if (value_json == NULL || json_is_null(value_json)) {
        return true;
    }
    if (json_is_string(value_json) == false) {
        return false;
    }

    const char *identifier = json_string_value(value_json);
    for (size_t i = 0; i < ARRAYLEN(FELICA_ENCRYPTION_IDENTIFIER_INFO); i++) {
        if (strcmp(identifier, FELICA_ENCRYPTION_IDENTIFIER_INFO[i].name) == 0) {
            *identifier_out = FELICA_ENCRYPTION_IDENTIFIER_INFO[i].identifier;
            return true;
        }
    }

    uint8_t raw_identifier = 0;
    if (felica_sim_hex_to_bytes(identifier, &raw_identifier, sizeof(raw_identifier)) == false) {
        return false;
    }

    if (felica_encryption_identifier_get_info(raw_identifier) == NULL) {
        return false;
    }

    *identifier_out = raw_identifier;
    return true;
}

static const char *felica_sim_rwe_error_location_indication_name(uint8_t mode) {
    switch (mode) {
        case FELICA_SIM_RWE_ERROR_LOCATION_MASK:
            return "mask";
        case FELICA_SIM_RWE_ERROR_LOCATION_INDEX:
            return "index";
        case FELICA_SIM_RWE_ERROR_LOCATION_FLAG:
            return "flag";
        default:
            return "unknown";
    }
}

static bool felica_sim_parse_rwe_error_location_indication(const char *value, uint8_t *mode_out) {
    if (value == NULL || value[0] == '\0' || mode_out == NULL) {
        return false;
    }

    char mode[16] = {0};
    const size_t len = strlen(value);
    if (len >= sizeof(mode)) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        mode[i] = (char)tolower((unsigned char)value[i]);
    }

    if (strcmp(mode, "mask") == 0 || strcmp(mode, "bitmask") == 0) {
        *mode_out = FELICA_SIM_RWE_ERROR_LOCATION_MASK;
        return true;
    }
    if (strcmp(mode, "index") == 0 || strcmp(mode, "number") == 0) {
        *mode_out = FELICA_SIM_RWE_ERROR_LOCATION_INDEX;
        return true;
    }
    if (strcmp(mode, "flag") == 0 || strcmp(mode, "ff") == 0) {
        *mode_out = FELICA_SIM_RWE_ERROR_LOCATION_FLAG;
        return true;
    }

    return false;
}

static int felica_sim_parse_metadata_json(felica_sim_model_builder_t *builder, const json_t *root) {
    if (builder == NULL || json_is_object(root) == false) {
        return PM3_EINVARG;
    }

    if (felica_sim_parse_optional_hex_json(json_object_get(root, "specification_version"),
                                           builder->specification_version,
                                           4U, sizeof(builder->specification_version),
                                           &builder->specification_version_len) == false ||
            felica_sim_validate_specification_version_data(builder->specification_version,
                                                           builder->specification_version_len) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: root has invalid specification_version");
        return PM3_EINVARG;
    }

    if (felica_sim_parse_optional_hex_json(json_object_get(root, "product_information"),
                                           builder->product_information,
                                           1U, sizeof(builder->product_information),
                                           &builder->product_information_len) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: root has invalid product_information");
        return PM3_EINVARG;
    }

    if (felica_sim_parse_optional_hex_json(json_object_get(root, "container_issue_information"),
                                           builder->container_issue_information,
                                           sizeof(builder->container_issue_information),
                                           sizeof(builder->container_issue_information),
                                           &builder->container_issue_information_len) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: root has invalid container_issue_information");
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static bool felica_sim_node_duplicate_exists(const felica_sim_model_builder_t *builder, const felica_sim_system_record_t *system,
                                             uint8_t flags, uint16_t node_code_le, uint16_t end_code_le) {
    const uint8_t node_type = flags & FELICA_SIM_NODE_TYPE_MASK;
    const size_t end = (size_t)system->first_node + system->node_count;
    for (size_t i = system->first_node; i < end; i++) {
        const felica_sim_node_record_t *node = &builder->nodes[i];
        if ((node->flags & FELICA_SIM_NODE_TYPE_MASK) != node_type) {
            continue;
        }
        if (node->node_code_le == node_code_le &&
                (node_type != FELICA_SIM_NODE_TYPE_AREA || node->end_code_le == end_code_le)) {
            return true;
        }
    }
    return false;
}

static bool felica_sim_block_duplicate_exists(const felica_sim_model_builder_t *builder, const felica_sim_node_record_t *node,
                                              uint16_t block_number) {
    const size_t end = (size_t)node->first_block + node->block_count;
    for (size_t i = node->first_block; i < end; i++) {
        if (builder->blocks[i].block_number == block_number) {
            return true;
        }
    }
    return false;
}

static int felica_sim_parse_node_json(felica_sim_model_builder_t *builder, const json_t *node_json,
                                      size_t system_index, size_t node_json_index) {
    if (json_is_object(node_json) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu is not an object", node_json_index);
        return PM3_EINVARG;
    }

    json_t *type_json = json_object_get(node_json, "type");
    json_t *code_json = json_object_get(node_json, "code");
    json_t *des_key_json = json_object_get(node_json, "des_key_version");
    json_t *aes_key_json = json_object_get(node_json, "aes_key_version");
    json_t *data_json = json_object_get(node_json, "data");

    if (json_is_string(type_json) == false || json_is_string(code_json) == false || json_is_object(data_json) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu is missing type/code/data", node_json_index);
        return PM3_EINVARG;
    }

    const char *type = json_string_value(type_json);
    const bool is_area = strcmp(type, "area") == 0;
    const bool is_system = strcmp(type, "system") == 0;
    const uint8_t node_type = is_system ? FELICA_SIM_NODE_TYPE_SYSTEM :
                              is_area ? FELICA_SIM_NODE_TYPE_AREA :
                              FELICA_SIM_NODE_TYPE_SERVICE;
    if (is_area == false && is_system == false && strcmp(type, "service") != 0) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has unknown type `%s`", node_json_index, type);
        return PM3_EINVARG;
    }

    const char *code_hex = json_string_value(code_json);
    const size_t code_len = strlen(code_hex);
    if ((is_area && code_len != 4U && code_len != 8U) || (is_area == false && code_len != 4U)) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has invalid code length", node_json_index);
        return PM3_EINVARG;
    }

    char start_code_hex[5] = {0};
    memcpy(start_code_hex, code_hex, 4);
    uint16_t node_code_be = 0;
    if (felica_sim_parse_u16_be_hex(start_code_hex, &node_code_be) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has invalid code", node_json_index);
        return PM3_EINVARG;
    }
    if (is_system && node_code_be != FELICA_SYSTEM_NODE) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system node %zu must use code FFFF", node_json_index);
        return PM3_EINVARG;
    }
    if (is_system == false && node_code_be == FELICA_SYSTEM_NODE) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: non-system node %zu uses reserved system code FFFF", node_json_index);
        return PM3_EINVARG;
    }

    felica_sim_node_record_t node = {
        .system_index = (uint16_t)system_index,
        .node_code_le = felica_sim_swap16(node_code_be),
        .end_code_le = is_area ? 0xFFFEU : 0,
        .first_block = (uint16_t)builder->block_count,
        .block_count = 0,
        .des_key_version_le = 0xFFFFU,
        .aes_key_version_le = 0xFFFFU,
        .flags = node_type,
        .reserved = 0,
    };

    if (is_area && code_len == 8U) {
        char end_code_hex[5] = {0};
        memcpy(end_code_hex, code_hex + 4, 4);
        uint16_t end_code_be = 0;
        if (felica_sim_parse_u16_be_hex(end_code_hex, &end_code_be) == false) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has invalid area end code", node_json_index);
            return PM3_EINVARG;
        }
        node.end_code_le = felica_sim_swap16(end_code_be);
    }

    bool has_key_version = false;
    uint16_t key_version_le = 0;
    if (felica_sim_parse_key_version_json(des_key_json, &key_version_le, &has_key_version) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has invalid DES key version", node_json_index);
        return PM3_EINVARG;
    }
    if (has_key_version) {
        node.des_key_version_le = key_version_le;
        node.flags |= FELICA_SIM_NODE_HAS_DES_KEY_VERSION;
    }

    key_version_le = 0;
    if (felica_sim_parse_key_version_json(aes_key_json, &key_version_le, &has_key_version) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: node %zu has invalid AES key version", node_json_index);
        return PM3_EINVARG;
    }
    if (has_key_version) {
        node.aes_key_version_le = key_version_le;
        node.flags |= FELICA_SIM_NODE_HAS_AES_KEY_VERSION;
    }

    if (is_system && (node.flags & (FELICA_SIM_NODE_HAS_DES_KEY_VERSION | FELICA_SIM_NODE_HAS_AES_KEY_VERSION)) == 0) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system node `%s` is missing key version data", code_hex);
        return PM3_EINVARG;
    }

    const felica_sim_system_record_t *system = &builder->systems[system_index];
    if (felica_sim_node_duplicate_exists(builder, system, node.flags, node.node_code_le, node.end_code_le)) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: duplicate node code `%s`", code_hex);
        return PM3_EINVARG;
    }

    if ((is_area || is_system) && json_object_size(data_json) != 0) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: non-service node `%s` unexpectedly has block data", code_hex);
        return PM3_EINVARG;
    }

    size_t node_index = 0;
    int ret = felica_sim_builder_add_node(builder, &node, &node_index);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    const char *block_number_hex = NULL;
    json_t *block_data_json = NULL;
    json_object_foreach(data_json, block_number_hex, block_data_json) {
        if (json_is_string(block_data_json) == false) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: block `%s` value is not a string", block_number_hex);
            return PM3_EINVARG;
        }

        uint16_t block_number = 0;
        if (felica_sim_parse_u16_be_hex(block_number_hex, &block_number) == false) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: invalid block number `%s`", block_number_hex);
            return PM3_EINVARG;
        }

        if (felica_sim_block_duplicate_exists(builder, &builder->nodes[node_index], block_number)) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: duplicate block `%s` in node `%s`", block_number_hex, code_hex);
            return PM3_EINVARG;
        }

        felica_sim_block_record_t block = {
            .node_index = (uint16_t)node_index,
            .block_number = block_number,
            .data = {0},
        };
        if (felica_sim_hex_to_bytes(json_string_value(block_data_json), block.data, sizeof(block.data)) == false) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: block `%s` is not 16 bytes", block_number_hex);
            return PM3_EINVARG;
        }

        ret = felica_sim_builder_add_block(builder, &block);
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        builder->nodes[node_index].block_count++;
    }

    builder->systems[system_index].node_count++;
    return PM3_SUCCESS;
}

static int felica_sim_parse_system_json(felica_sim_model_builder_t *builder, const json_t *system_json, size_t system_json_index) {
    if (json_is_object(system_json) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system %zu is not an object", system_json_index);
        return PM3_EINVARG;
    }

    json_t *code_json = json_object_get(system_json, "code");
    json_t *idm_json = json_object_get(system_json, "idm");
    json_t *pmm_json = json_object_get(system_json, "pmm");
    json_t *encryption_identifier_json = json_object_get(system_json, "encryption_identifier");
    json_t *nodes_json = json_object_get(system_json, "nodes");

    if (json_is_string(code_json) == false ||
            json_is_string(idm_json) == false ||
            json_is_string(pmm_json) == false ||
            json_is_array(nodes_json) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system %zu is missing code/idm/pmm/nodes", system_json_index);
        return PM3_EINVARG;
    }

    uint16_t system_code = 0;
    if (felica_sim_parse_u16_be_hex(json_string_value(code_json), &system_code) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system %zu has invalid system code", system_json_index);
        return PM3_EINVARG;
    }

    for (size_t i = 0; i < builder->system_count; i++) {
        if (builder->systems[i].system_code == system_code) {
            PrintAndLogEx(ERR, "Invalid FeliCa dump: duplicate system code `%04X`", system_code);
            return PM3_EINVARG;
        }
    }

    felica_sim_system_record_t system = {
        .system_code = system_code,
        .idm = {0},
        .pmm = {0},
        .encryption_identifier = 0,
        .reserved = 0,
        .first_node = (uint16_t)builder->node_count,
        .node_count = 0,
    };

    if (felica_sim_hex_to_bytes(json_string_value(idm_json), system.idm, sizeof(system.idm)) == false ||
            felica_sim_hex_to_bytes(json_string_value(pmm_json), system.pmm, sizeof(system.pmm)) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system %zu has invalid IDm or PMm", system_json_index);
        return PM3_EINVARG;
    }

    if (felica_sim_parse_encryption_identifier_json(encryption_identifier_json, &system.encryption_identifier) == false) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system %zu has invalid encryption identifier", system_json_index);
        return PM3_EINVARG;
    }

    size_t system_index = 0;
    int ret = felica_sim_builder_add_system(builder, &system, &system_index);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    size_t node_index = 0;
    json_t *node_json = NULL;
    json_array_foreach(nodes_json, node_index, node_json) {
        ret = felica_sim_parse_node_json(builder, node_json, system_index, node_index);
        if (ret != PM3_SUCCESS) {
            return ret;
        }
    }

    return PM3_SUCCESS;
}

static int felica_sim_model_finalize(const felica_sim_model_builder_t *builder, felica_sim_model_t *model_out) {
    const size_t systems_len = builder->system_count * sizeof(felica_sim_system_record_t);
    const size_t nodes_len = builder->node_count * sizeof(felica_sim_node_record_t);
    const size_t blocks_len = builder->block_count * sizeof(felica_sim_block_record_t);
    const size_t metadata_len = builder->specification_version_len +
                                builder->product_information_len +
                                builder->container_issue_information_len;
    const size_t model_len = sizeof(felica_sim_model_header_t) + systems_len + nodes_len + blocks_len + metadata_len;

    if (builder->system_count == 0 ||
            builder->system_count > FELICA_SYSTEM_CODE_MAX_COUNT ||
            builder->node_count > UINT16_MAX ||
            builder->block_count > UINT16_MAX ||
            builder->specification_version_len > UINT16_MAX ||
            builder->product_information_len > UINT16_MAX ||
            builder->container_issue_information_len > UINT16_MAX ||
            model_len > UINT32_MAX) {
        return PM3_EOVFLOW;
    }

    uint8_t *model = calloc(1, model_len);
    if (model == NULL) {
        return PM3_EMALLOC;
    }

    felica_sim_model_header_t *hdr = (felica_sim_model_header_t *)model;
    hdr->magic = FELICA_SIM_MODEL_MAGIC;
    hdr->version = FELICA_SIM_MODEL_VERSION;
    hdr->header_len = sizeof(*hdr);
    hdr->total_len = (uint32_t)model_len;
    hdr->model_crc = 0;
    hdr->system_count = (uint16_t)builder->system_count;
    hdr->node_count = (uint16_t)builder->node_count;
    hdr->block_count = (uint16_t)builder->block_count;
    hdr->system_offset = sizeof(*hdr);
    hdr->node_offset = hdr->system_offset + systems_len;
    hdr->block_offset = hdr->node_offset + nodes_len;
    hdr->metadata_offset = hdr->block_offset + blocks_len;
    hdr->specification_version_len = (uint16_t)builder->specification_version_len;
    hdr->product_information_len = (uint16_t)builder->product_information_len;
    hdr->container_issue_information_len = (uint16_t)builder->container_issue_information_len;
    hdr->reserved = 0;

    if (systems_len) {
        memcpy(model + hdr->system_offset, builder->systems, systems_len);
    }
    if (nodes_len) {
        memcpy(model + hdr->node_offset, builder->nodes, nodes_len);
    }
    if (blocks_len) {
        memcpy(model + hdr->block_offset, builder->blocks, blocks_len);
    }
    uint8_t *metadata = model + hdr->metadata_offset;
    size_t metadata_pos = 0;
    if (builder->specification_version_len) {
        memcpy(metadata + metadata_pos, builder->specification_version, builder->specification_version_len);
        metadata_pos += builder->specification_version_len;
    }
    if (builder->product_information_len) {
        memcpy(metadata + metadata_pos, builder->product_information, builder->product_information_len);
        metadata_pos += builder->product_information_len;
    }
    if (builder->container_issue_information_len) {
        memcpy(metadata + metadata_pos, builder->container_issue_information, builder->container_issue_information_len);
    }
    hdr->model_crc = Crc16ex(CRC_XMODEM, model, model_len);

    model_out->model = model;
    model_out->model_len = model_len;
    model_out->system_count = hdr->system_count;
    model_out->node_count = hdr->node_count;
    model_out->block_count = hdr->block_count;
    return PM3_SUCCESS;
}

static int felica_sim_model_from_json(json_t *root, felica_sim_model_t *model_out) {
    if (json_is_object(root) == false || model_out == NULL) {
        return PM3_EINVARG;
    }

    json_t *systems_json = json_object_get(root, "systems");
    if (json_is_array(systems_json) == false || json_array_size(systems_json) == 0) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: root must contain non-empty systems array");
        return PM3_EINVARG;
    }

    if (json_array_size(systems_json) > FELICA_SYSTEM_CODE_MAX_COUNT) {
        PrintAndLogEx(ERR, "Invalid FeliCa dump: system count exceeds %u", FELICA_SYSTEM_CODE_MAX_COUNT);
        return PM3_EOVFLOW;
    }

    felica_sim_model_builder_t builder = {0};
    int ret = felica_sim_parse_metadata_json(&builder, root);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    size_t system_index = 0;
    json_t *system_json = NULL;
    json_array_foreach(systems_json, system_index, system_json) {
        ret = felica_sim_parse_system_json(&builder, system_json, system_index);
        if (ret != PM3_SUCCESS) {
            felica_sim_builder_free(&builder);
            return ret;
        }
    }

    ret = felica_sim_model_finalize(&builder, model_out);
    felica_sim_builder_free(&builder);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Unable to build FeliCa simulator model");
    }
    return ret;
}

static int felica_sim_send_control(uint8_t subcommand, uint32_t total_len, uint32_t offset, uint16_t model_crc,
                                   const uint8_t *data, uint16_t data_len, uint32_t timeout_ms) {
    if (data_len > (PM3_CMD_DATA_SIZE - sizeof(felica_sim_upload_t))) {
        return PM3_EOVFLOW;
    }

    uint8_t packet[PM3_CMD_DATA_SIZE] = {0};
    felica_sim_upload_t *payload = (felica_sim_upload_t *)packet;
    payload->subcommand = subcommand;
    payload->total_len = total_len;
    payload->offset = offset;
    payload->model_crc = model_crc;
    payload->chunk_len = data_len;
    if (data_len && data) {
        memcpy(payload->data, data, data_len);
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICA_SIMULATE, packet, sizeof(*payload) + data_len);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_FELICA_SIMULATE, &resp, timeout_ms) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for simulator response");
        return PM3_ETIMEOUT;
    }

    return resp.status;
}

static int felica_sim_upload_model(const felica_sim_model_t *model) {
    const felica_sim_model_header_t *hdr = (const felica_sim_model_header_t *)model->model;
    int ret = felica_sim_send_control(FELICA_SIM_CLEAR, 0, 0, 0, NULL, 0, 5000);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to clear FeliCa simulator state (%d)", ret);
        return ret;
    }

    const uint16_t chunk_size = PM3_CMD_DATA_SIZE - sizeof(felica_sim_upload_t);
    uint32_t offset = 0;
    PrintAndLogEx(INFO, "Uploading simulator model");
    PrintAndLogEx(INFO, "." NOLF);
    fflush(stdout);

    g_conn.block_after_ACK = true;
    while (offset < model->model_len) {
        const uint16_t bytes_to_send = MIN(chunk_size, model->model_len - offset);
        if (offset + bytes_to_send >= model->model_len) {
            g_conn.block_after_ACK = false;
        }

        ret = felica_sim_send_control(FELICA_SIM_LOAD, (uint32_t)model->model_len, offset, hdr->model_crc,
                                      model->model + offset, bytes_to_send, 2500);
        if (ret != PM3_SUCCESS) {
            g_conn.block_after_ACK = false;
            PrintAndLogEx(FAILED, "Unable to upload simulator model at offset %" PRIu32 " (%d)", offset, ret);
            return ret;
        }

        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        offset += bytes_to_send;
    }
    g_conn.block_after_ACK = false;
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int felica_sim_start(const felica_sim_model_t *model, uint8_t rwe_error_location_indication) {
    const felica_sim_model_header_t *hdr = (const felica_sim_model_header_t *)model->model;
    uint8_t packet[sizeof(felica_sim_upload_t)] = {0};
    felica_sim_upload_t *payload = (felica_sim_upload_t *)packet;
    payload->subcommand = FELICA_SIM_START;
    payload->total_len = (uint32_t)model->model_len;
    payload->model_crc = hdr->model_crc;
    payload->rwe_error_location_indication = rwe_error_location_indication;

    PrintAndLogEx(INFO, "RWE error location indication.. " _YELLOW_("%s"),
                  felica_sim_rwe_error_location_indication_name(rwe_error_location_indication));
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");
    PrintAndLogEx(INFO, "After abort, use " _YELLOW_("hf felica list") " to view captured simulator traffic");
    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICA_SIMULATE, packet, sizeof(packet));

    PacketResponseNG resp;
    bool abort_sent = false;
    for (;;) {
        if (abort_sent == false && kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            abort_sent = true;
            msleep(300);
        }

        if (WaitForResponseTimeout(CMD_HF_FELICA_SIMULATE, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                return PM3_SUCCESS;
            }
            if (resp.status != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "FeliCa simulator stopped with status %d", resp.status);
                return resp.status;
            }
            return PM3_SUCCESS;
        }
    }
}

static int CmdHFFelicaSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica sim",
                  "Emulate a FeliCa Standard card from a JSON dump generated by `hf felica dump`.",
                  "hf felica sim -f hf-felica-dump.json\n"
                  "hf felica sim -f hf-felica-dump --read-without-encryption-error-location-indication index\n"
                  "hf felica sim -f hf-felica-dump --read-without-encryption-error-location-indication flag -v"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "JSON dump file"),
        arg_str0(NULL, "read-without-encryption-error-location-indication",
        "<mask|index|flag>", "Read Without Encryption error location indication (default: mask)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    char filename[FILE_PATH_SIZE] = {0};
    int filename_len = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filename_len);
    uint8_t rwe_error_location_indication = FELICA_SIM_RWE_ERROR_LOCATION_MASK;
    struct arg_str *rwe_error_location_arg = arg_get_str(ctx, 2);
    const char *rwe_error_location = rwe_error_location_arg->count ? rwe_error_location_arg->sval[0] : NULL;
    if (rwe_error_location &&
            felica_sim_parse_rwe_error_location_indication(rwe_error_location, &rwe_error_location_indication) == false) {
        PrintAndLogEx(ERR, "Invalid RWE error location indication `%s`; expected mask, index, or flag", rwe_error_location);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    const bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    json_t *root = NULL;
    int ret = loadFileJSONroot(filename, (void **)&root, verbose);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    felica_sim_model_t model = {0};
    ret = felica_sim_model_from_json(root, &model);
    json_decref(root);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(SUCCESS, "Prepared FeliCa Standard model: %u system(s), %u node(s), %u block(s), %zu byte(s)",
                  model.system_count, model.node_count, model.block_count, model.model_len);
    if (g_pm3_capabilities.bigbuf_size &&
            model.model_len + FELICA_SIM_RUNTIME_RESERVE > g_pm3_capabilities.bigbuf_size) {
        PrintAndLogEx(ERR, "Simulator model is too large for device BigBuf: %zu + %u reserve > %" PRIu32,
                      model.model_len, FELICA_SIM_RUNTIME_RESERVE, g_pm3_capabilities.bigbuf_size);
        felica_sim_model_free(&model);
        return PM3_EOVFLOW;
    }

    ret = felica_sim_upload_model(&model);
    if (ret == PM3_SUCCESS) {
        ret = felica_sim_start(&model, rwe_error_location_indication);
    }

    felica_sim_model_free(&model);
    PrintAndLogEx(INFO, "Done!");
    return ret;
}

// uid  hex
static int CmdHFFelicaSimLite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica litesim",
                  "Emulating ISO/18092 FeliCa Lite tag",
                  "hf felica litesim -u 1122334455667788"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "UID/NDEF2 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int uid_len = 0;
    struct p {
        uint8_t uid[8];
    } PACKED payload;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uid_len);
    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort simulation");

    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICALITE_SIMULATE, payload.uid, sizeof(payload));
    PacketResponseNG resp;

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            msleep(300);
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_FELICALITE_SIMULATE, &resp, 1000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
                break;
            }
        }
    }

    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int felica_make_block_list(uint16_t *out, const uint8_t *blk_numbers, const size_t length) {
    if (length > 4) {
        PrintAndLogEx(ERR, "felica_make_block_list: exceeds max size");
        return PM3_EINVARG;
    }

    uint16_t tmp[4];
    memset(tmp, 0, sizeof(tmp));

    for (size_t i = 0; i < length; i++) {
        tmp[i] = (uint16_t)(blk_numbers[i] << 8) | 0x80;
    }
    memcpy(out, tmp, length * sizeof(uint16_t));

    return PM3_SUCCESS;
}

static int read_without_encryption(
    const uint8_t *idm,
    const uint8_t num,
    const uint8_t *blk_numbers,
    uint8_t *out,
    uint16_t *n) {

    felica_read_request_haeder_t request = {
        .command_code = { 0x06 },
        .number_of_service = { 1 },
        .service_code_list = { 0x00B },
        .number_of_block = { num },
    };
    memcpy(request.IDm, idm, sizeof(request.IDm));

    uint16_t svc[num];
    int ret = felica_make_block_list(svc, blk_numbers, num);
    if (ret) {
        return PM3_EINVARG;
    }

    size_t hdr_size = sizeof(request);
    uint16_t size = hdr_size + sizeof(svc) + 1;
    *n = size;

    memcpy(out, &(uint8_t) { size }, sizeof(uint8_t));
    memcpy(out + 1, &request, hdr_size);
    memcpy(out + hdr_size + 1, &svc, sizeof(svc));

    return PM3_SUCCESS;
}

static bool check_write_req_data(const felica_write_request_haeder_t *hdr, const uint8_t datalen) {
    if (!hdr || !datalen)
        return false;

    uint8_t num = *(hdr->number_of_block);
    if (num != 1 && num != 2)
        return false;

    // Check Block data size
    if (num * 16 != datalen)
        return false;

    return true;
}

static int write_without_encryption(
    const uint8_t *idm,
    uint8_t num,
    uint8_t *blk_numbers,
    const uint8_t *data,
    size_t datalen,
    uint8_t *out,
    uint16_t *n) {

    felica_write_request_haeder_t hdr = {
        .command_code = { 0x08 },
        .number_of_service = { 1 },
        .service_code_list = { 0x009 },
        .number_of_block = { num },
    };
    memcpy(hdr.IDm, idm, sizeof(hdr.IDm));

    uint8_t dl = (uint8_t)(datalen);

    if (check_write_req_data(&hdr, dl) == false) {
        PrintAndLogEx(FAILED, "invalid request");
        return PM3_EINVARG;
    }

    uint16_t blk[num];
    int ret = felica_make_block_list(blk, blk_numbers, num);
    if (ret) {
        return PM3_EINVARG;
    }


    size_t hdr_size = sizeof(hdr);
    size_t offset = hdr_size + (num * 2) + 1;

    uint8_t size = hdr_size + sizeof(blk) + dl + 1;
    *n = size;

    memcpy(out, &(uint8_t) { size }, sizeof(uint8_t));
    memcpy(out + 1, &hdr, hdr_size);
    memcpy(out + hdr_size + 1, &blk, sizeof(blk));
    memcpy(out + offset, data, dl);

    return PM3_SUCCESS;
}

static int parse_multiple_block_data(const uint8_t *data, const size_t datalen, uint8_t *out, uint8_t *outlen) {
    if (datalen < 3) {
        PrintAndLogEx(ERR, "\ndata size must be at least 3 bytes");
        return PM3_EINVARG;
    }

    felica_status_response_t res;
    memcpy(&res, data, sizeof(res));

    uint8_t empty[8] = {0};

    if (!memcmp(res.frame_response.IDm, empty, sizeof(empty))) {
        PrintAndLogEx(ERR, "internal error");
        return PM3_ERFTRANS;
    }


    if (res.status_flags.status_flag1[0] != 0x00 || res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "error status");
        return PM3_ERFTRANS;
    }

    size_t res_size = sizeof(res);

    uint8_t num = 0;
    memcpy(&num, data + res_size, sizeof(uint8_t));
    res_size++;

    memcpy(out, data + res_size, num * FELICA_BLK_SIZE);

    if (outlen) {
        *outlen = num * FELICA_BLK_SIZE;
    }

    return PM3_SUCCESS;
}

static int felica_auth_context_init(
    mbedtls_des3_context *ctx,
    const uint8_t *rc,
    const size_t rclen,
    const uint8_t *key,
    const size_t keylen,
    felica_auth_context_t *auth_ctx) {

    int ret = PM3_SUCCESS;

    uint8_t rev_rc[16], rev_key[16];
    uint8_t encrypted_sk[16], rev_sk[16];
    uint8_t iv[8] = {0};

    if (!ctx || !auth_ctx || rclen != 16 || keylen != 16) {
        PrintAndLogEx(ERR, "\nfelica_auth_context_init: invalid parameters");
        return PM3_EINVARG;
    }

    SwapEndian64ex(rc, sizeof(rev_rc), 8, rev_rc);
    memcpy(auth_ctx->random_challenge, rev_rc, sizeof(auth_ctx->random_challenge));

    SwapEndian64ex(key, sizeof(rev_key), 8, rev_key);

    if (mbedtls_des3_set2key_enc(ctx, rev_key) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    if (mbedtls_des3_crypt_cbc(ctx, MBEDTLS_DES_ENCRYPT, 16, iv, rev_rc, encrypted_sk) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    SwapEndian64ex(encrypted_sk, sizeof(encrypted_sk), 8, rev_sk);

    memcpy(auth_ctx->session_key, rev_sk, sizeof(auth_ctx->session_key));

cleanup:
    mbedtls_platform_zeroize(rev_rc, sizeof(rev_rc));
    mbedtls_platform_zeroize(rev_key, sizeof(rev_key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(encrypted_sk, sizeof(encrypted_sk));
    mbedtls_platform_zeroize(rev_sk, sizeof(rev_sk));

    return ret;
}

static void felica_auth_context_free(felica_auth_context_t *auth_ctx) {
    if (!auth_ctx) {
        return;
    }

    mbedtls_platform_zeroize(auth_ctx->session_key, sizeof(auth_ctx->session_key));
    mbedtls_platform_zeroize(auth_ctx->random_challenge, sizeof(auth_ctx->random_challenge));
}

static int felica_generate_mac(
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    const uint8_t *initialize_block,
    const uint8_t *block_data,
    const size_t length,
    bool use_read_key,
    uint8_t *mac) {

    int ret = PM3_SUCCESS;

    uint8_t rev_sk[FELICA_BLK_SIZE];
    uint8_t iv[8], rev_block[8], out[8];

    if (!ctx || !auth_ctx || !initialize_block || !block_data || !mac) {
        return PM3_EINVARG;
    }

    if (length % FELICA_BLK_HALF != 0) {
        return PM3_EINVARG;
    }

    uint8_t sk[FELICA_BLK_SIZE];

    if (use_read_key == false) {
        memcpy(sk, auth_ctx->session_key + 8, 8);
        memcpy(sk + 8, auth_ctx->session_key, 8);
    } else {
        memcpy(sk, auth_ctx->session_key, sizeof(auth_ctx->session_key));
    }

    SwapEndian64ex(sk, sizeof(sk), 8, rev_sk);

    memcpy(iv, auth_ctx->random_challenge, sizeof(iv));

    SwapEndian64ex(initialize_block, sizeof(rev_block), 8, rev_block);

    if (mbedtls_des3_set2key_enc(ctx, rev_sk) != 0) {
        ret = PM3_ECRYPTO;
        goto cleanup;
    }

    for (int i = 0; i <= length; i += 8) {
        if (mbedtls_des3_crypt_cbc(ctx, MBEDTLS_DES_ENCRYPT, sizeof(rev_block), iv, rev_block, out) != 0) {
            ret = PM3_ECRYPTO;
            goto cleanup;
        }
        memcpy(iv, out, sizeof(iv));
        SwapEndian64ex(block_data + i, 8, 8, rev_block);
    }

    SwapEndian64ex(out, FELICA_BLK_HALF, 8, mac);

cleanup:
    mbedtls_platform_zeroize(sk, sizeof(sk));
    mbedtls_platform_zeroize(rev_sk, sizeof(rev_sk));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(out, sizeof(out));
    mbedtls_platform_zeroize(rev_block, sizeof(rev_block));

    return ret;
}

static int write_with_mac(
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    const uint8_t *counter,
    const uint8_t blk_number,
    const uint8_t *block_data,
    uint8_t *out) {

    uint8_t initialize_blk[FELICA_BLK_HALF];
    memset(initialize_blk, 0, sizeof(initialize_blk));

    uint8_t wcnt[3];
    memcpy(wcnt, counter, 3);

    memcpy(initialize_blk, wcnt, sizeof(wcnt));
    initialize_blk[4] = blk_number;
    initialize_blk[6] = 0x91;

    uint8_t mac[FELICA_BLK_HALF];

    int ret = felica_generate_mac(ctx, auth_ctx, initialize_blk, block_data, FELICA_BLK_SIZE, false, mac);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    uint8_t payload[FELICA_BLK_SIZE * 2];
    memset(payload, 0, sizeof(payload));

    memcpy(payload, block_data, FELICA_BLK_SIZE);
    memcpy(payload + FELICA_BLK_SIZE, mac, sizeof(mac));
    memcpy(payload + FELICA_BLK_SIZE + sizeof(mac), wcnt, sizeof(wcnt));

    memcpy(out, payload, sizeof(payload));

    return PM3_SUCCESS;
}

static int felica_internal_authentication(
    const uint8_t *idm,
    const uint8_t *rc,
    const size_t rclen,
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    bool verbose) {

    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    uint8_t blk_numbers[1] = {FELICA_BLK_NUMBER_RC};

    uint16_t datalen = 0;

    int ret = write_without_encryption(idm, (uint8_t)sizeof(blk_numbers), blk_numbers, rc, rclen, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW | FELICA_NO_DISCONNECT);

    felica_status_response_t res;
    if (send_write_without_encryption(flags, datalen, data, false, &res) != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (res.status_flags.status_flag1[0] != 0x00 || res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "\nError RC Write");
        return PM3_ERFTRANS;
    }

    memset(data, 0, sizeof(data));

    uint8_t blk_numbers2[2] = {FELICA_BLK_NUMBER_ID, FELICA_BLK_NUMBER_MACA};

    ret = read_without_encryption(idm, (uint8_t)sizeof(blk_numbers2), blk_numbers2, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    felica_read_without_encryption_response_t rd_resp;
    memset(&rd_resp, 0, sizeof(rd_resp));

    ret = send_read_without_encryption(flags, datalen, data, false, &rd_resp);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t pd[FELICA_BLK_SIZE * sizeof(blk_numbers2)];
    memset(pd, 0, sizeof(pd));

    uint8_t pd_len = 0;
    ret = parse_multiple_block_data((const uint8_t *)&rd_resp, sizeof(rd_resp), pd, &pd_len);
    if (ret || pd_len != sizeof(pd)) {
        return PM3_ERFTRANS;
    }

    uint8_t id_blk[FELICA_BLK_SIZE];
    memcpy(id_blk, pd, FELICA_BLK_SIZE);

    uint8_t mac_blk[FELICA_BLK_SIZE];
    memcpy(mac_blk, pd + FELICA_BLK_SIZE, FELICA_BLK_SIZE);

    uint8_t initialize_blk[8];
    memset(initialize_blk, 0xFF, sizeof(initialize_blk));

    initialize_blk[0] = FELICA_BLK_NUMBER_ID;
    initialize_blk[1] = 0x00;
    initialize_blk[2] = FELICA_BLK_NUMBER_MACA;
    initialize_blk[3] = 0x00;

    uint8_t mac[FELICA_BLK_HALF];

    ret = felica_generate_mac(ctx, auth_ctx, initialize_blk, id_blk, sizeof(id_blk), true, mac);
    if (ret) {
        return PM3_ERFTRANS;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "MAC_A: %s", sprint_hex(mac, sizeof(mac)));
    }

    if (memcmp(mac_blk, mac, FELICA_BLK_HALF) != 0) {
        PrintAndLogEx(ERR, "\nInternal Authenticate: " _RED_("Failed"));
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Internal Authenticate: " _GREEN_("OK"));

    return PM3_SUCCESS;
}

static int felica_external_authentication(
    const uint8_t *idm,
    mbedtls_des3_context *ctx,
    const felica_auth_context_t *auth_ctx,
    bool keep) {

    uint8_t data[PM3_CMD_DATA_SIZE_MIX];
    memset(data, 0, sizeof(data));

    uint8_t flags = (FELICA_APPEND_CRC | FELICA_RAW | FELICA_NO_DISCONNECT);

    uint16_t datalen = 0;

    uint8_t blk_numbers[1] = {FELICA_BLK_NUMBER_WCNT};

    int ret = read_without_encryption(idm, (uint8_t)sizeof(blk_numbers), blk_numbers, data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    felica_read_without_encryption_response_t rd_resp;
    memset(&rd_resp, 0, sizeof(rd_resp));

    ret = send_read_without_encryption(flags, datalen, data, false, &rd_resp);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t wcnt_blk[FELICA_BLK_SIZE];
    uint8_t wcnt_len = 0;
    ret = parse_multiple_block_data((const uint8_t *)&rd_resp, sizeof(rd_resp), wcnt_blk, &wcnt_len);
    if (ret || wcnt_len != sizeof(wcnt_blk)) {
        return PM3_ERFTRANS;
    }

    uint8_t ext_auth[FELICA_BLK_SIZE];
    memset(ext_auth, 0, sizeof(ext_auth));

    ext_auth[0] = 1; // After Authenticate

    uint8_t mac_w[FELICA_BLK_SIZE * 2];

    ret = write_with_mac(ctx, auth_ctx, wcnt_blk, FELICA_BLK_NUMBER_STATE, ext_auth, mac_w);
    if (ret) {
        return PM3_ERFTRANS;
    }

    uint8_t blk_numbers2[2] = {FELICA_BLK_NUMBER_STATE, FELICA_BLK_NUMBER_MACA};

    ret = write_without_encryption(idm, (uint8_t)sizeof(blk_numbers2), blk_numbers2, mac_w, sizeof(mac_w), data, &datalen);
    if (ret) {
        return PM3_ERFTRANS;
    }

    if (keep == false) {
        flags &= ~FELICA_NO_DISCONNECT;
    }

    felica_status_response_t res;
    if (send_write_without_encryption(flags, datalen, data, false, &res) != PM3_SUCCESS) {
        return PM3_ERFTRANS;
    }

    if (res.status_flags.status_flag1[0] != 0x00 || res.status_flags.status_flag2[0] != 0x00) {
        PrintAndLogEx(ERR, "\nExternal Authenticate: " _RED_("Failed"));
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "External Authenticate: " _GREEN_("OK"));

    return PM3_SUCCESS;
}

static int felica_mutual_authentication(
    const uint8_t *idm,
    const uint8_t *rc,
    const size_t rclen,
    const uint8_t *key,
    const size_t keylen,
    bool keep,
    bool verbose) {

    int ret = PM3_SUCCESS;

    mbedtls_des3_context des3_ctx;
    mbedtls_des3_init(&des3_ctx);

    felica_auth_context_t auth_ctx;

    ret = felica_auth_context_init(&des3_ctx, rc, rclen, key, keylen, &auth_ctx);
    if (ret) {
        goto cleanup;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Session Key(SK): %s", sprint_hex(auth_ctx.session_key, sizeof(auth_ctx.session_key)));
    }

    ret = felica_internal_authentication(idm, rc, rclen, &des3_ctx, &auth_ctx, verbose);
    if (ret) {
        goto cleanup;
    }

    ret = felica_external_authentication(idm, &des3_ctx, &auth_ctx, keep);
    if (ret) {
        goto cleanup;
    }

cleanup:
    mbedtls_des3_free(&des3_ctx);
    felica_auth_context_free(&auth_ctx);

    return ret;
}

/**
 * Command parser for liteauth.
 * @param Cmd input data of the user.
 * @return client result code.
 */
static int CmdHFFelicaAuthenticationLite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica liteauth",
                  "Authenticate",
                  "hf felica liteauth --idm 11100910C11BC407\n"
                  "hf felica liteauth --key 46656c69436130313233343536616263\n"
                  "hf felica liteauth --key 46656c69436130313233343536616263 -k\n"
                  "hf felica liteauth -c 701185c59f8d30afeab8e4b3a61f5cc4 --key 46656c69436130313233343536616263"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "key", "<hex>", "set card key, 16 bytes"),
        arg_str0("c", "", "<hex>", "set random challenge, 16 bytes"),
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_lit0("k", "", "keep signal field ON after receive"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t key[FELICA_BLK_SIZE];
    memset(key, 0, sizeof(key));
    int keylen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t rc[FELICA_BLK_SIZE];
    memset(rc, 0, sizeof(rc));
    int rclen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), rc, sizeof(rc), &rclen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t idm[8];
    memset(idm, 0, sizeof(idm));
    int ilen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 3), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool keep_field_on = arg_get_lit(ctx, 4);

    CLIParserFree(ctx);

    res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, idm);
    if (res != PM3_SUCCESS) {
        return res;
    }

    int ret = PM3_SUCCESS;

    PrintAndLogEx(INFO, "Card Key: %s", sprint_hex(key, sizeof(key)));
    PrintAndLogEx(INFO, "Random Challenge(RC): %s", sprint_hex(rc, sizeof(rc)));

    PrintAndLogEx(SUCCESS, "FeliCa lite - auth started");

    ret = felica_mutual_authentication(idm, rc, sizeof(rc), key, sizeof(key), keep_field_on, true);
    if (ret) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static void printSep(void) {
    PrintAndLogEx(INFO, "------------------------------------------------------------------------------------");
}

static uint16_t PrintFliteBlock(uint16_t tracepos, uint8_t *trace, uint16_t tracelen) {
    if (tracepos + 19 >= tracelen)
        return tracelen;

    trace += tracepos;
    uint8_t blocknum = trace[0];
    uint8_t status1 = trace[1];
    uint8_t status2 = trace[2];

    bool error = (status1 != 0x00 && (status2 == 0xB1 || status2 == 0xB2));

    char line[110] = {0};
    for (int j = 0; j < 16; j++) {
        if (error) {
            snprintf(line + (j * 4), sizeof(line) - 1 - (j * 4), "??  ");
        } else {
            snprintf(line + (j * 4), sizeof(line) - 1 - (j * 4), "%02x  ", trace[j + 3]);
        }
    }

    PrintAndLogEx(NORMAL, "block number %02x, status: %02x %02x", blocknum, status1, status2);
    switch (blocknum) {
        case 0x00:
            PrintAndLogEx(NORMAL,  "S_PAD0: %s", line);
            break;
        case 0x01:
            PrintAndLogEx(NORMAL,  "S_PAD1: %s", line);
            break;
        case 0x02:
            PrintAndLogEx(NORMAL,  "S_PAD2: %s", line);
            break;
        case 0x03:
            PrintAndLogEx(NORMAL,  "S_PAD3: %s", line);
            break;
        case 0x04:
            PrintAndLogEx(NORMAL,  "S_PAD4: %s", line);
            break;
        case 0x05:
            PrintAndLogEx(NORMAL,  "S_PAD5: %s", line);
            break;
        case 0x06:
            PrintAndLogEx(NORMAL,  "S_PAD6: %s", line);
            break;
        case 0x07:
            PrintAndLogEx(NORMAL,  "S_PAD7: %s", line);
            break;
        case 0x08:
            PrintAndLogEx(NORMAL,  "S_PAD8: %s", line);
            break;
        case 0x09:
            PrintAndLogEx(NORMAL,  "S_PAD9: %s", line);
            break;
        case 0x0a:
            PrintAndLogEx(NORMAL,  "S_PAD10: %s", line);
            break;
        case 0x0b:
            PrintAndLogEx(NORMAL,  "S_PAD11: %s", line);
            break;
        case 0x0c:
            PrintAndLogEx(NORMAL,  "S_PAD12: %s", line);
            break;
        case 0x0d:
            PrintAndLogEx(NORMAL,  "S_PAD13: %s", line);
            break;
        case 0x0E: {
            uint32_t regA = trace[3] | trace[4] << 8 | trace[5] << 16 | trace[6] << 24;
            uint32_t regB = trace[7] | trace[8] << 8 | trace[9] << 16 | trace[10] << 24;
            line[0] = 0;
            for (int j = 0; j < 8; j++)
                snprintf(line + (j * 2), sizeof(line) - 1 - (j * 2), "%02x", trace[j + 11]);

            if (error) {
                PrintAndLogEx(NORMAL,  "REG: regA: ???????? regB: ???????? regC: ???????????????? ");
            } else {
                PrintAndLogEx(NORMAL,  "REG: regA: %d regB: %d regC: %s ", regA, regB, line);
            }
        }
        break;
        case 0x80:
            PrintAndLogEx(NORMAL,  "Random Challenge, WO:  %s ", line);
            break;
        case 0x81:
            PrintAndLogEx(NORMAL,  "MAC, only set on dual read:  %s ", line);
            break;
        case 0x82: {
            char idd[20];
            char idm[20];
            for (int j = 0; j < 8; j++)
                snprintf(idd + (j * 2), sizeof(idd) - 1 - (j * 2), "%02x", trace[j + 3]);

            for (int j = 0; j < 6; j++)
                snprintf(idm + (j * 2), sizeof(idm) - 1 - (j * 2), "%02x", trace[j + 13]);

            PrintAndLogEx(NORMAL,  "ID Block, IDd: 0x%s DFC: 0x%02x%02x Arb: %s ", idd, trace[11], trace [12], idm);
        }
        break;
        case 0x83: {
            char idm[20];
            char pmm[20];
            for (int j = 0; j < 8; j++)
                snprintf(idm + (j * 2), sizeof(idm) - 1 - (j * 2), "%02x", trace[j + 3]);

            for (int j = 0; j < 8; j++)
                snprintf(pmm + (j * 2), sizeof(pmm) - 1 - (j * 2), "%02x", trace[j + 11]);

            PrintAndLogEx(NORMAL,  "DeviceId:  IDm: 0x%s PMm: 0x%s ", idm, pmm);
        }
        break;
        case 0x84:
            PrintAndLogEx(NORMAL,  "SER_C: 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x85:
            PrintAndLogEx(NORMAL,  "SYS_Cl 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x86:
            PrintAndLogEx(NORMAL,  "CKV (key version): 0x%02x%02x ", trace[3], trace[4]);
            break;
        case 0x87:
            PrintAndLogEx(NORMAL,  "CK (card key), WO:   %s ", line);
            break;
        case 0x88: {
            PrintAndLogEx(NORMAL,  "Memory Configuration (MC):");
            PrintAndLogEx(NORMAL,  "MAC needed to write state: %s", trace[3 + 12] ? "on" : "off");
            //order might be off here...
            PrintAndLogEx(NORMAL,  "Write with MAC for S_PAD  : %s ", sprint_bin(trace + 3 + 10, 2));
            PrintAndLogEx(NORMAL,  "Write with AUTH for S_PAD : %s ", sprint_bin(trace + 3 + 8, 2));
            PrintAndLogEx(NORMAL,  "Read after AUTH for S_PAD : %s ", sprint_bin(trace + 3 + 6, 2));
            PrintAndLogEx(NORMAL,  "MAC needed to write CK and CKV: %s", trace[3 + 5] ? "on" : "off");
            PrintAndLogEx(NORMAL,  "RF parameter: %02x", (trace[3 + 4] & 0x7));
            PrintAndLogEx(NORMAL,  "Compatible with NDEF: %s", trace[3 + 3] ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "Memory config writable : %s", (trace[3 + 2] == 0xff) ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "RW access for S_PAD : %s ", sprint_bin(trace + 3, 2));
        }
        break;
        case 0x90: {
            PrintAndLogEx(NORMAL,  "Write counter, RO:   %02x %02x %02x ", trace[3], trace[4], trace[5]);
        }
        break;
        case 0x91: {
            PrintAndLogEx(NORMAL,  "MAC_A, RW (auth):   %s ", line);
        }
        break;
        case 0x92:
            PrintAndLogEx(NORMAL,  "State:");
            PrintAndLogEx(NORMAL,  "Polling disabled: %s", trace[3 + 8] ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "Authenticated: %s", trace[3] ? "yes" : "no");
            break;
        case 0xa0:
            PrintAndLogEx(NORMAL,  "CRC of all blocks match : %s", (trace[3 + 2] == 0xff) ? "no" : "yes");
            break;
        default:
            PrintAndLogEx(WARNING,  "INVALID %d: %s", blocknum, line);
            break;
    }
    return tracepos + 19;
}

static int CmdHFFelicaDumpLite(const char *Cmd) {

    /*
    iceman 2021,
    Why does this command say it dumps a FeliCa lite card
    and then tries to print a trace?!?
    Is this a trace list or a FeliCa dump cmd?
    */


    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica litedump",
                  "Dump ISO/18092 FeliCa Lite tag.  It will timeout after 200sec",
                  "hf felica litedump"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "idm", "<hex>", "set custom IDm"),
        arg_str0(NULL, "key", "<hex>", "set card key, 16 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t idm[8];
    memset(idm, 0, sizeof(idm));
    int ilen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idm, sizeof(idm), &ilen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[FELICA_BLK_SIZE];
    memset(key, 0, sizeof(key));
    int keylen = 0;
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), key, sizeof(key), &keylen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (keylen != 0) {
        res = felica_ensure_target_present(idm, (size_t)ilen, FELICA_IDM_RESOLVE_STANDALONE, idm);
        if (res != PM3_SUCCESS) {
            return res;
        }

        uint8_t rc[FELICA_BLK_SIZE] = {0};

        int ret = felica_mutual_authentication(idm, rc, sizeof(rc), key, sizeof(key), true, false);
        if (ret) {
            PrintAndLogEx(WARNING, "Authenticate Failed");
        }
    }

    PrintAndLogEx(NORMAL, "");

    PrintAndLogEx(SUCCESS, "FeliCa lite - dump started");

    clearCommandBuffer();
    SendCommandNG(CMD_HF_FELICALITE_DUMP, NULL, 0);
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to abort dumping");

    uint8_t timeout = 0;
    while (WaitForResponseTimeout(CMD_HF_FELICALITE_DUMP, &resp, 2000) == false) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "\naborted via keyboard!");
            return PM3_EOPABORTED;
        }

        timeout++;
        PrintAndLogEx(INPLACE, "% 3i", timeout);

        fflush(stdout);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }
        if (timeout > 10) {
            PrintAndLogEx(WARNING, "\ntimeout while waiting for reply");
            DropField();
            return PM3_ETIMEOUT;
        }
    }

    PrintAndLogEx(NORMAL, "");

    if (resp.status == PM3_EOPABORTED) {
        PrintAndLogEx(WARNING, "Button pressed, aborted");
        return PM3_EOPABORTED;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "FeliCa lite dump failed (%d)", resp.status);
        return resp.status;
    }

    if (resp.length < sizeof(felica_lite_dump_resp_t)) {
        PrintAndLogEx(WARNING, "Unexpected dump response length");
        return PM3_ESOFT;
    }

    felica_lite_dump_resp_t *dump_resp = (felica_lite_dump_resp_t *)resp.data.asBytes;
    if (dump_resp->completed == 0) {
        PrintAndLogEx(WARNING, "Button pressed, aborted");
        return PM3_EOPABORTED;
    }

    uint16_t tracelen = dump_resp->tracelen;
    if (tracelen == 0) {
        PrintAndLogEx(WARNING, "No trace data! Maybe not a FeliCa Lite card?");
        return PM3_ESOFT;
    }

    uint8_t *trace = calloc(tracelen, sizeof(uint8_t));
    if (trace == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    if (GetFromDevice(BIG_BUF, trace, tracelen, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(trace);
        return PM3_ETIMEOUT;
    }


    PrintAndLogEx(SUCCESS, "Recorded Activity (trace len = %"PRIu32" bytes)", (uint32_t)tracelen);
    print_hex_break(trace, tracelen, 32);
    printSep();

    uint16_t tracepos = 0;
    while (tracepos < tracelen)
        tracepos = PrintFliteBlock(tracepos, trace, tracelen);

    printSep();

    free(trace);
    return PM3_SUCCESS;
}

static int CmdHFFelicaCmdRaw(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf felica raw ",
                  "Send raw hex data to tag",
                  "hf felica raw -cs 20\n"
                  "hf felica raw -cs 2008"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  NULL, "active signal field ON without select"),
        arg_lit0("c",  NULL, "calculate and append CRC"),
        arg_lit0("k",  NULL, "keep signal field ON after receive"),
        arg_u64_0("n", NULL, "<dec>", "number of bits"),
        arg_lit0("r",  NULL, "do not read response"),
        arg_lit0("s",  NULL, "active signal field ON with select"),
        arg_str1(NULL, NULL, "<hex>", "raw bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool active = arg_get_lit(ctx, 1);
    bool crc = arg_get_lit(ctx, 2);
    bool keep_field_on = arg_get_lit(ctx, 3);
    uint16_t numbits = arg_get_u32_def(ctx, 4, 0) & 0xFFFF;
    bool reply = (arg_get_lit(ctx, 5) == false);
    bool active_select = arg_get_lit(ctx, 6);

    int datalen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    memset(data, 0, sizeof(data));

    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    uint8_t flags = 0;

    if (crc) {
        flags |= FELICA_APPEND_CRC;
    }

    if (active || active_select) {
        flags |= FELICA_CONNECT | FELICA_CLEARTRACE;
        if (active) {
            flags |= FELICA_NO_SELECT;
        }
    }

    if (keep_field_on) {
        flags |= FELICA_NO_DISCONNECT;
    }

    if (datalen > 0) {
        flags |= FELICA_RAW;
    }

    // FeliCa length byte includes itself, so raw payload must be <= 254 bytes.
    if (datalen > 254) {
        PrintAndLogEx(FAILED, "FeliCa raw payload too long (%d). Max is 254 bytes.", datalen);
        return PM3_EINVARG;
    }

    // Max transport buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    PrintAndLogEx(SUCCESS, "Data: %s", sprint_hex(data, datalen));

    clear_and_send_command_ex(flags, datalen, data, numbits, false, false);

    if (reply) {

        if (active_select) {
            PrintAndLogEx(SUCCESS, "Active select wait for FeliCa.");
            PacketResponseNG resp_IDm;
            if (waitCmdFelica(true, &resp_IDm, true) == false) {
                return PM3_ERFTRANS;
            }
        }

        if (datalen) {
            PacketResponseNG resp_frame;
            if (waitCmdFelica(false, &resp_frame, true) == false) {
                return PM3_ERFTRANS;
            }
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",            CmdHelp,                          AlwaysAvailable, "This help"},
    {"list",            CmdHFFelicaList,                  AlwaysAvailable, "List ISO 18092/FeliCa history"},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("Operations") " -----------------------"},
    {"info",            CmdHFFelicaInfo,                  IfPm3Felica,     "Tag information"},
    {"seacinfo",        CmdHFFelicaSeacInfo,              IfPm3Felica,     "FeliCa SEAC tag information"},
    {"raw",             CmdHFFelicaCmdRaw,                IfPm3Felica,     "Send raw hex data to tag"},
    {"rdbl",            CmdHFFelicaReadPlain,             IfPm3Felica,     "read block data from authentication-not-required Service."},
    {"reader",          CmdHFFelicaReader,                IfPm3Felica,     "Act like an ISO18092/FeliCa reader"},
    {"sniff",           CmdHFFelicaSniff,                 IfPm3Felica,     "Sniff ISO 18092/FeliCa traffic"},
    {"wrbl",            CmdHFFelicaWritePlain,            IfPm3Felica,     "write block data to an authentication-not-required Service."},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("FeliCa Standard") " -----------------------"},
    {"dump",            CmdHFFelicaDump,                  IfPm3Felica,     "Wait for and try dumping FeliCa"},
    {"discnodes",       CmdHFFelicaDiscoverNodes,         IfPm3Felica,     "discover Area Code and Service Code nodes."},
    {"sim",             CmdHFFelicaSim,                   IfPm3Felica,     "Emulate FeliCa Standard from dump file"},
    {"rqservice",       CmdHFFelicaRequestService,        IfPm3Felica,     "verify the existence of Area and Service, and to acquire Key Version."},
    {"rqresponse",      CmdHFFelicaRequestResponse,       IfPm3Felica,     "verify the existence of a card and its Mode."},
    {"scsvcode",        CmdHFFelicaDumpServiceArea,       IfPm3Felica,     "acquire Area Code and Service Code."},
    {"rqsyscode",       CmdHFFelicaRequestSystemCode,     IfPm3Felica,     "acquire System Code registered to the card."},
    {"auth1",           CmdHFFelicaAuthentication1,       IfPm3Felica,     "authenticate a card. Start mutual authentication with Auth1"},
    {"auth2",           CmdHFFelicaAuthentication2,       IfPm3Felica,     "allow a card to authenticate a Reader/Writer. Complete mutual authentication"},
    //{"read",          CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"write",         CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "write Block Data to an authentication-required Service."},
    //{"scsvcodev2",    CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "verify the existence of Area or Service, and to acquire Key Version."},
    //{"getsysstatus",  CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "acquire the setup information in System."},
    {"rqspecver",       CmdHFFelicaRequestSpecificationVersion, IfPm3Felica,  "acquire the version of card OS."},
    {"resetmode",       CmdHFFelicaResetMode,             IfPm3Felica,     "reset Mode to Mode 0."},
    //{"auth1v2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "authenticate a card."},
    //{"auth2v2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "allow a card to authenticate a Reader/Writer."},
    //{"readv2",        CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "read Block Data from authentication-required Service."},
    //{"writev2",       CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "write Block Data to authentication-required Service."},
    //{"uprandomid",    CmdHFFelicaNotImplementedYet,     IfPm3Felica,     "update Random ID (IDr)."},
    {"-----------",     CmdHelp,                          AlwaysAvailable, "----------------------- " _CYAN_("FeliCa Light") " -----------------------"},
    {"litesim",         CmdHFFelicaSimLite,               IfPm3Felica,     "Emulating ISO/18092 FeliCa Lite tag"},
    {"liteauth",        CmdHFFelicaAuthenticationLite,    IfPm3Felica,     "authenticate a card."},
    {"litedump",        CmdHFFelicaDumpLite,              IfPm3Felica,     "Wait for and try dumping FelicaLite"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFFelica(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
