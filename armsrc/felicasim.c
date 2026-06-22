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
#include "felicasim.h"

#include "felica.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "util.h"
#include "protocols.h"
#include "crc16.h"
#include "fpgaloader.h"
#include "string.h"
#include "commonutil.h"
#include "dbprint.h"
#include "ticks.h"
#include "iso18.h"

#define AddCrc(data, len) compute_crc(CRC_FELICA, (data), (len), (data)+(len)+1, (data)+(len))

#define FELICA_SIM_SYSTEM_MAX 16U
#define FELICA_SIM_STATUS_SERVICE_COUNT_ERROR 0xA1U
#define FELICA_SIM_STATUS_BLOCK_COUNT_ERROR 0xA2U
#define FELICA_SIM_STATUS_ILLEGAL_BLOCK_LIST_SERVICE_ORDER 0xA3U
#define FELICA_SIM_STATUS_ILLEGAL_SERVICE_CODE_LIST 0xA6U
#define FELICA_SIM_STATUS_ACCESS_MODE_ERROR 0xA7U
#define FELICA_SIM_STATUS_BLOCK_NOT_FOUND 0xA8U
#define FELICA_SIM_STATUS_AUTH_REQUIRED 0xB1U

static uint32_t felica_sim_model_len;
static uint32_t felica_sim_model_uploaded;
static uint16_t felica_sim_model_crc;
static uint8_t felica_sim_rwe_error_location_indication = FELICA_SIM_RWE_ERROR_LOCATION_MASK;

typedef struct {
    const felica_sim_node_record_t *node;
    uint16_t block_number;
} felica_sim_read_ref_t;

static const felica_sim_system_record_t *felica_sim_systems(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    return (const felica_sim_system_record_t *)(model + hdr->system_offset);
}

static const felica_sim_node_record_t *felica_sim_nodes(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    return (const felica_sim_node_record_t *)(model + hdr->node_offset);
}

static const felica_sim_block_record_t *felica_sim_blocks(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    return (const felica_sim_block_record_t *)(model + hdr->block_offset);
}

static const uint8_t *felica_sim_metadata(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    return model + hdr->metadata_offset;
}

static bool felica_sim_range_fits(uint32_t offset, uint32_t count, uint32_t elem_size, uint32_t total_len) {
    return offset <= total_len && elem_size != 0 && count <= ((total_len - offset) / elem_size);
}

static uint16_t felica_sim_crc_model(uint8_t *model, uint32_t len) {
    if (model == NULL || len < sizeof(felica_sim_model_header_t)) {
        return 0;
    }

    felica_sim_model_header_t *hdr = (felica_sim_model_header_t *)model;
    const uint16_t stored_crc = hdr->model_crc;
    hdr->model_crc = 0;
    const uint16_t crc = Crc16ex(CRC_XMODEM, model, len);
    hdr->model_crc = stored_crc;
    return crc;
}

static int felica_sim_validate_model(uint8_t *model, uint32_t len, const felica_sim_model_header_t **hdr_out) {
    if (model == NULL || len < sizeof(felica_sim_model_header_t) || hdr_out == NULL) {
        return PM3_EINVARG;
    }

    const felica_sim_model_header_t *hdr = (const felica_sim_model_header_t *)model;
    if (hdr->magic != FELICA_SIM_MODEL_MAGIC ||
            hdr->version != FELICA_SIM_MODEL_VERSION ||
            hdr->header_len != sizeof(felica_sim_model_header_t) ||
            hdr->total_len != len ||
            hdr->reserved != 0) {
        return PM3_EINVARG;
    }

    if (hdr->system_count == 0 || hdr->system_count > FELICA_SIM_SYSTEM_MAX) {
        return PM3_EINVARG;
    }

    if (felica_sim_crc_model(model, len) != hdr->model_crc) {
        return PM3_ECRC;
    }

    const uint32_t metadata_len = (uint32_t)hdr->specification_version_len +
                                  hdr->product_information_len +
                                  hdr->container_issue_information_len;
    if (hdr->specification_version_len > FELICA_SIM_SPECIFICATION_VERSION_MAX_LEN ||
            hdr->product_information_len > FELICA_SIM_PRODUCT_INFORMATION_MAX_LEN ||
            (hdr->container_issue_information_len != 0 &&
             hdr->container_issue_information_len != FELICA_SIM_CONTAINER_ISSUE_INFORMATION_LEN)) {
        return PM3_EINVARG;
    }

    if (felica_sim_range_fits(hdr->system_offset, hdr->system_count, sizeof(felica_sim_system_record_t), len) == false ||
            felica_sim_range_fits(hdr->node_offset, hdr->node_count, sizeof(felica_sim_node_record_t), len) == false ||
            felica_sim_range_fits(hdr->block_offset, hdr->block_count, sizeof(felica_sim_block_record_t), len) == false ||
            hdr->metadata_offset > len ||
            metadata_len > (len - hdr->metadata_offset)) {
        return PM3_EINVARG;
    }

    const uint32_t expected_node_offset = hdr->system_offset + (hdr->system_count * sizeof(felica_sim_system_record_t));
    const uint32_t expected_block_offset = hdr->node_offset + (hdr->node_count * sizeof(felica_sim_node_record_t));
    const uint32_t expected_metadata_offset = hdr->block_offset + (hdr->block_count * sizeof(felica_sim_block_record_t));
    const uint32_t expected_total_len = expected_metadata_offset + metadata_len;
    if (hdr->system_offset != hdr->header_len ||
            hdr->node_offset != expected_node_offset ||
            hdr->block_offset != expected_block_offset ||
            hdr->metadata_offset != expected_metadata_offset ||
            hdr->total_len != expected_total_len) {
        return PM3_EINVARG;
    }

    if (hdr->specification_version_len) {
        const uint8_t *metadata = felica_sim_metadata(hdr, model);
        if (hdr->specification_version_len < 4U ||
                hdr->specification_version_len != 4U + ((uint16_t)metadata[3] * 2U)) {
            return PM3_EINVARG;
        }
    }

    const felica_sim_system_record_t *systems = felica_sim_systems(hdr, model);
    const felica_sim_node_record_t *nodes = felica_sim_nodes(hdr, model);
    const felica_sim_block_record_t *blocks = felica_sim_blocks(hdr, model);

    for (uint16_t i = 0; i < hdr->system_count; i++) {
        if ((uint32_t)systems[i].first_node + systems[i].node_count > hdr->node_count) {
            return PM3_EINVARG;
        }
    }

    const uint8_t valid_node_flags = FELICA_SIM_NODE_TYPE_MASK |
                                     FELICA_SIM_NODE_HAS_DES_KEY_VERSION |
                                     FELICA_SIM_NODE_HAS_AES_KEY_VERSION;
    for (uint16_t i = 0; i < hdr->node_count; i++) {
        const uint8_t node_type = nodes[i].flags & FELICA_SIM_NODE_TYPE_MASK;
        if ((nodes[i].flags & ~valid_node_flags) != 0 ||
                node_type == 0 ||
                nodes[i].system_index >= hdr->system_count ||
                (uint32_t)nodes[i].first_block + nodes[i].block_count > hdr->block_count) {
            return PM3_EINVARG;
        }
    }

    for (uint16_t i = 0; i < hdr->block_count; i++) {
        if (blocks[i].node_index >= hdr->node_count) {
            return PM3_EINVARG;
        }
    }

    *hdr_out = hdr;
    return PM3_SUCCESS;
}

static bool felica_sim_enc_has_aes(uint8_t encryption_identifier) {
    switch (encryption_identifier) {
        case FELICA_ENCRYPTION_IDENTIFIER_AES128:
        case FELICA_ENCRYPTION_IDENTIFIER_AES128_DES112:
        case FELICA_ENCRYPTION_IDENTIFIER_AES128_DES56:
            return true;
        default:
            return false;
    }
}

static bool felica_sim_enc_has_des(uint8_t encryption_identifier) {
    switch (encryption_identifier) {
        case FELICA_ENCRYPTION_IDENTIFIER_AES128_DES112:
        case FELICA_ENCRYPTION_IDENTIFIER_AES128_DES56:
        case FELICA_ENCRYPTION_IDENTIFIER_DES112:
        case FELICA_ENCRYPTION_IDENTIFIER_DES56:
            return true;
        default:
            return false;
    }
}

static uint8_t felica_sim_effective_encryption_identifier(const felica_sim_system_record_t *system) {
    return system->encryption_identifier ? system->encryption_identifier : FELICA_ENCRYPTION_IDENTIFIER_DES56;
}

static uint8_t felica_sim_node_type(const felica_sim_node_record_t *node) {
    return node ? (node->flags & FELICA_SIM_NODE_TYPE_MASK) : 0;
}

static bool felica_sim_node_is_service(const felica_sim_node_record_t *node) {
    return felica_sim_node_type(node) == FELICA_SIM_NODE_TYPE_SERVICE;
}

static bool felica_sim_node_is_area(const felica_sim_node_record_t *node) {
    return felica_sim_node_type(node) == FELICA_SIM_NODE_TYPE_AREA;
}

static bool felica_sim_node_is_system(const felica_sim_node_record_t *node) {
    return felica_sim_node_type(node) == FELICA_SIM_NODE_TYPE_SYSTEM;
}

static bool felica_sim_service_allows_read_without_encryption(const felica_sim_node_record_t *node) {
    if (felica_sim_node_is_service(node) == false) {
        return false;
    }

    const uint8_t attribute = node->node_code_le & FELICA_NODE_ATTRIBUTE_MASK;
    return (attribute & FELICA_SERVICE_ATTRIBUTE_UNAUTH_READ) &&
           ((attribute & FELICA_SERVICE_ATTRIBUTE_PIN_REQUIRED) == 0);
}

static uint8_t felica_sim_response_begin(uint8_t *resp, uint8_t command) {
    resp[0] = 0xb2;
    resp[1] = 0x4d;
    resp[2] = 0;
    resp[3] = command;
    return 4;
}

static uint16_t felica_sim_response_finish(uint8_t *resp, uint16_t pos) {
    if (pos < 4 || (pos - 2) > 0xFFU) {
        return 0;
    }

    resp[2] = (uint8_t)(pos - 2);
    AddCrc(resp + 2, resp[2]);
    return resp[2] + 4U;
}

static uint16_t felica_sim_process_echo(const uint8_t *req, uint16_t req_len, uint8_t *resp) {
    if (req_len < 3 ||
            req[3] != ((FELICA_ECHO_REQ >> 8) & 0xFFU) ||
            req[4] != (FELICA_ECHO_REQ & 0xFFU)) {
        return 0;
    }

    resp[0] = 0xb2;
    resp[1] = 0x4d;
    memcpy(resp + 2, req + 2, req_len);
    AddCrc(resp + 2, resp[2]);
    return resp[2] + 4U;
}

static void felica_sim_append_idm(uint8_t *resp, uint16_t *pos, const felica_sim_system_record_t *system) {
    memcpy(resp + *pos, system->idm, sizeof(system->idm));
    *pos += sizeof(system->idm);
}

static uint16_t felica_sim_rwe_error_response(uint8_t *resp, const felica_sim_system_record_t *system, uint8_t status1, uint8_t status2) {
    uint16_t pos = felica_sim_response_begin(resp, FELICA_RDBLK_ACK);
    felica_sim_append_idm(resp, &pos, system);
    resp[pos++] = status1;
    resp[pos++] = status2;
    return felica_sim_response_finish(resp, pos);
}

static uint8_t felica_sim_rwe_error_status1(uint8_t list_index) {
    switch (felica_sim_rwe_error_location_indication) {
        case FELICA_SIM_RWE_ERROR_LOCATION_INDEX:
            return list_index + 1U;
        case FELICA_SIM_RWE_ERROR_LOCATION_FLAG:
            return 0xFFU;
        case FELICA_SIM_RWE_ERROR_LOCATION_MASK:
        default:
            // Bit-data location wraps: bit 0 indicates the 1st or 9th list element.
            return (uint8_t)(1U << (list_index & 0x07U));
    }
}

static const felica_sim_system_record_t *felica_sim_find_system_by_code(const felica_sim_model_header_t *hdr, const uint8_t *model, uint16_t code, uint16_t *index_out) {
    const felica_sim_system_record_t *systems = felica_sim_systems(hdr, model);
    for (uint16_t i = 0; i < hdr->system_count; i++) {
        if (systems[i].system_code == code) {
            if (index_out) {
                *index_out = i;
            }
            return &systems[i];
        }
    }
    return NULL;
}

static const felica_sim_node_record_t *felica_sim_find_node(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                            const felica_sim_system_record_t *system, uint16_t node_code_le) {
    const felica_sim_node_record_t *nodes = felica_sim_nodes(hdr, model);
    const uint16_t end = system->first_node + system->node_count;
    for (uint16_t i = system->first_node; i < end; i++) {
        if (nodes[i].node_code_le == node_code_le) {
            return &nodes[i];
        }
    }
    return NULL;
}

static const felica_sim_block_record_t *felica_sim_find_block(const felica_sim_model_header_t *hdr, const uint8_t *model,
        const felica_sim_node_record_t *node, uint16_t block_number) {
    const felica_sim_block_record_t *blocks = felica_sim_blocks(hdr, model);
    const uint16_t end = node->first_block + node->block_count;
    for (uint16_t i = node->first_block; i < end; i++) {
        if (blocks[i].block_number == block_number) {
            return &blocks[i];
        }
    }
    return NULL;
}

static bool felica_sim_idm_matches(const uint8_t *req, const felica_sim_system_record_t *system) {
    return memcmp(req + 4, system->idm, sizeof(system->idm)) == 0;
}

static const uint8_t *felica_sim_specification_version_data(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    return hdr->specification_version_len ? felica_sim_metadata(hdr, model) : NULL;
}

static const uint8_t *felica_sim_product_information_data(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    if (hdr->product_information_len == 0) {
        return NULL;
    }

    return felica_sim_metadata(hdr, model) + hdr->specification_version_len;
}

static const uint8_t *felica_sim_container_issue_information_data(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    if (hdr->container_issue_information_len == 0) {
        return NULL;
    }

    return felica_sim_metadata(hdr, model) + hdr->specification_version_len + hdr->product_information_len;
}

static uint16_t felica_sim_process_polling(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                           const uint8_t *req, uint16_t req_len,
                                           uint16_t *active_system_index, uint8_t *resp) {
    if (req_len != 6) {
        return 0;
    }

    const uint16_t requested_system_code = ((uint16_t)req[4] << 8) | req[5];
    uint16_t selected_index = 0;
    const felica_sim_system_record_t *selected = NULL;
    if (requested_system_code == 0xFFFFU) {
        selected = felica_sim_systems(hdr, model);
        selected_index = 0;
    } else {
        selected = felica_sim_find_system_by_code(hdr, model, requested_system_code, &selected_index);
        if (selected == NULL) {
            return 0;
        }
    }

    const uint8_t request_code = req[6];
    if (request_code > 0x02U) {
        return 0;
    }

    *active_system_index = selected_index;

    static uint8_t timeslot = 0;
    if (timeslot > req[7]) {
        timeslot = 0;
    }
    felica_nexttransfertime = GetCountSspClk() -
                              FELICA_212K_CARRIER_TO_TIMER_TICKS(DELAY_AIR2ARM_AS_READER + DELAY_ARM2AIR_AS_READER) +
                              (512 + timeslot * 256) + 1;
    timeslot++;

    uint16_t pos = felica_sim_response_begin(resp, FELICA_POLL_ACK);
    memcpy(resp + pos, selected->idm, sizeof(selected->idm));
    pos += sizeof(selected->idm);
    memcpy(resp + pos, selected->pmm, sizeof(selected->pmm));
    pos += sizeof(selected->pmm);

    if (request_code == 0x01U) {
        resp[pos++] = (selected->system_code >> 8) & 0xFFU;
        resp[pos++] = selected->system_code & 0xFFU;
    } else if (request_code == 0x02U) {
        resp[pos++] = 0x00;
        resp[pos++] = 0x01;
    }

    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request_system_code(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                       const uint8_t *req, uint16_t req_len,
                                                       const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len != 10 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_REQSYSCODE_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = (uint8_t)hdr->system_count;
    const felica_sim_system_record_t *systems = felica_sim_systems(hdr, model);
    for (uint16_t i = 0; i < hdr->system_count; i++) {
        resp[pos++] = (systems[i].system_code >> 8) & 0xFFU;
        resp[pos++] = systems[i].system_code & 0xFFU;
    }
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_get_container_id(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                    const uint8_t *req, uint16_t req_len, uint8_t *resp) {
    if (req_len != sizeof(felica_get_container_id_request_t) ||
            req[4] != 0x00 ||
            req[5] != 0x00) {
        return 0;
    }

    const felica_sim_system_record_t *system = felica_sim_find_system_by_code(hdr, model, SYSTEMCODE_OSAIFU_KEITAI, NULL);
    if (system == NULL) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_GET_CONTAINER_ID_ACK);
    memcpy(resp + pos, system->idm, sizeof(system->idm));
    pos += sizeof(system->idm);
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request_response(const uint8_t *req, uint16_t req_len,
                                                    const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len != 10 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_REQRESP_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_reset_mode(const uint8_t *req, uint16_t req_len,
                                              const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len != 12 ||
            felica_sim_idm_matches(req, active_system) == false ||
            req[12] != 0x00 ||
            req[13] != 0x00) {
        return 0;
    }

    // If authentication handling is added, reset the tracked card mode to Mode0 here.
    uint16_t pos = felica_sim_response_begin(resp, FELICA_RESET_MODE_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request_specification_version(const felica_sim_model_header_t *hdr, const uint8_t *model,
        const uint8_t *req, uint16_t req_len,
        const felica_sim_system_record_t *active_system, uint8_t *resp) {
    const uint8_t *specification_version = felica_sim_specification_version_data(hdr, model);
    if (specification_version == NULL ||
            req_len != 12 ||
            felica_sim_idm_matches(req, active_system) == false ||
            req[12] != 0x00 ||
            req[13] != 0x00) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_REQUEST_SPEC_VERSION_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    memcpy(resp + pos, specification_version, hdr->specification_version_len);
    pos += hdr->specification_version_len;
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_get_product_information(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                           const uint8_t *req, uint16_t req_len,
                                                           const felica_sim_system_record_t *active_system, uint8_t *resp) {
    const uint8_t *product_information = felica_sim_product_information_data(hdr, model);
    if (product_information == NULL ||
            req_len != 10 ||
            felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_GETPLATFORMINFO_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = (uint8_t)hdr->product_information_len;
    memcpy(resp + pos, product_information, hdr->product_information_len);
    pos += hdr->product_information_len;
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_get_container_issue_information(const felica_sim_model_header_t *hdr, const uint8_t *model,
        const uint8_t *req, uint16_t req_len,
        const felica_sim_system_record_t *active_system, uint8_t *resp) {
    const uint8_t *container_issue_information = felica_sim_container_issue_information_data(hdr, model);
    if (container_issue_information == NULL ||
            req_len != 12 ||
            felica_sim_idm_matches(req, active_system) == false ||
            req[12] != 0x00 ||
            req[13] != 0x00) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_GET_CONTAINER_ISSUE_INFO_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    memcpy(resp + pos, container_issue_information, hdr->container_issue_information_len);
    pos += hdr->container_issue_information_len;
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request_service(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                   const uint8_t *req, uint16_t req_len,
                                                   const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len < 11 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    const uint8_t node_count = req[12];
    const uint16_t expected_len = 11U + (2U * node_count);
    if (node_count == 0 || req_len != expected_len) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_REQSRV_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = node_count;
    for (uint8_t i = 0; i < node_count; i++) {
        const uint16_t node_code_le = req[13 + (i * 2U)] | ((uint16_t)req[14 + (i * 2U)] << 8);
        const felica_sim_node_record_t *node = felica_sim_find_node(hdr, model, active_system, node_code_le);
        uint16_t key_version_le = 0xFFFFU;
        if (node && (node->flags & FELICA_SIM_NODE_HAS_DES_KEY_VERSION)) {
            key_version_le = node->des_key_version_le;
        }
        resp[pos++] = key_version_le & 0xFFU;
        resp[pos++] = (key_version_le >> 8) & 0xFFU;
    }
    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request_service_v2(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                      const uint8_t *req, uint16_t req_len,
                                                      const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len < 11 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    const uint8_t node_count = req[12];
    const uint16_t expected_len = 11U + (2U * node_count);
    if (node_count == 0 || req_len != expected_len) {
        return 0;
    }

    const uint8_t encryption_identifier = felica_sim_effective_encryption_identifier(active_system);
    const bool has_aes = felica_sim_enc_has_aes(encryption_identifier);
    const bool has_des = felica_sim_enc_has_des(encryption_identifier);
    const uint16_t response_len = 1U + 1U + 8U + 2U + 1U + 1U + (2U * node_count) + (has_des ? (2U * node_count) : 0U);
    if (response_len > 0xFFU) {
        return 0;
    }

    uint16_t pos = felica_sim_response_begin(resp, FELICA_REQSRV2_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = encryption_identifier;
    resp[pos++] = node_count;

    for (uint8_t pass = 0; pass < 2; pass++) {
        if (pass == 1 && has_des == false) {
            break;
        }

        for (uint8_t i = 0; i < node_count; i++) {
            const uint16_t node_code_le = req[13 + (i * 2U)] | ((uint16_t)req[14 + (i * 2U)] << 8);
            const felica_sim_node_record_t *node = felica_sim_find_node(hdr, model, active_system, node_code_le);
            uint16_t key_version_le = 0xFFFFU;
            if (node) {
                if (pass == 0 && has_aes && (node->flags & FELICA_SIM_NODE_HAS_AES_KEY_VERSION)) {
                    key_version_le = node->aes_key_version_le;
                } else if (pass == 1 && (node->flags & FELICA_SIM_NODE_HAS_DES_KEY_VERSION)) {
                    key_version_le = node->des_key_version_le;
                }
            }
            resp[pos++] = key_version_le & 0xFFU;
            resp[pos++] = (key_version_le >> 8) & 0xFFU;
        }
    }

    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_search_service_code(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                       const uint8_t *req, uint16_t req_len,
                                                       const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len != 12 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    const uint16_t iterator = req[12] | ((uint16_t)req[13] << 8);
    uint16_t pos = felica_sim_response_begin(resp, FELICA_SRCHSYSCODE_ACK);
    felica_sim_append_idm(resp, &pos, active_system);

    const felica_sim_node_record_t *nodes = felica_sim_nodes(hdr, model);
    const felica_sim_node_record_t *node = NULL;
    const uint16_t end = active_system->first_node + active_system->node_count;
    uint16_t visible_index = 0;
    for (uint16_t i = active_system->first_node; i < end; i++) {
        if (felica_sim_node_is_system(&nodes[i])) {
            continue;
        }
        if (visible_index == iterator) {
            node = &nodes[i];
            break;
        }
        visible_index++;
    }

    if (node == NULL) {
        resp[pos++] = 0xFF;
        resp[pos++] = 0xFF;
        return felica_sim_response_finish(resp, pos);
    }

    resp[pos++] = node->node_code_le & 0xFFU;
    resp[pos++] = (node->node_code_le >> 8) & 0xFFU;
    if (felica_sim_node_is_area(node)) {
        resp[pos++] = node->end_code_le & 0xFFU;
        resp[pos++] = (node->end_code_le >> 8) & 0xFFU;
    }

    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_read_without_encryption(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                                           const uint8_t *req, uint16_t req_len,
                                                           const felica_sim_system_record_t *active_system, uint8_t *resp) {
    if (req_len < 14 || felica_sim_idm_matches(req, active_system) == false) {
        return 0;
    }

    const uint16_t end = 2U + req_len;
    const uint8_t service_count = req[12];
    if (service_count == 0 || service_count > 16U) {
        return felica_sim_rwe_error_response(resp, active_system, 0xFFU, FELICA_SIM_STATUS_SERVICE_COUNT_ERROR);
    }

    uint16_t pos = 13U;
    if ((uint16_t)(pos + (2U * service_count) + 1U) > end) {
        return 0;
    }

    const felica_sim_node_record_t *service_nodes[16] = {0};
    for (uint8_t i = 0; i < service_count; i++) {
        const uint16_t service_code_le = req[pos] | ((uint16_t)req[pos + 1] << 8);
        pos += 2;
        service_nodes[i] = felica_sim_find_node(hdr, model, active_system, service_code_le);
    }

    const uint8_t block_count = req[pos++];
    if (block_count == 0 || block_count > 15U) {
        return felica_sim_rwe_error_response(resp, active_system, 0xFFU, FELICA_SIM_STATUS_BLOCK_COUNT_ERROR);
    }

    felica_sim_read_ref_t refs[15] = {0};
    for (uint8_t i = 0; i < block_count; i++) {
        if (pos >= end) {
            return 0;
        }

        const uint8_t d0 = req[pos++];
        const uint8_t service_order = d0 & 0x0FU;
        const uint8_t access_mode = (d0 >> 4) & 0x07U;
        const bool extended = (d0 & 0x80U) == 0;
        if (service_order >= service_count) {
            return felica_sim_rwe_error_response(resp, active_system, felica_sim_rwe_error_status1(i), FELICA_SIM_STATUS_ILLEGAL_BLOCK_LIST_SERVICE_ORDER);
        }
        if (access_mode != 0U) {
            return felica_sim_rwe_error_response(resp, active_system, felica_sim_rwe_error_status1(i), FELICA_SIM_STATUS_ACCESS_MODE_ERROR);
        }

        uint16_t block_number = 0;
        if (extended) {
            if ((uint16_t)(pos + 2U) > end) {
                return 0;
            }
            block_number = req[pos] | ((uint16_t)req[pos + 1] << 8);
            pos += 2;
        } else {
            if ((uint16_t)(pos + 1U) > end) {
                return 0;
            }
            block_number = req[pos++];
        }

        refs[i].node = service_nodes[service_order];
        refs[i].block_number = block_number;
        if (felica_sim_node_is_service(refs[i].node) == false) {
            return felica_sim_rwe_error_response(resp, active_system, felica_sim_rwe_error_status1(i), FELICA_SIM_STATUS_ILLEGAL_SERVICE_CODE_LIST);
        }
        if (felica_sim_service_allows_read_without_encryption(refs[i].node) == false) {
            return felica_sim_rwe_error_response(resp, active_system, felica_sim_rwe_error_status1(i), FELICA_SIM_STATUS_AUTH_REQUIRED);
        }
        if (felica_sim_find_block(hdr, model, refs[i].node, block_number) == NULL) {
            return felica_sim_rwe_error_response(resp, active_system, felica_sim_rwe_error_status1(i), FELICA_SIM_STATUS_BLOCK_NOT_FOUND);
        }
    }

    if (pos != end) {
        return 0;
    }

    pos = felica_sim_response_begin(resp, FELICA_RDBLK_ACK);
    felica_sim_append_idm(resp, &pos, active_system);
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = block_count;

    for (uint8_t i = 0; i < block_count; i++) {
        const felica_sim_block_record_t *block = felica_sim_find_block(hdr, model, refs[i].node, refs[i].block_number);
        if (block == NULL || (uint16_t)(pos + 16U) > (FELICA_MAX_RF_FRAME_SIZE - 2U)) {
            return 0;
        }
        memcpy(resp + pos, block->data, sizeof(block->data));
        pos += sizeof(block->data);
    }

    return felica_sim_response_finish(resp, pos);
}

static uint16_t felica_sim_process_request(const felica_sim_model_header_t *hdr, const uint8_t *model,
                                           const felica_frame_t *request, uint16_t *active_system_index,
                                           uint8_t *resp) {
    if (request == NULL || request->crc_ok == false || request->len < 6 || request->framebytes[2] < 2) {
        return 0;
    }

    const uint8_t *req = request->framebytes;
    const uint16_t req_len = req[2];
    if ((uint16_t)(req_len + 4U) != request->len) {
        return 0;
    }

    const felica_sim_system_record_t *systems = felica_sim_systems(hdr, model);
    const felica_sim_system_record_t *active_system = &systems[*active_system_index];

    uint16_t req_command = req[3];
    if (req[3] >= 0xC0U && req_len >= 3U) {
        req_command = ((uint16_t)req[3] << 8) | req[4];
    }

    switch (req_command) {
        case FELICA_POLL_REQ:
            return felica_sim_process_polling(hdr, model, req, req_len, active_system_index, resp);
        case FELICA_ECHO_REQ:
            return felica_sim_process_echo(req, req_len, resp);
        case FELICA_GET_CONTAINER_ID_REQ:
            return felica_sim_process_get_container_id(hdr, model, req, req_len, resp);
        case FELICA_REQSYSCODE_REQ:
            return felica_sim_process_request_system_code(hdr, model, req, req_len, active_system, resp);
        case FELICA_REQRESP_REQ:
            return felica_sim_process_request_response(req, req_len, active_system, resp);
        case FELICA_RESET_MODE_REQ:
            return felica_sim_process_reset_mode(req, req_len, active_system, resp);
        case FELICA_REQUEST_SPEC_VERSION_REQ:
            return felica_sim_process_request_specification_version(hdr, model, req, req_len, active_system, resp);
        case FELICA_GETPLATFORMINFO_REQ:
            return felica_sim_process_get_product_information(hdr, model, req, req_len, active_system, resp);
        case FELICA_GET_CONTAINER_ISSUE_INFO_REQ:
            return felica_sim_process_get_container_issue_information(hdr, model, req, req_len, active_system, resp);
        case FELICA_REQSRV_REQ:
            return felica_sim_process_request_service(hdr, model, req, req_len, active_system, resp);
        case FELICA_REQSRV2_REQ:
            return felica_sim_process_request_service_v2(hdr, model, req, req_len, active_system, resp);
        case FELICA_SRCHSYSCODE_REQ:
            return felica_sim_process_search_service_code(hdr, model, req, req_len, active_system, resp);
        case FELICA_RDBLK_REQ:
            return felica_sim_process_read_without_encryption(hdr, model, req, req_len, active_system, resp);
        default:
            return 0;
    }
}

static uint32_t felica_sim_trace_offset(uint32_t model_len) {
    return (model_len + 3U) & ~3U;
}

static void felica_sim_log_request(const felica_frame_t *request) {
    if (request == NULL) {
        return;
    }

    LogTrace(
        request->framebytes,
        request->len,
        felica_timer_to_carrier_periods(request->startTime, false) - DELAY_AIR2ARM_AS_READER,
        felica_timer_to_carrier_periods(request->endTime, false) - DELAY_AIR2ARM_AS_READER,
        NULL,
        true
    );
}

static void felica_sim_preserve_trace(uint32_t trace_offset) {
    set_tracing(false);

    const uint32_t trace_len = BigBuf_get_traceLen();
    if (trace_len <= trace_offset) {
        clear_trace();
        return;
    }

    const uint32_t captured_len = trace_len - trace_offset;
    memmove(BigBuf_get_addr(), BigBuf_get_addr() + trace_offset, captured_len);
    set_tracelen(captured_len);
}

static int felica_sim_standard_loop(const felica_sim_model_header_t *hdr, const uint8_t *model) {
    const uint32_t model_len = hdr->total_len;
    const uint32_t trace_offset = felica_sim_trace_offset(hdr->total_len);
    if (iso18092_setup_ex(FPGA_HF_ISO18092_FLAG_NOMOD, trace_offset) == false) {
        return PM3_EMALLOC;
    }

    const felica_sim_model_header_t *validated_hdr = NULL;
    int retval = felica_sim_validate_model((uint8_t *)model, model_len, &validated_hdr);
    if (retval != PM3_SUCCESS) {
        felica_reset_frame_mode();
        return retval;
    }
    hdr = validated_hdr;

    set_tracelen(trace_offset);
    set_tracing(true);

    Dbprintf("FeliCa Standard simulation start. Systems: %u, nodes: %u, blocks: %u",
             hdr->system_count, hdr->node_count, hdr->block_count);

    retval = PM3_SUCCESS;
    uint16_t active_system_index = 0;
    uint8_t resp[FELICA_MAX_RF_FRAME_SIZE] = {0};

    uint8_t flip = 0;
    uint16_t checker = 0;
    for (;;) {
        WDT_HIT();

        if (flip == 3) {
            if (data_available()) {
                retval = PM3_EOPABORTED;
                break;
            }
            flip = 0;
        }

        if (checker >= 3000) {
            if (BUTTON_PRESS()) {
                retval = PM3_EOPABORTED;
                break;
            }
            flip++;
            checker = 0;
        }
        ++checker;

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
            Process18092Byte(&FelicaFrame, dist, felica_get_rx_byte_start_time());

            if (FelicaFrame.state == STATE_FULL) {
                if (FelicaFrame.crc_ok) {
                    felica_sim_log_request(&FelicaFrame);
                    const uint16_t resp_len = felica_sim_process_request(hdr, model, &FelicaFrame, &active_system_index, resp);
                    if (resp_len) {
                        TransmitFor18092_AsReaderEx(resp, resp_len, NULL, 0, 0, false);
                        FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO18092 | FPGA_HF_ISO18092_FLAG_NOMOD);
                    }
                }
                FelicaFrameReset(&FelicaFrame);
            }
        }
    }

    felica_reset_frame_mode();
    felica_sim_preserve_trace(trace_offset);
    set_tracing(true);
    Dbprintf("FeliCa Standard emulator stopped. Trace length: %d", BigBuf_get_traceLen());
    return retval;
}

void felicasim_standard(const PacketCommandNG *c) {
    if (c == NULL || c->ng == false || c->length < sizeof(felica_sim_upload_t)) {
        reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
        return;
    }

    const felica_sim_upload_t *payload = (const felica_sim_upload_t *)c->data.asBytes;
    const uint32_t total_len = payload->total_len;
    const uint32_t offset = payload->offset;
    const uint16_t chunk_len = payload->chunk_len;

    switch (payload->subcommand) {
        case FELICA_SIM_CLEAR:
            /*
             * FpgaDownloadAndGo() clears BigBuf when the bitstream is not
             * already loaded. Do this before accepting the model upload so a
             * first simulator run cannot wipe the freshly uploaded model.
             */
#if defined XC3
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
#else
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF_FELICA);
#endif
            felica_sim_model_len = 0;
            felica_sim_model_uploaded = 0;
            felica_sim_model_crc = 0;
            BigBuf_free();
            clear_trace();
            reply_ng(CMD_HF_FELICA_SIMULATE, PM3_SUCCESS, NULL, 0);
            return;

        case FELICA_SIM_LOAD: {
            const uint32_t bigbuf_size = BigBuf_get_size();
            if (chunk_len == 0 ||
                    c->length < sizeof(felica_sim_upload_t) + chunk_len ||
                    total_len == 0 ||
                    bigbuf_size < FELICA_SIM_RUNTIME_RESERVE ||
                    total_len > bigbuf_size - FELICA_SIM_RUNTIME_RESERVE ||
                    offset > total_len ||
                    chunk_len > total_len - offset) {
                reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
                return;
            }

            if (offset == 0) {
                felica_sim_model_len = total_len;
                felica_sim_model_uploaded = 0;
                felica_sim_model_crc = payload->model_crc;
                BigBuf_free();
                clear_trace();
            } else if (total_len != felica_sim_model_len ||
                       payload->model_crc != felica_sim_model_crc ||
                       offset != felica_sim_model_uploaded) {
                reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
                return;
            }

            memcpy(BigBuf_get_addr() + offset, payload->data, chunk_len);
            felica_sim_model_uploaded = offset + chunk_len;
            reply_ng(CMD_HF_FELICA_SIMULATE, PM3_SUCCESS, NULL, 0);
            return;
        }

        case FELICA_SIM_START: {
            if (felica_sim_model_len == 0 ||
                    felica_sim_model_uploaded != felica_sim_model_len ||
                    total_len != felica_sim_model_len ||
                    payload->model_crc != felica_sim_model_crc) {
                reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
                return;
            }

            if (payload->rwe_error_location_indication > FELICA_SIM_RWE_ERROR_LOCATION_FLAG) {
                reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
                return;
            }
            felica_sim_rwe_error_location_indication = payload->rwe_error_location_indication;

            uint8_t *model = BigBuf_get_addr();
            const felica_sim_model_header_t *hdr = NULL;
            int status = felica_sim_validate_model(model, felica_sim_model_len, &hdr);
            if (status != PM3_SUCCESS) {
                reply_ng(CMD_HF_FELICA_SIMULATE, status, NULL, 0);
                return;
            }

            status = felica_sim_standard_loop(hdr, model);
            reply_ng(CMD_HF_FELICA_SIMULATE, status, NULL, 0);
            return;
        }

        default:
            reply_ng(CMD_HF_FELICA_SIMULATE, PM3_EINVARG, NULL, 0);
            return;
    }
}
