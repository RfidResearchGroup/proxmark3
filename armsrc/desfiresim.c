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

#include "desfiresim.h"

#include "BigBuf.h"
#include "dbprint.h"
#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_virtual_picc.h"
#include "dfc_port_pm3.h"
#include "pm3_cmd.h"

#include <string.h>

static DfcCredential *s_credential;
static DfcVirtualPiccSession *s_session;
static DfcVirtualPiccActivation s_activation;
static bool s_ready;
static bool s_activated;

static void desfire_sim_release_memory(void) {
    dfc_pm3_workspace_release();
    uint8_t *base = BigBuf_get_addr();
    uint8_t *emulator = BigBuf_get_EM_addr();
    uint32_t high = BigBuf_get_hi();

    // Credential, file, key, and session objects share this transient slice.
    if (base != NULL && emulator != NULL && base + high < emulator) {
        memset(base + high, 0, emulator - (base + high));
    }
    s_credential = NULL;
    BigBuf_free_keep_EM();
}

bool desfire_sim_flush(void) {
    if (!s_ready) {
        return false;
    }

    uint8_t *memory = BigBuf_get_EM_addr();
    size_t capacity = BigBuf_get_EM_size();
    size_t length = 0;
    if (memory == NULL) {
        return false;
    }
    DfcDerStatus status = dfc_der_encode(s_credential, memory, capacity, &length);
    if (status != DfcDerOk) {
        Dbprintf("Could not save DFCB credential: DER status %u", status);
        return false;
    }
    if (length < capacity) {
        memset(memory + length, 0, capacity - length);
    }
    return true;
}

bool desfire_sim_init(void) {
    if (s_ready && s_session != NULL) {
        return true;
    }
    if (s_session != NULL) {
        dfc_virtual_picc_session_free(s_session);
        s_session = NULL;
    }
    s_ready = false;
    s_activated = false;

    uint8_t *memory = BigBuf_get_EM_addr();
    size_t capacity = BigBuf_get_EM_size();
    size_t length = dfc_der_length(memory, capacity);
    if (length == 0) {
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("No DFCB credential in emulator memory");
        }
        return false;
    }

    s_credential = (DfcCredential *)BigBuf_calloc(sizeof(*s_credential));
    if (s_credential == NULL || !dfc_pm3_workspace_init()) {
        desfire_sim_release_memory();
        Dbprintf("Could not allocate DESFire emulator workspace");
        return false;
    }

    if (dfc_der_decode(s_credential, memory, length) != DfcDerOk) {
        Dbprintf("Invalid or unsupported DFCB credential");
        desfire_sim_release_memory();
        return false;
    }
    s_session = dfc_virtual_picc_session_alloc(s_credential);
    if (s_session == NULL ||
            dfc_virtual_picc_scan_iso14443a(s_session, &s_activation) != DfcVirtualPiccStatusOk) {
        if (s_session != NULL) {
            dfc_virtual_picc_session_free(s_session);
            s_session = NULL;
        }
        desfire_sim_release_memory();
        Dbprintf("Could not start DESFire emulator session");
        return false;
    }
    s_ready = true;
    s_activated = true;
    return true;
}

void desfire_sim_deinit(bool flush) {
    if (flush && s_ready) {
        desfire_sim_flush();
    }
    if (s_session != NULL) {
        dfc_virtual_picc_session_free(s_session);
        s_session = NULL;
    }
    s_ready = false;
    s_activated = false;
    dfc_pm3_random_clear();
    desfire_sim_release_memory();
}

bool desfire_sim_ready(void) {
    return s_ready;
}

void desfire_sim_identity(
    uint8_t *uid,
    uint8_t *uidlen,
    uint8_t *atqa,
    uint8_t *sak,
    uint8_t *ats,
    uint8_t *atslen) {
    if (!s_ready) {
        return;
    }
    if (uid != NULL) {
        memcpy(uid, s_activation.uid, s_activation.uid_len);
    }
    if (uidlen != NULL) {
        *uidlen = s_activation.uid_len;
    }
    if (atqa != NULL) {
        memcpy(atqa, s_activation.atqa, s_activation.atqa_len);
    }
    if (sak != NULL) {
        *sak = s_activation.sak;
    }
    if (ats != NULL) {
        memcpy(ats, s_activation.ats, s_activation.ats_len);
    }
    if (atslen != NULL) {
        *atslen = s_activation.ats_len;
    }
}

void desfire_sim_reset(void) {
    if (s_ready) {
        dfc_virtual_picc_reset_protocol(s_session);
    }
}

uint16_t desfire_sim_apdu(const uint8_t *input, uint16_t input_length, uint8_t *output) {
    if (!s_ready || input == NULL || output == NULL) {
        return 0;
    }

    size_t output_length = 0;
    DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_exchange(
                                      s_session,
                                      input,
                                      input_length,
                                      output,
                                      DESFIRE_SIM_MAX_RESP,
                                      &output_length);
    if (status != DfcVirtualPiccStatusOk) {
        return 0;
    }
    return (uint16_t)output_length;
}

uint16_t desfire_sim_frame(const uint8_t *input, uint16_t input_length, uint8_t *output) {
    if (!s_ready || input == NULL || output == NULL) {
        return 0;
    }

    size_t output_length = 0;
    DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_frame_exchange(
                                      s_session,
                                      input,
                                      input_length,
                                      output,
                                      DESFIRE_SIM_MAX_RESP,
                                      &output_length);
    return status == DfcVirtualPiccStatusOk ? (uint16_t)output_length : 0;
}

void desfire_sim_print_banner(void) {
    if (!s_ready) {
        return;
    }
    Dbprintf(
        "Simulating DESFire from DFCB, %u application(s), %u file(s)",
        (unsigned)s_credential->num_apps,
        (unsigned)s_credential->num_files);
}

int desfire_sim_control(
    uint8_t operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length) {
    if (output_length == NULL) {
        return PM3_EINVARG;
    }
    *output_length = 0;

    if (operation == DFC_SIM_BEGIN) {
        // Release a previous session before reusing its BigBuf allocation.
        desfire_sim_deinit(true);
        return desfire_sim_init() ? PM3_SUCCESS : PM3_ESOFT;
    }
    if (operation == DFC_SIM_END) {
        bool saved = desfire_sim_flush();
        desfire_sim_deinit(false);
        return saved ? PM3_SUCCESS : PM3_ESOFT;
    }
    if (!s_ready || s_session == NULL) {
        return PM3_ESOFT;
    }

    switch (operation) {
        case DFC_SIM_SCAN: {
            if (dfc_virtual_picc_scan_iso14443a(s_session, &s_activation) !=
                    DfcVirtualPiccStatusOk || output_capacity < 5 + s_activation.uid_len +
                    s_activation.ats_len + s_activation.atqa_len) {
                return PM3_ESOFT;
            }
            s_activated = true;
            size_t offset = 0;
            output[offset++] = s_activation.uid_len;
            memcpy(output + offset, s_activation.uid, s_activation.uid_len);
            offset += s_activation.uid_len;
            output[offset++] = s_activation.atqa_len;
            memcpy(output + offset, s_activation.atqa, s_activation.atqa_len);
            offset += s_activation.atqa_len;
            output[offset++] = s_activation.sak;
            output[offset++] = s_activation.ats_len;
            memcpy(output + offset, s_activation.ats, s_activation.ats_len);
            offset += s_activation.ats_len;
            *output_length = offset;
            return PM3_SUCCESS;
        }
        case DFC_SIM_FIELD_OFF: {
            DfcVirtualPiccStatus status = dfc_virtual_picc_field_off(s_session);
            s_activated = false;
            return status == DfcVirtualPiccStatusOk ? PM3_SUCCESS : PM3_ESOFT;
        }
        case DFC_SIM_APDU:
        case DFC_SIM_FRAME: {
            if (!s_activated &&
                    dfc_virtual_picc_scan_iso14443a(s_session, &s_activation) !=
                    DfcVirtualPiccStatusOk) {
                return PM3_ESOFT;
            }
            s_activated = true;
            DfcVirtualPiccStatus status;
            if (operation == DFC_SIM_APDU) {
                status = dfc_virtual_picc_iso_dep_exchange(
                             s_session, input, input_length, output, output_capacity, output_length);
            } else {
                status = dfc_virtual_picc_iso_dep_frame_exchange(
                             s_session, input, input_length, output, output_capacity, output_length);
            }
            return status == DfcVirtualPiccStatusOk ? PM3_SUCCESS : PM3_ESOFT;
        }
        case DFC_SIM_RANDOM:
            dfc_pm3_random_set(input, input_length, true);
            return dfc_pm3_random_underflowed() ? PM3_EOVFLOW : PM3_SUCCESS;
        case DFC_SIM_ADVANCE: {
            if (input_length != 4) {
                return PM3_EINVARG;
            }
            uint32_t milliseconds = input[0] | ((uint32_t)input[1] << 8) |
                                    ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
            dfc_emulator_advance_time(s_session->emulator, milliseconds);
            return PM3_SUCCESS;
        }
        case DFC_SIM_CLEAR_DIRTY:
            s_credential->dirty = false;
            return PM3_SUCCESS;
        case DFC_SIM_STATE:
            if (output_capacity < 4) {
                return PM3_EOVFLOW;
            }
            output[0] = s_credential->dirty;
            output[1] = dfc_pm3_random_underflowed();
            output[2] = (uint8_t)dfc_pm3_random_remaining();
            output[3] = (uint8_t)(dfc_pm3_random_remaining() >> 8);
            *output_length = 4;
            return PM3_SUCCESS;
        default:
            return PM3_EINVARG;
    }
}
