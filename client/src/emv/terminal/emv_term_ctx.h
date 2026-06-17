//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — session context
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_CTX_H__
#define EMV_TERM_CTX_H__

#include "common.h"
#include "proxmark3.h"
#include "fileutils.h"
#include "../emvcore.h"
#include "../tlv.h"

typedef enum {
    EMV_PHASE_INIT = 0,
    EMV_PHASE_ODA,
    EMV_PHASE_RESTRICT,
    EMV_PHASE_CVM,
    EMV_PHASE_TRM,
    EMV_PHASE_TAA,
    EMV_PHASE_CAA,
    EMV_PHASE_ONLINE,
    EMV_PHASE_COMPLETE,
    EMV_PHASE_COUNT,
} emv_term_phase_t;

typedef enum {
    EMV_OUTCOME_UNKNOWN = 0,
    EMV_OUTCOME_APPROVED_OFFLINE,
    EMV_OUTCOME_DECLINED,
    EMV_OUTCOME_ONLINE_REQUIRED,
    EMV_OUTCOME_APPROVED_ONLINE,
    EMV_OUTCOME_ABORTED,
} emv_term_outcome_t;

#define EMVAC_AAC_BYTE   0x00
#define EMVAC_TC_BYTE    0x40
#define EMVAC_ARQC_BYTE  0x80

typedef struct {
    emv_term_phase_t id;
    int result;
    uint16_t sw;
    uint64_t ts_ms;
    uint32_t duration_ms;
    char note[128];
} emv_phase_event_t;

typedef struct {
    bool activate_field;
    bool show_apdu;
    bool decode_tlv;
    bool param_load_json;
    bool force_search;
    TransactionType_t tr_type;
    bool gen_ac_gpo;
    Iso7816CommandChannel channel;
    bool trace_phases;
    bool cvm_skip_online;
    bool use_terminal_profile;
    const char *pin;
    const char *output_session;
    const char *stop_after;
    const char *profile_path;
    const char *session_path;
    const char *arc;
    const char *arpc;
    const char *arpc_rc;
    const char *host_keys;
    const char *mock_apdu;
    const char *scheme_profile;
    bool auto_online;
    bool host_sim;
    bool continue_on_bad_arqc;
    bool record_apdu;
    const char *exception_file;
    const char *capk_extra;
    bool no_redact;
    bool full_tlv;
    const char *export_sim;
    const char *host_tcp;
    const char *pcap_out;
    const char *pcap_meta;
    bool timing_report;
    bool skip_banner;
    bool crypto_quick_afl;
    bool crypto_aid_fallback;
    bool crypto_stream_fast;
    uint8_t crypto_forced_aid[APDU_AID_LEN];
    size_t crypto_forced_aid_len;
} emv_term_cli_opts_t;

typedef struct emv_term_ctx {
    struct tlvdb *terminal;
    struct tlvdb *card;
    struct tlvdb *select;
    Iso7816CommandChannel channel;
    TransactionType_t tr_type;
    emv_term_outcome_t outcome;
    emv_term_phase_t current_phase;
    emv_phase_event_t *events;
    size_t event_count;
    size_t event_cap;
    uint8_t aid[APDU_AID_LEN];
    size_t aid_len;
    bool oda_performed;
    bool oda_success;
    bool cvm_performed;
    bool cvm_success;
    uint8_t cvm_results[3];
    uint8_t oda_list[4096];
    size_t oda_list_len;
    struct tlv *pdol_data_tlv;
    emv_term_cli_opts_t opts;
    char session_file[FILE_PATH_SIZE];
    uint8_t requested_ac;
    uint8_t ac1_cid;
    uint8_t ac2_cid;
    bool ac1_performed;
    bool ac2_performed;
    bool online_performed;
    bool online_success;
    bool restrict_failed;
    bool floor_limit_exceeded;
    uint8_t arc[2];
    uint8_t issuer_auth[32];
    size_t issuer_auth_len;
    uint8_t script71[256];
    size_t script71_len;
    uint8_t script72[256];
    size_t script72_len;
    uint8_t cdol1_data[256];
    size_t cdol1_len;
    char host_keys_path[FILE_PATH_SIZE];
    char scheme_name[32];
    bool host_arqc_ok;
    bool flash_skip_offline_pin;
    bool cda_verify_ok;
    bool cda_verify_performed;
    uint8_t online_pin_block[16];
    size_t online_pin_block_len;
    struct emv_term_exception_file *exception_file;
    char atr_hex[128];
    size_t atr_len;
    char host_tcp_arpc[128];
    char host_tcp_arpc_rc[16];
    bool host_tcp_applied;
    size_t crypto_ppse_app_count;
    size_t crypto_ppse_app_index;
    bool crypto_aid_fallback_used;
    bool crypto_stream_profile_valid;
    bool crypto_stream_qvsdc;
    uint8_t crypto_stream_cdol1[256];
    size_t crypto_stream_cdol1_len;
} emv_term_ctx_t;

const char *emv_term_phase_name(emv_term_phase_t phase);
const char *emv_term_outcome_str(emv_term_outcome_t outcome);

int emv_term_ctx_init(emv_term_ctx_t *ctx, const emv_term_cli_opts_t *opts);
void emv_term_ctx_free(emv_term_ctx_t *ctx);
int emv_term_cli_setup(emv_term_ctx_t *ctx);

int emv_term_event_add(emv_term_ctx_t *ctx, emv_term_phase_t phase, int result, uint16_t sw, const char *note);
int emv_term_event_add_timed(emv_term_ctx_t *ctx, emv_term_phase_t phase, int result, uint16_t sw,
                             const char *note, uint32_t duration_ms);

struct tlvdb *emv_term_get_root(emv_term_ctx_t *ctx);

#endif
