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
// EMV terminal emulator - Cardholder Verification (PIN / CVM)
//-----------------------------------------------------------------------------

#include "phase_cvm.h"
#include "../emv_pki.h"
#include "../crypto.h"
#include "emv_term_pin_prompt.h"
#include "emv_term_secure.h"
#include "emv_term_tvr.h"
#include "emv_term_tlv.h"
#include "ui.h"
#include "protocols.h"
#include "commonutil.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define CVM_PLAIN_OFFLINE       0x01
#define CVM_ENCIPHERED_ONLINE   0x02
#define CVM_ENCIPHERED_OFFLINE  0x04
#define CVM_SIGNATURE           0x1E
#define CVM_NO_CVM              0x1F
#define CVM_FAIL                0x00
#define CVM_NOT_ALLOWED         0x3F

#define CVM_COND_ALWAYS         0x00
#define CVM_COND_TERM_SUPPORTS  0x03
#define CVM_COND_AMT_LE_X       0x06
#define CVM_COND_AMT_GT_X      0x07
#define CVM_COND_AMT_LE_Y       0x08
#define CVM_COND_AMT_GT_Y       0x09

#define CVM_RESULT_UNKNOWN      0x00
#define CVM_RESULT_FAILED       0x01
#define CVM_RESULT_SUCCESS      0x02

static uint32_t cvm_get_amount(const unsigned char *S) {
    return ((uint32_t)S[0] << 24) | ((uint32_t)S[1] << 16) | ((uint32_t)S[2] << 8) | S[3];
}

#define TVR_OFFLINE_PIN_NOT_PERFORMED   (1 << 4)  // byte 3 bit 4
#define TVR_PIN_TRY_LIMIT_EXCEEDED      (1 << 2)  // byte 3 bit 6
#define TVR_ONLINE_PIN_ENTERED          (1 << 3)  // byte 3 bit 3

void emv_term_pin_zeroize(uint8_t *buf, size_t len) {
    emv_term_secure_zero(buf, len);
}

static const char *pin_from_opts_or_env(const emv_term_ctx_t *ctx) {
    if (ctx->opts.pin && ctx->opts.pin[0]) {
        return ctx->opts.pin;
    }
    const char *env = getenv("EMV_TEST_PIN");
    if (env && env[0]) {
        return env;
    }
    return NULL;
}

static const char *pin_prompt_interactive(emv_term_ctx_t *ctx, char *prompt_buf, size_t prompt_buf_len) {
    if (emv_term_pin_prompt("Enter offline PIN: ", prompt_buf, prompt_buf_len) == PM3_SUCCESS) {
        return prompt_buf;
    }
    return NULL;
}

static bool cvm_will_verify_offline_pin(const emv_term_ctx_t *ctx, uint8_t cvm_code) {
    if (cvm_code != CVM_PLAIN_OFFLINE && cvm_code != CVM_ENCIPHERED_OFFLINE) {
        return false;
    }
    if (ctx->channel == CC_CONTACTLESS) {
        return false;
    }
    if (cvm_code == CVM_ENCIPHERED_OFFLINE && !tlvdb_get(ctx->card, 0x9f2d, NULL)) {
        return false;
    }
    return true;
}

static bool card_aip_supports_cvm(const emv_term_ctx_t *ctx) {
    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (!aip || aip->len < 1) {
        return true;
    }
    return (aip->value[0] & 0x10) != 0;
}

static size_t pin_digits_len(const char *pin) {
    if (!pin) {
        return 0;
    }
    size_t n = 0;
    while (pin[n] && n < 12) {
        if (!isdigit((unsigned char)pin[n])) {
            return 0;
        }
        n++;
    }
    if (n < 4 || n > 12) {
        return 0;
    }
    return n;
}

static void build_plain_pin_block(uint8_t block[8], const char *pin, size_t pin_len) {
    memset(block, 0xFF, 8);
    block[0] = 0x20 | (pin_len & 0x0F);
    for (size_t i = 0; i < pin_len; i++) {
        uint8_t digit = (uint8_t)(pin[i] - '0');
        if (i % 2 == 0) {
            block[1 + i / 2] = (digit << 4) | 0x0F;
        } else {
            block[1 + i / 2] = (block[1 + i / 2] & 0xF0) | digit;
        }
    }
}

static void build_enciphered_pin_block(uint8_t *block, size_t block_len, const char *pin, size_t pin_len) {
    memset(block, 0xFF, block_len);
    block[0] = 0x7F;
    block[1] = (uint8_t)pin_len;
    for (size_t i = 0; i < pin_len; i++) {
        uint8_t digit = (uint8_t)(pin[i] - '0');
        if (i % 2 == 0) {
            block[2 + i / 2] = (digit << 4) | 0x0F;
        } else {
            block[2 + i / 2] = (block[2 + i / 2] & 0xF0) | digit;
        }
    }
    for (size_t i = 2 + (pin_len + 1) / 2; i < block_len; i++) {
        block[i] = (uint8_t)(rand() & 0xFF);
    }
}

static void set_cvm_results(emv_term_ctx_t *ctx, uint8_t cvm_code, uint8_t condition, uint8_t result) {
    ctx->cvm_results[0] = cvm_code;
    ctx->cvm_results[1] = condition;
    ctx->cvm_results[2] = result;
    tlvdb_change_or_add_node(ctx->card, 0x9f34, 3, ctx->cvm_results);
}

static void update_tvr_bit(emv_term_ctx_t *ctx, size_t byte_idx, uint8_t bit_mask, bool set) {
    uint8_t tvr[5] = {0};
    const struct tlv *tvr_tlv = tlvdb_get(ctx->card, 0x95, NULL);
    if (tvr_tlv && tvr_tlv->len >= 5) {
        memcpy(tvr, tvr_tlv->value, 5);
    }
    if (set) {
        tvr[byte_idx] |= bit_mask;
    } else {
        tvr[byte_idx] &= (uint8_t)~bit_mask;
    }
    tlvdb_change_or_add_node(ctx->card, 0x95, 5, tvr);
}

static const char *cvm_code_name(uint8_t cvm_code) {
    switch (cvm_code) {
        case CVM_PLAIN_OFFLINE:       return "plain offline PIN";
        case CVM_ENCIPHERED_ONLINE:   return "enciphered online PIN";
        case CVM_ENCIPHERED_OFFLINE:  return "enciphered offline PIN";
        case CVM_SIGNATURE:           return "signature";
        case CVM_NO_CVM:              return "no CVM";
        case CVM_FAIL:                return "fail CVM";
        case CVM_NOT_ALLOWED:         return "not allowed";
        default:                      return "other/RFU";
    }
}

static const char *cvm_condition_name(uint8_t condition) {
    switch (condition) {
        case CVM_COND_ALWAYS:         return "always";
        case CVM_COND_TERM_SUPPORTS:  return "if terminal supports CVM";
        case CVM_COND_AMT_LE_X:       return "if amount <= X";
        case CVM_COND_AMT_GT_X:       return "if amount > X";
        case CVM_COND_AMT_LE_Y:       return "if amount <= Y";
        case CVM_COND_AMT_GT_Y:       return "if amount > Y";
        default:                      return "other";
    }
}

void emv_term_cvm_dump_list(const emv_term_ctx_t *ctx) {
    const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
    if (!cvm_list || cvm_list->len < 10) {
        PrintAndLogEx(INFO, "CVM List (8E): not present or too short");
        return;
    }

    uint32_t amount_x = cvm_get_amount(cvm_list->value);
    uint32_t amount_y = cvm_get_amount(cvm_list->value + 4);
    PrintAndLogEx(INFO, "CVM List (8E) [%zu]: X=%08x Y=%08x", cvm_list->len, amount_x, amount_y);

    for (size_t i = 8; i + 1 < cvm_list->len; i += 2) {
        uint8_t cvm_byte = cvm_list->value[i];
        uint8_t cvm_code = cvm_byte & 0x3F;
        uint8_t condition = cvm_list->value[i + 1];
        const char *apply_next = (cvm_byte & 0x40) ? "apply succeeding rule if this fails" : "stop if this fails";
        PrintAndLogEx(INFO, "  rule %zu: %02x/%02x - %s, %s (%s)",
                      (i - 8) / 2 + 1, cvm_code, condition,
                      cvm_code_name(cvm_code), cvm_condition_name(condition), apply_next);
    }
}

void emv_term_cvm_print_diagnostics(const emv_term_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    PrintAndLogEx(INFO, "--- CVM diagnostics ---");
    PrintAndLogEx(INFO, "Channel: %s", ctx->channel == CC_CONTACT ? "contact" : "contactless");
    if (ctx->scheme_name[0]) {
        PrintAndLogEx(INFO, "Scheme profile: %s", ctx->scheme_name);
    }
    if (ctx->flash_skip_offline_pin) {
        PrintAndLogEx(INFO, "Scheme flag: flash_skip_offline_pin (Interac contactless)");
    }

    const struct tlv *caps = emv_term_tlv_lookup(ctx, 0x9f33);
    if (caps && caps->len >= 3) {
        PrintAndLogEx(INFO, "Terminal Capabilities (9F33): %s", sprint_hex(caps->value, caps->len));
        PrintAndLogEx(INFO, "  plain offline PIN: %s", (caps->value[1] & 0x40) ? "yes" : "no");
        PrintAndLogEx(INFO, "  enciphered offline PIN: %s", (caps->value[1] & 0x40) ? "yes" : "no");
        PrintAndLogEx(INFO, "  enciphered online PIN: %s", (caps->value[0] & 0x80) ? "yes" : "no");
    } else {
        PrintAndLogEx(WARNING, "Terminal Capabilities (9F33) missing - use -j or emv terminal run -j");
    }

    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (aip && aip->len >= 1) {
        PrintAndLogEx(INFO, "AIP (82): cardholder verification %s",
                      (aip->value[0] & 0x10) ? "supported" : "not supported");
    }

    emv_term_cvm_dump_list(ctx);

    if (ctx->channel == CC_CONTACTLESS) {
        const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
        bool has_offline = false;
        if (cvm_list && cvm_list->len >= 10) {
            for (size_t i = 8; i + 1 < cvm_list->len; i += 2) {
                uint8_t code = cvm_list->value[i] & 0x3F;
                if (code == CVM_PLAIN_OFFLINE || code == CVM_ENCIPHERED_OFFLINE) {
                    has_offline = true;
                    break;
                }
            }
        }
        if (has_offline) {
            PrintAndLogEx(WARNING, "Contactless + offline PIN in CVM list: most cards reject VERIFY (00 20) over NFC");
            PrintAndLogEx(INFO, "Try: emv terminal run -w -j --pin <pin>  OR  emv terminal pin --offline <pin> -w");
        }
    }
}

static bool terminal_supports_cvm(const emv_term_ctx_t *ctx, uint8_t cvm_code) {
    const struct tlv *caps = emv_term_tlv_lookup(ctx, 0x9f33);
    if (!caps || caps->len < 3) {
        return true;
    }
    switch (cvm_code) {
        case CVM_PLAIN_OFFLINE:
        case CVM_ENCIPHERED_OFFLINE:
            return (caps->value[1] & 0x40) != 0;
        case CVM_ENCIPHERED_ONLINE:
            return (caps->value[0] & 0x80) != 0;
        default:
            return true;
    }
}

static bool cvm_condition_ok(const emv_term_ctx_t *ctx, uint8_t condition, uint32_t amount_x, uint32_t amount_y) {
    uint64_t txn_amt = 0;
    const struct tlv *amount = emv_term_tlv_lookup(ctx, 0x9f02);
    if (amount && amount->len) {
        txn_amt = emv_term_bcd_to_uint(amount->value, amount->len);
    }

    switch (condition) {
        case CVM_COND_ALWAYS:
        case CVM_COND_TERM_SUPPORTS:
            return true;
        case CVM_COND_AMT_LE_X:
            return txn_amt <= amount_x;
        case CVM_COND_AMT_GT_X:
            return txn_amt > amount_x;
        case CVM_COND_AMT_LE_Y:
            return txn_amt <= amount_y;
        case CVM_COND_AMT_GT_Y:
            return txn_amt > amount_y;
        default:
            return true;
    }
}

static bool interac_contactless_skip_cvm(const emv_term_ctx_t *ctx) {
    if (ctx->channel != CC_CONTACTLESS) {
        return false;
    }
    if (ctx->flash_skip_offline_pin) {
        PrintAndLogEx(INFO, "Scheme profile: skip offline PIN on contactless");
        return true;
    }
    if (GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) != CV_INTERAC) {
        return false;
    }
    const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
    if (!cvm_list || cvm_list->len <= 8) {
        PrintAndLogEx(INFO, "Interac contactless Flash: no CVM rules - skipping CVM");
        return true;
    }
    return false;
}

static struct emv_pk *recover_icc_pe_key(emv_term_ctx_t *ctx) {
    struct emv_pk *ca_pk = get_ca_pk(ctx->card);
    if (!ca_pk) {
        return NULL;
    }
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(ca_pk, ctx->card);
    emv_pk_free(ca_pk);
    if (!issuer_pk) {
        return NULL;
    }
    struct emv_pk *icc_pe_pk = emv_pki_recover_icc_pe_cert(issuer_pk, ctx->card);
    emv_pk_free(issuer_pk);
    return icc_pe_pk;
}

static int send_verify_apdu(emv_term_ctx_t *ctx, uint8_t p2, const uint8_t *data, size_t data_len, uint16_t *sw_out) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    sAPDU_t apdu = {
        .CLA = 0x00,
        .INS = 0x20,
        .P1 = 0x00,
        .P2 = p2,
        .Lc = (uint8_t)data_len,
        .data = (uint8_t *)data,
    };

    int res = EMVExchange(ctx->channel, true, apdu, buf, sizeof(buf), &len, &sw, ctx->card);
    if (sw_out) {
        *sw_out = sw;
    }
    return res;
}

int phase_cvm_verify_pin(emv_term_ctx_t *ctx, const char *pin, bool enciphered) {
    if (!ctx || !pin) {
        return PM3_EINVARG;
    }

    size_t pin_len = pin_digits_len(pin);
    if (!pin_len) {
        PrintAndLogEx(ERR, "PIN must be 4-12 decimal digits");
        return PM3_EINVARG;
    }

    uint8_t plain_block[8] = {0};
    build_plain_pin_block(plain_block, pin, pin_len);

    uint8_t verify_data[256] = {0};
    size_t verify_len = 0;
    uint8_t p2 = 0x80;

    if (enciphered) {
        struct emv_pk *icc_pe_pk = recover_icc_pe_key(ctx);
        if (!icc_pe_pk) {
            PrintAndLogEx(ERR, "Cannot recover ICC PIN encipherment public key (9F2D)");
            emv_term_pin_zeroize(plain_block, sizeof(plain_block));
            update_tvr_bit(ctx, 2, TVR_OFFLINE_PIN_NOT_PERFORMED, true);
            return PM3_ESOFT;
        }

        size_t modlen = icc_pe_pk->mlen;
        build_enciphered_pin_block(verify_data, modlen, pin, pin_len);

        struct crypto_pk *cp = crypto_pk_open(icc_pe_pk->pk_algo,
                                              icc_pe_pk->modulus, icc_pe_pk->mlen,
                                              icc_pe_pk->exp, icc_pe_pk->elen);
        if (!cp) {
            emv_pk_free(icc_pe_pk);
            emv_term_pin_zeroize(plain_block, sizeof(plain_block));
            emv_term_pin_zeroize(verify_data, sizeof(verify_data));
            return PM3_ESOFT;
        }

        size_t enc_len = 0;
        unsigned char *enc = crypto_pk_encrypt(cp, verify_data, modlen, &enc_len);
        crypto_pk_close(cp);
        emv_pk_free(icc_pe_pk);
        emv_term_pin_zeroize(verify_data, sizeof(verify_data));

        if (!enc || enc_len == 0) {
            free(enc);
            emv_term_pin_zeroize(plain_block, sizeof(plain_block));
            return PM3_ESOFT;
        }

        memcpy(verify_data, enc, enc_len);
        verify_len = enc_len;
        free(enc);
        p2 = 0x88;
    } else {
        memcpy(verify_data, plain_block, sizeof(plain_block));
        verify_len = sizeof(plain_block);
    }

    emv_term_pin_zeroize(plain_block, sizeof(plain_block));

    uint16_t sw = 0;
    int res = send_verify_apdu(ctx, p2, verify_data, verify_len, &sw);
    emv_term_pin_zeroize(verify_data, sizeof(verify_data));

    if (res) {
        PrintAndLogEx(ERR, "VERIFY APDU transport error (%d)", res);
        return res;
    }

    PrintAndLogEx(INFO, "VERIFY response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (sw == 0x9000) {
        PrintAndLogEx(SUCCESS, "PIN verified OK");
        ctx->cvm_success = true;
        return PM3_SUCCESS;
    }

    ctx->cvm_success = false;
    if ((sw & 0xFF00) == 0x6300) {
        PrintAndLogEx(WARNING, "Wrong PIN, retries remaining: %d", sw & 0x0F);
        update_tvr_bit(ctx, 2, TVR_PIN_TRY_LIMIT_EXCEEDED, (sw & 0x0F) == 0);
    } else {
        update_tvr_bit(ctx, 2, TVR_OFFLINE_PIN_NOT_PERFORMED, true);
    }
    return PM3_ESOFT;
}

int phase_cvm_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (interac_contactless_skip_cvm(ctx)) {
        set_cvm_results(ctx, CVM_NO_CVM, CVM_COND_ALWAYS, CVM_RESULT_UNKNOWN);
        ctx->cvm_performed = false;
        ctx->cvm_success = true;
        return PM3_SUCCESS;
    }

    if (!card_aip_supports_cvm(ctx)) {
        PrintAndLogEx(INFO, "AIP: cardholder verification not supported - skipping CVM");
        set_cvm_results(ctx, CVM_NO_CVM, CVM_COND_ALWAYS, CVM_RESULT_UNKNOWN);
        ctx->cvm_performed = false;
        ctx->cvm_success = true;
        return PM3_SUCCESS;
    }

    const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
    if (!cvm_list || cvm_list->len < 10) {
        PrintAndLogEx(INFO, "No CVM List (8E) - skipping CVM phase");
        if (ctx->channel == CC_CONTACTLESS) {
            PrintAndLogEx(INFO, "Contactless cards often use no-CVM or online PIN only (no 8E in records)");
        }
        set_cvm_results(ctx, CVM_NO_CVM, CVM_COND_ALWAYS, CVM_RESULT_UNKNOWN);
        return PM3_SUCCESS;
    }

    emv_term_cvm_dump_list(ctx);

    uint32_t amount_x = cvm_get_amount(cvm_list->value);
    uint32_t amount_y = cvm_get_amount(cvm_list->value + 4);

    char prompt_pin[16] = {0};
    const char *pin = pin_from_opts_or_env(ctx);

    for (size_t i = 8; i + 1 < cvm_list->len; i += 2) {
        uint8_t cvm_code = cvm_list->value[i] & 0x3F;
        uint8_t condition = cvm_list->value[i + 1];
        uint8_t cvm_flags = cvm_list->value[i] & 0xC0;

        (void)cvm_flags;

        if (!cvm_condition_ok(ctx, condition, amount_x, amount_y)) {
            continue;
        }

        if (!terminal_supports_cvm(ctx, cvm_code)) {
            PrintAndLogEx(INFO, "CVM rule skipped (terminal 9F33): %s", cvm_code_name(cvm_code));
            continue;
        }

        PrintAndLogEx(INFO, "CVM rule: %s, %s", cvm_code_name(cvm_code), cvm_condition_name(condition));

        switch (cvm_code) {
            case CVM_NO_CVM:
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_UNKNOWN);
                ctx->cvm_performed = true;
                ctx->cvm_success = true;
                return PM3_SUCCESS;

            case CVM_FAIL:
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_FAILED);
                update_tvr_bit(ctx, 2, 0x80, true);
                emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
                return PM3_ESOFT;

            case CVM_NOT_ALLOWED:
                continue;

            case CVM_SIGNATURE:
                PrintAndLogEx(INFO, "CVM: signature (paper)");
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_UNKNOWN);
                ctx->cvm_performed = true;
                ctx->cvm_success = true;
                emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
                return PM3_SUCCESS;

            case CVM_PLAIN_OFFLINE:
                if (!cvm_will_verify_offline_pin(ctx, cvm_code)) {
                    PrintAndLogEx(INFO, "CVM: %s not verifiable on this channel - trying next rule",
                                  cvm_code_name(cvm_code));
                    continue;
                }
                if (!pin) {
                    pin = pin_prompt_interactive(ctx, prompt_pin, sizeof(prompt_pin));
                }
                if (!pin || !pin[0]) {
                    PrintAndLogEx(WARNING, "Plaintext offline PIN required but no PIN provided (--pin or EMV_TEST_PIN)");
                    update_tvr_bit(ctx, 2, 1 << 4, true); // PIN not entered
                    continue;
                }
                ctx->cvm_performed = true;
                if (phase_cvm_verify_pin(ctx, pin, false) == PM3_SUCCESS) {
                    set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_SUCCESS);
                    return PM3_SUCCESS;
                }
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_FAILED);
                if ((cvm_list->value[i] & 0x30) == 0x00) {
                    return PM3_ESOFT;
                }
                break;

            case CVM_ENCIPHERED_OFFLINE:
                if (!cvm_will_verify_offline_pin(ctx, cvm_code)) {
                    PrintAndLogEx(INFO, "CVM: %s not verifiable on this channel - trying next rule",
                                  cvm_code_name(cvm_code));
                    continue;
                }
                if (!pin) {
                    pin = pin_prompt_interactive(ctx, prompt_pin, sizeof(prompt_pin));
                }
                if (!pin || !pin[0]) {
                    PrintAndLogEx(WARNING, "Enciphered offline PIN required but no PIN provided");
                    continue;
                }
                ctx->cvm_performed = true;
                if (phase_cvm_verify_pin(ctx, pin, true) == PM3_SUCCESS) {
                    set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_SUCCESS);
                    return PM3_SUCCESS;
                }
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_FAILED);
                if ((cvm_list->value[i] & 0x30) == 0x00) {
                    return PM3_ESOFT;
                }
                break;

            case CVM_ENCIPHERED_ONLINE:
                if (ctx->opts.cvm_skip_online) {
                    PrintAndLogEx(INFO, "Online PIN CVM skipped (--cvm-skip-online)");
                    update_tvr_bit(ctx, 2, TVR_ONLINE_PIN_ENTERED, true);
                    set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_UNKNOWN);
                    emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
                    return PM3_SUCCESS;
                }
                if (pin && pin[0]) {
                    build_plain_pin_block(ctx->online_pin_block, pin, pin_digits_len(pin));
                    ctx->online_pin_block_len = 8;
                    PrintAndLogEx(INFO, "Online PIN captured for host/CDOL (block stashed)");
                }
                update_tvr_bit(ctx, 2, TVR_ONLINE_PIN_ENTERED, true);
                set_cvm_results(ctx, cvm_code, condition, CVM_RESULT_UNKNOWN);
                emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
                return PM3_SUCCESS;

            default:
                PrintAndLogEx(INFO, "Unsupported CVM code %02x - trying next rule", cvm_code);
                break;
        }
    }

    emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
    PrintAndLogEx(WARNING, "CVM processing exhausted without success");
    update_tvr_bit(ctx, 2, TVR_OFFLINE_PIN_NOT_PERFORMED, true);
    return PM3_ESOFT;
}
