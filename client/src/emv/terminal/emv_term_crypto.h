//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — crypto playground
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_CRYPTO_H__
#define EMV_TERM_CRYPTO_H__

#include "emv_term_ctx.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    EMV_CRYPTO_AC_AAC  = 0x00,
    EMV_CRYPTO_AC_TC   = 0x40,
    EMV_CRYPTO_AC_ARQC = 0x80,
} emv_term_crypto_ac_t;

typedef struct {
    bool amount_set;
    uint8_t amount[6];
    bool un_set;
    uint8_t un[4];
    bool date_set;
    uint8_t date[3];
    bool country_set;
    uint8_t country[2];
    bool currency_set;
    uint8_t currency[2];
    emv_term_crypto_ac_t ac_type;
    bool cda;
    bool mc_challenge;
} emv_term_crypto_genac_opts_t;

typedef struct {
    uint8_t un[4];
    uint8_t ac[8];
    size_t ac_len;
    uint8_t atc[2];
    size_t atc_len;
    uint16_t sw;
} emv_term_crypto_run_entry_t;

typedef struct {
    bool do_challenge;
    bool do_genac;
    bool do_intauth;
    bool do_checksum;
    bool do_vary;
    int vary_count;
    emv_term_crypto_genac_opts_t genac;
} emv_term_crypto_bench_opts_t;

void emv_term_crypto_genac_opts_defaults(emv_term_crypto_genac_opts_t *opts);
void emv_term_crypto_set_amount_cents(emv_term_ctx_t *ctx, uint64_t cents);
void emv_term_crypto_set_un_bytes(emv_term_ctx_t *ctx, const uint8_t un[4]);
void emv_term_crypto_randomize_un(emv_term_ctx_t *ctx);
void emv_term_crypto_apply_field_overrides(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts);

int emv_term_crypto_print_summary(const emv_term_ctx_t *ctx);
int emv_term_crypto_challenge(emv_term_ctx_t *ctx, bool decode_tlv, bool store_9f4c);
int emv_term_crypto_genac(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts, bool ac2);
int emv_term_crypto_vary_un(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts,
                            int count, emv_term_crypto_run_entry_t *entries, size_t *entry_count);
int emv_term_crypto_intauth(emv_term_ctx_t *ctx, bool decode_tlv);
int emv_term_crypto_msc_checksum(emv_term_ctx_t *ctx, bool decode_tlv);
int emv_term_crypto_export_json(const emv_term_ctx_t *ctx, const char *path,
                                const emv_term_crypto_run_entry_t *entries, size_t entry_count);
int emv_term_crypto_bench(emv_term_ctx_t *ctx, const emv_term_crypto_bench_opts_t *opts,
                          const char *export_path);

void emv_term_uint_to_bcd(uint64_t val, uint8_t *out, size_t len);

#endif
