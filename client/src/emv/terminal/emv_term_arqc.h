//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_ARQC_H__
#define EMV_TERM_ARQC_H__

#include "common.h"

typedef enum {
    EMV_ARPC_CVN10 = 0,
    EMV_ARPC_CVN18,
    EMV_ARPC_XOR_STUB,
} emv_arpc_method_t;

void emv_term_sk_derive_ac(const uint8_t ac_mk[16], uint16_t atc, uint8_t sk[16]);

void emv_term_retail_mac_3des(const uint8_t sk[16], const uint8_t *data, size_t data_len, uint8_t mac[8]);

bool emv_term_arqc_verify(const uint8_t sk[16], const uint8_t *cdol1, size_t cdol1_len,
                          const uint8_t *arqc, size_t arqc_len);

bool emv_term_arpc_compute(emv_arpc_method_t method, const uint8_t sk[16],
                           const uint8_t *arqc, size_t arqc_len,
                           const uint8_t *arc, size_t arc_len,
                           uint8_t *arpc, size_t *arpc_len);

#endif
