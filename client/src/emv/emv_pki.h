//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/lumag/emv-tools/
// Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
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
// libopenemv - a library to work with EMV family of smart cards
//-----------------------------------------------------------------------------

#ifndef EMV_PKI_H
#define EMV_PKI_H

#include "emv_pk.h"
#include "tlv.h"

void PKISetStrictExecution(bool se);

unsigned char *emv_pki_sdatl_fill(const struct tlvdb *db, size_t *sdatl_len);
struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *pk, struct tlvdb *db);
struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *pk, struct tlvdb *db, const struct tlv *sda_tlv);
struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *pk, struct tlvdb *db);

struct tlvdb *emv_pki_recover_dac(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *sda_tlv);
struct tlvdb *emv_pki_recover_dac_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *sda_tlv, bool showData);
struct tlvdb *emv_pki_recover_idn(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *dyn_tlv);
struct tlvdb *emv_pki_recover_idn_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *dyn_tlv, bool showData);
struct tlvdb *emv_pki_recover_atc_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, bool showData);
struct tlvdb *emv_pki_perform_cda(const struct emv_pk *enc_pk, const struct tlvdb *db,
                                  const struct tlvdb *this_db,
                                  const struct tlv *pdol_data_tlv,
                                  const struct tlv *crm1_tlv,
                                  const struct tlv *crm2_tlv);
struct tlvdb *emv_pki_perform_cda_ex(const struct emv_pk *enc_pk, const struct tlvdb *db,
                                     const struct tlvdb *this_db,
                                     const struct tlv *pdol_data_tlv,
                                     const struct tlv *crm1_tlv,
                                     const struct tlv *crm2_tlv,
                                     bool showData);

#endif
