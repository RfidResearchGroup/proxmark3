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
// originality checks with known pk
//-----------------------------------------------------------------------------

#include "originality.h"
#include <string.h>       // memcpy
#include "ui.h"

// See tools/recover_pk.py to recover Pk from UIDs and signatures
const ecdsa_publickey_ng_t manufacturer_public_keys[] = {
    {PK_MFC,     MBEDTLS_ECP_DP_SECP128R1, 33, "NXP MIFARE Classic MFC1C14_x",
    "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF"},
    {PK_MFC,     MBEDTLS_ECP_DP_SECP128R1, 33, "MIFARE Classic / QL88",
    "046F70AC557F5461CE5052C8E4A7838C11C7A236797E8A0730A101837C004039C2"},

    // ref: TagInfo
    // NTAG 210/212 ? not present in recover_pk
    {PK_MFUL,    MBEDTLS_ECP_DP_SECP128R1, 33, "NXP Public key",
    "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC"},
    // ref: AN11341 MIFARE Ultralight EV1 Originality Signature Validation
    {PK_MFUL,    MBEDTLS_ECP_DP_SECP128R1, 33, "NXP Ultralight EV1",
    "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8"},
    // ref: AN11350 NTAG 21x Originality Signature Validation
    {PK_MFUL,    MBEDTLS_ECP_DP_SECP128R1, 33, "NXP NTAG21x (2013)",
    "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"},

    // ref: AN13452 MIFARE Ultralight AES features and hints
    {PK_MFULAES, MBEDTLS_ECP_DP_SECP192R1, 49, "NXP Ultralight AES",
    "0453BF8C49B7BD9FE3207A91513B9C1D238ECAB07186B772104AB535F7D3AE63CF7C7F3DD0D169DA3E99E43C6399621A86"},
    // ref: TagInfo
    {PK_MFULAES, MBEDTLS_ECP_DP_SECP192R1, 49, "NXP Ultralight AES (alt key)",
    "04DC34DAA903F2726A6225B11C692AF6AB4396575CA12810CBBCE3F781A097B3833B50AB364A70D9C2B641A728A599AE74"},

    {PK_MFP,     MBEDTLS_ECP_DP_SECP224R1, 57, "MIFARE Plus EV1",
    "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"},
     // not present in recover_pk
    {PK_MFP,     MBEDTLS_ECP_DP_SECP224R1, 57, "MIFARE Plus EV2",
    "04BB49AE4447E6B1B6D21C098C1538B594A11A4A1DBF3D5E673DEACDEB3CC512D1C08AFA1A2768CE20A200BACD2DC7804CD7523A0131ABF607"},
    {PK_MFP,     MBEDTLS_ECP_DP_SECP224R1, 57, "MIFARE Plus Troika",
    "040F732E0EA7DF2B38F791BF89425BF7DCDF3EE4D976669E3831F324FF15751BD52AFF1782F72FF2731EEAD5F63ABE7D126E03C856FFB942AF"},

    // ref: AN12343 MIFARE DESFire Light Features and Hints
    // not present in recover_pk
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "DESFire Light",
    "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "NTAG413DNA, DESFire EV1",
    "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "NTAG424DNA, NTAG424DNATT, DESFire EV2, DESFire Light EV2",
    "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
    // ref: AN12196 NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "NTAG424DNA, DESFire EV2, DESFire Light",
    "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "DESFire EV2 XL",
    "04CD5D45E50B1502F0BA4656FF37669597E7E183251150F9574CC8DA56BF01C7ABE019E29FEA48F9CE22C3EA4029A765E1BC95A89543BAD1BC"},
    {PK_MFDES,   MBEDTLS_ECP_DP_SECP224R1, 57, "DESFire EV3",
    "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743"},

    // ref: AN5101 TruST25 digital signature for ST25TA512B, ST25TA02KB, ST25TA02KB-D and ST25TA02KB-P devices
    {PK_ST25TA,  MBEDTLS_ECP_DP_SECP128R1, 33, "ST25TA TruST25 (ST) key 01?",
    "041D92163650161A2548D33881C235D0FB2315C2C31A442F23C87ACF14497C0CBA"},
    // ref: AN5660 TruST25 digital signature for ST25TN512 and ST25TN01K devices
    {PK_ST25TN,  MBEDTLS_ECP_DP_SECP128R1, 33, "ST25TN TruST25 (ST) KeyID 05",
    "0440004F974F7C76BC8718E523D85FA7B354A9A992BFA966CB8219242F9D274FD6"},
    // ref: AN5104 TruST25 digital signature for ST25TV512 and ST25TV02K devices ?
    // ref: AN5149 TruST25 digital signature for ST25DV02K-W1, ST25DV02K-W2 devices ?
    // ref: AN5580 TruST25 digital signature for ST25TV512C and ST25TV02KC devices
    {PK_ST25TV,  MBEDTLS_ECP_DP_SECP128R1, 33, "ST25TV TruST25 (ST) KeyID 04",
    "04101E188A8B4CDDBC62D5BC3E0E6850F0C2730E744B79765A0E079907FBDB01BC"},

    {PK_15,      MBEDTLS_ECP_DP_SECP128R1, 33, "NXP ICODE DNA, ICODE SLIX2",
    "048878A2A2D3EEC336B4F261A082BD71F9BE11C4E2E896648B32EFA59CEA6E59F0"},
    {PK_15,      MBEDTLS_ECP_DP_SECP128R1, 33, "VivoKey Spark1 Public key",
    "04D64BB732C0D214E7EC580736ACF847284B502C25C0F7F2FA86AACE1DADA4387A"},

// FIXME: what type(s) of card exactly? MFC? MFUL? not present in recover_pk
    {PK_MIK,     MBEDTLS_ECP_DP_SECP128R1, 33, "MIKRON Public key",
    "04F971EDA742A4A80D32DCF6A814A707CC3DC396D35902F72929FDCD698B3468F2"},
};


// return pk if match index else -1
int originality_check_verify(uint8_t *data, uint8_t data_len, uint8_t *signature, uint8_t signature_len, pk_type_t type) {
    return originality_check_verify_ex(data, data_len, signature, signature_len, type, false, false);
}

int originality_check_verify_ex(uint8_t *data, uint8_t data_len, uint8_t *signature, uint8_t signature_len, pk_type_t type, bool reverse, bool hash) {
    // test if signature is null
    bool is_zero = true;
    for (uint8_t i = 0; i < signature_len; i++) {
        if (signature[i] != 0) {
            is_zero = false;
        }
    }
    if (is_zero) {
        return -1;
    }

    uint8_t tmp_data[data_len];
    uint8_t tmp_signature[signature_len];
    if (reverse) {
        reverse_array_copy(data, data_len, tmp_data);
        reverse_array_copy(signature, signature_len, tmp_signature);
    } else {
        memcpy(tmp_data, data, data_len);
        memcpy(tmp_signature, signature, signature_len);
    }

    for (uint8_t i = 0; i < ARRAYLEN(manufacturer_public_keys); i++) {
        if ((type != PK_ALL) && (type != manufacturer_public_keys[i].type))
            continue;
        int dl = 0;
        uint8_t key[manufacturer_public_keys[i].keylen];
        param_gethex_to_eol(manufacturer_public_keys[i].value, 0, key, manufacturer_public_keys[i].keylen, &dl);
        if (ecdsa_signature_r_s_verify(manufacturer_public_keys[i].grp_id, key, tmp_data, data_len, tmp_signature, signature_len, hash) == 0)
            return i;
    }
    return -1;
}

int originality_check_print(uint8_t *signature, int signature_len, int index) {
    if ((index < 0) || (index >= ARRAYLEN(manufacturer_public_keys))) {
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
        if (signature_len > 16) {
            PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
        }
        if (signature_len > 32) {
            PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
        }
        if (signature_len > 48) {
            PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
        }
        PrintAndLogEx(SUCCESS, "       Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), manufacturer_public_keys[index].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %.32s", manufacturer_public_keys[index].value);
    if (manufacturer_public_keys[index].keylen > 16) {
        PrintAndLogEx(INFO, "                             : %.32s", manufacturer_public_keys[index].value + 32);
    }
    if (manufacturer_public_keys[index].keylen > 32) {
        PrintAndLogEx(INFO, "                             : %.32s", manufacturer_public_keys[index].value + 64);
    }
    if (manufacturer_public_keys[index].keylen > 48) {
        PrintAndLogEx(INFO, "                             : %.32s", manufacturer_public_keys[index].value + 96);
    }
    PrintAndLogEx(INFO, "    Elliptic curve parameters: %s", mbedtls_ecp_curve_info_from_grp_id(manufacturer_public_keys[index].grp_id)->name);
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
    if (signature_len > 16) {
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
    }
    if (signature_len > 32) {
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
    }
    if (signature_len > 48) {
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
    }
    PrintAndLogEx(SUCCESS, "       Signature verification: " _GREEN_("successful"));
    return PM3_SUCCESS;
}
