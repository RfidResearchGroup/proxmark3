//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO7816 core functionality
//-----------------------------------------------------------------------------

#ifndef ISO7816CORE_H__
#define ISO7816CORE_H__

#include "common.h"
#include <inttypes.h>
#include "apduinfo.h"

#define APDU_RES_LEN 260
#define APDU_AID_LEN 50

typedef enum {
    ISODEP_INACTIVE = 0,
    ISODEP_NFCA,
    ISODEP_NFCB,
} isodep_state_t;

typedef enum {
    CC_CONTACTLESS,
    CC_CONTACT
} Iso7816CommandChannel;

void SetAPDULogging(bool logging);
bool GetAPDULogging(void);

void SetISODEPState(isodep_state_t state);
isodep_state_t GetISODEPState(void);

// connect
int Iso7816Connect(Iso7816CommandChannel channel);

// exchange
int Iso7816Exchange(Iso7816CommandChannel channel, bool leave_field_on, sAPDU apdu, uint8_t *result, size_t max_result_len,
                    size_t *result_len, uint16_t *sw);

int Iso7816ExchangeEx(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on, sAPDU apdu, bool include_le,
                      uint16_t le, uint8_t *result,  size_t max_result_len, size_t *result_len, uint16_t *sw);

// search application
int Iso7816Select(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on, uint8_t *aid, size_t aid_len,
                  uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

#endif
