//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CA PEM certificates
//-----------------------------------------------------------------------------
//

#ifndef __ADDITIONAL_CA_H__
#define __ADDITIONAL_CA_H__

#include <stddef.h>

// Concatenation of all CA certificates in PEM format if available
extern const char   additional_ca_pem[];
extern const size_t additional_ca_pem_len;

#endif /* __ADDITIONAL_CA_H__ */
