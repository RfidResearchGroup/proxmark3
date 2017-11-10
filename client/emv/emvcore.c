//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV core functions
//-----------------------------------------------------------------------------

#include "emvcore.h"

static bool print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
	emv_tag_dump(tlv, stdout, level);
	if (is_leaf) {
		dump_buffer(tlv->value, tlv->len, stdout, level);
	}

	return true;
}

void TLVPrintFromBuffer(uint8_t *data, int datalen) {
	struct tlvdb *t = NULL;
	t = tlvdb_parse_multi(data, datalen);
	if (t) {
		PrintAndLog("TLV decoded:");
		
		tlvdb_visit(t, print_cb, NULL, 0);
		tlvdb_free(t);
	} else {
		PrintAndLog("TLV ERROR: Can't parse response as TLV tree.");
	}
}
