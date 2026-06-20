#ifndef PARSEHRT_H__
#define PARSEHRT_H__

#include "mifare/desfirecore.h"
#include <stddef.h>
#include <stdint.h>

bool is_valid_hrt_card(DesfireContext_t *dctx, const uint8_t *aidbuf, size_t aidbuflen);
bool hrt_parser_parse(DesfireContext_t *dctx);

#endif
