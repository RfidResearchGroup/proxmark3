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
// Pack a DESFire card image for emulator memory, and read one back.
// Layout and rationale live in include/desfire_em.h.
//-----------------------------------------------------------------------------

#ifndef __DESFIREEM_H
#define __DESFIREEM_H

#include "common.h"
#include "desfire_em.h"
#include "fileutils.h"      // desfire_dump_t

// Which generation a GetVersion hardware frame describes. Needs at least 5
// bytes; returns DESFIRE_EM_GEN_UNKNOWN for anything it does not recognise.
uint8_t desfire_em_gen_from_version(const uint8_t *versionhw, uint8_t len);

// NV the GetVersion storage size byte codes. A floor on the real capacity, not
// the capacity: a 2K part codes 2048 and hands out 2560. 0 if undecodable.
uint32_t desfire_em_nominal_cardsize(const uint8_t *versionhw, uint8_t len);
const char *desfire_em_gen_str(uint8_t gen);

// Emulator memory a file reserves, committed region and shadow together.
// Rounded to DESFIRE_EM_GRANULE. Backup, value and record files carry a shadow
// because CommitTransaction covers them; standard data files do not.
uint32_t desfire_em_file_reserve(const desfire_dump_file_t *f);

// Pack `dump` into `out`, which may use at most `outlen` bytes. On success
// *used is the number of bytes the image occupies, which is outlen unless the
// caller wants to trim -- the data pool grows down from the end, so the image
// is not contiguous and cannot be shortened.
//
// Fails with PM3_EOUTOFBOUND, naming the shortfall, rather than truncating.
int desfire_em_pack(const desfire_dump_t *dump, uint8_t *out, size_t outlen, size_t *used);

// Walk an image back into a desfire_dump_t. The caller owns the per-file heap
// buffers afterwards and must release them with desfire_dump_free().
// Unpack a card image into a dump.  A deleted application or file is a tombstone
// in the image: the memory it held stays spent, but it is gone as far as a
// reader is concerned.  `keep_deleted` decides which of those two views you get
// -- false for the card as a reader sees it, true to keep what was there.
int desfire_em_unpack_ex(const uint8_t *img, size_t imglen, desfire_dump_t *dump, bool keep_deleted);
int desfire_em_unpack(const uint8_t *img, size_t imglen, desfire_dump_t *dump);

// Print an image's structure. Does not need a device.
void desfire_em_print(const uint8_t *img, size_t imglen);

// Move an image to and from emulator memory. imglen must be a multiple of 16
// for the upload, which is what the generic emulator setter addresses in.
int desfire_em_upload(const uint8_t *img, size_t imglen);
int desfire_em_download(uint8_t *img, size_t imglen);

#endif // __DESFIREEM_H
