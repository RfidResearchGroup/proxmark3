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
// JPEG2000 decoding, so the picture viewer can show eMRTD biometrics.
//
// Qt has no JPEG2000 image handler,  the old JasPer based plugin was dropped
// from qtimageformats and distros don't ship a replacement.  Most passports
// store EF_DG2 as JPEG2000, so we decode it ourselves with the vendored
// openjpeg in client/deps/openjpeg and hand plain RGB to the viewer.
//-----------------------------------------------------------------------------

#ifndef IMGJP2_H__
#define IMGJP2_H__

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Does this buffer start with a JPEG2000 signature?
// Both the JP2 container (00 00 00 0C 6A 50 20 20) and a raw
// codestream (FF 4F FF 51) are recognized.
bool jp2_is_jpeg2000(const uint8_t *data, size_t datalen);

// Decode a JPEG2000 image into a freshly allocated, tightly packed RGB888
// buffer of w * h * 3 bytes.  Returns NULL on failure, otherwise the caller
// owns the buffer and must free() it.
uint8_t *jp2_decode_rgb(const uint8_t *data, size_t datalen, int *width, int *height);

#ifdef __cplusplus
}
#endif

#endif // IMGJP2_H__
