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
//-----------------------------------------------------------------------------

#include "imgjp2.h"

#include <stdlib.h>
#include <string.h>

#include "openjpeg.h"
#include "ui.h"

static const uint8_t jp2_signature[8] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20 };
static const uint8_t j2k_signature[4] = { 0xFF, 0x4F, 0xFF, 0x51 };

// openjpeg has no memory stream of its own,  it wants callbacks
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} jp2_membuf_t;

static OPJ_SIZE_T jp2_mem_read(void *buffer, OPJ_SIZE_T nb_bytes, void *user_data) {
    jp2_membuf_t *mb = (jp2_membuf_t *)user_data;

    if (mb->pos >= mb->len) {
        return (OPJ_SIZE_T) - 1;
    }

    size_t remaining = mb->len - mb->pos;
    if (nb_bytes > remaining) {
        nb_bytes = remaining;
    }

    memcpy(buffer, mb->data + mb->pos, nb_bytes);
    mb->pos += nb_bytes;
    return nb_bytes;
}

static OPJ_OFF_T jp2_mem_skip(OPJ_OFF_T nb_bytes, void *user_data) {
    jp2_membuf_t *mb = (jp2_membuf_t *)user_data;

    if (nb_bytes < 0) {
        // rewinding past the start is a hard error
        if ((OPJ_OFF_T)mb->pos + nb_bytes < 0) {
            return (OPJ_OFF_T) - 1;
        }
        mb->pos = (size_t)((OPJ_OFF_T)mb->pos + nb_bytes);
        return nb_bytes;
    }

    size_t remaining = mb->len - mb->pos;
    if ((OPJ_SIZE_T)nb_bytes > remaining) {
        // skipping to the end is fine,  it just means we're done
        mb->pos = mb->len;
        return (OPJ_OFF_T)remaining;
    }

    mb->pos += (size_t)nb_bytes;
    return nb_bytes;
}

static OPJ_BOOL jp2_mem_seek(OPJ_OFF_T nb_bytes, void *user_data) {
    jp2_membuf_t *mb = (jp2_membuf_t *)user_data;

    if (nb_bytes < 0 || (OPJ_SIZE_T)nb_bytes > mb->len) {
        return OPJ_FALSE;
    }

    mb->pos = (size_t)nb_bytes;
    return OPJ_TRUE;
}

static void jp2_err(const char *msg, void *client_data) {
    (void)client_data;
    PrintAndLogEx(DEBUG, "jpeg2000 error... %s", msg);
}

static void jp2_warn(const char *msg, void *client_data) {
    (void)client_data;
    PrintAndLogEx(DEBUG, "jpeg2000 warning... %s", msg);
}

static void jp2_info(const char *msg, void *client_data) {
    (void)client_data;
    (void)msg;
}

bool jp2_is_jpeg2000(const uint8_t *data, size_t datalen) {
    if (data == NULL) {
        return false;
    }

    if (datalen >= sizeof(jp2_signature) && memcmp(data, jp2_signature, sizeof(jp2_signature)) == 0) {
        return true;
    }

    if (datalen >= sizeof(j2k_signature) && memcmp(data, j2k_signature, sizeof(j2k_signature)) == 0) {
        return true;
    }

    return false;
}

// Pull one sample out of a component and normalise it to 0..255.
// Handles signed components, precisions other than 8 bit and subsampling.
static uint8_t jp2_sample(const opj_image_comp_t *c, int x, int y) {

    int sx = x / (int)c->dx;
    int sy = y / (int)c->dy;

    if (sx < 0) {
        sx = 0;
    }
    if (sy < 0) {
        sy = 0;
    }
    if (sx >= (int)c->w) {
        sx = (int)c->w - 1;
    }
    if (sy >= (int)c->h) {
        sy = (int)c->h - 1;
    }

    int v = c->data[sy * (int)c->w + sx];

    // signed components are stored centred on zero
    if (c->sgnd) {
        v += 1 << (c->prec - 1);
    }

    // scale whatever precision we got to 8 bit
    if (c->prec > 8) {
        v >>= (c->prec - 8);
    } else if (c->prec < 8) {
        v <<= (8 - c->prec);
    }

    if (v < 0) {
        v = 0;
    }
    if (v > 255) {
        v = 255;
    }

    return (uint8_t)v;
}

// ITU-R BT.601 , openjpeg leaves sYCC to the application
static void jp2_sycc_to_rgb(int y, int cb, int cr, uint8_t *rgb) {

    cb -= 128;
    cr -= 128;

    int r = y + ((91881 * cr) >> 16);
    int g = y - ((22554 * cb + 46802 * cr) >> 16);
    int b = y + ((116130 * cb) >> 16);

    rgb[0] = (r < 0) ? 0 : ((r > 255) ? 255 : (uint8_t)r);
    rgb[1] = (g < 0) ? 0 : ((g > 255) ? 255 : (uint8_t)g);
    rgb[2] = (b < 0) ? 0 : ((b > 255) ? 255 : (uint8_t)b);
}

uint8_t *jp2_decode_rgb(const uint8_t *data, size_t datalen, int *width, int *height) {

    if (data == NULL || width == NULL || height == NULL) {
        return NULL;
    }

    if (jp2_is_jpeg2000(data, datalen) == false) {
        return NULL;
    }

    OPJ_CODEC_FORMAT codec_format = OPJ_CODEC_J2K;
    if (datalen >= sizeof(jp2_signature) && memcmp(data, jp2_signature, sizeof(jp2_signature)) == 0) {
        codec_format = OPJ_CODEC_JP2;
    }

    jp2_membuf_t mb = { data, datalen, 0 };
    uint8_t *rgb = NULL;
    opj_image_t *image = NULL;
    opj_codec_t *codec = NULL;

    // OPJ_TRUE == this is an input stream
    opj_stream_t *stream = opj_stream_default_create(OPJ_TRUE);
    if (stream == NULL) {
        return NULL;
    }

    opj_stream_set_read_function(stream, jp2_mem_read);
    opj_stream_set_skip_function(stream, jp2_mem_skip);
    opj_stream_set_seek_function(stream, jp2_mem_seek);
    opj_stream_set_user_data(stream, &mb, NULL);
    opj_stream_set_user_data_length(stream, datalen);

    codec = opj_create_decompress(codec_format);
    if (codec == NULL) {
        goto out;
    }

    opj_set_error_handler(codec, jp2_err, NULL);
    opj_set_warning_handler(codec, jp2_warn, NULL);
    opj_set_info_handler(codec, jp2_info, NULL);

    opj_dparameters_t params;
    opj_set_default_decoder_parameters(&params);

    if (opj_setup_decoder(codec, &params) == OPJ_FALSE) {
        goto out;
    }

    if (opj_read_header(stream, codec, &image) == OPJ_FALSE) {
        goto out;
    }

    if (opj_decode(codec, stream, image) == OPJ_FALSE) {
        goto out;
    }

    if (opj_end_decompress(codec, stream) == OPJ_FALSE) {
        goto out;
    }

    if (image->numcomps < 1 || image->comps[0].data == NULL) {
        PrintAndLogEx(DEBUG, "jpeg2000 image has no usable components");
        goto out;
    }

    // work in the reference grid,  components may be subsampled
    int w = (int)(image->x1 - image->x0);
    int h = (int)(image->y1 - image->y0);
    if (w <= 0 || h <= 0) {
        goto out;
    }

    // sanity cap,  a passport portrait is nowhere near this
    if ((int64_t)w * (int64_t)h > (int64_t)64 * 1024 * 1024) {
        PrintAndLogEx(DEBUG, "jpeg2000 image too large... %i x %i", w, h);
        goto out;
    }

    rgb = (uint8_t *)calloc((size_t)w * (size_t)h * 3, sizeof(uint8_t));
    if (rgb == NULL) {
        goto out;
    }

    bool have_color = (image->numcomps >= 3 &&
                       image->comps[1].data != NULL &&
                       image->comps[2].data != NULL);

    bool is_sycc = (image->color_space == OPJ_CLRSPC_SYCC);

    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {

            uint8_t *out = rgb + ((size_t)y * (size_t)w + (size_t)x) * 3;

            if (have_color == false) {
                // greyscale,  replicate to all three channels
                uint8_t v = jp2_sample(&image->comps[0], x, y);
                out[0] = v;
                out[1] = v;
                out[2] = v;
                continue;
            }

            uint8_t c0 = jp2_sample(&image->comps[0], x, y);
            uint8_t c1 = jp2_sample(&image->comps[1], x, y);
            uint8_t c2 = jp2_sample(&image->comps[2], x, y);

            if (is_sycc) {
                jp2_sycc_to_rgb(c0, c1, c2, out);
            } else {
                out[0] = c0;
                out[1] = c1;
                out[2] = c2;
            }
        }
    }

    *width = w;
    *height = h;

out:
    if (image) {
        opj_image_destroy(image);
    }
    if (codec) {
        opj_destroy_codec(codec);
    }
    opj_stream_destroy(stream);

    return rgb;
}
