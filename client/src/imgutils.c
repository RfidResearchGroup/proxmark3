
#include <assert.h>
#include "imgutils.h"

struct ycbcr_t {
    int y;
    int cb;
    int cr;
};

static void rgb_to_ycbcr(int rgb, struct ycbcr_t *ycbcr) {
    int r = gdTrueColorGetRed(rgb);
    int g = gdTrueColorGetGreen(rgb);
    int b = gdTrueColorGetBlue(rgb);

    /*
     * Below is a fixed-point version of the following code:
     * ycbcr->y  = r *  0.29900 + g *  0.58700 + b *  0.11400;
     * ycbcr->cb = r * -0.16874 + g * -0.33126 + b *  0.50000 + 128;
     * ycbcr->cr = r *  0.50000 + g * -0.41869 + b * -0.08131 + 128;
     */

    ycbcr->y  = (r *  19595 + g *  38470 + b *  7471) / 65536;
    ycbcr->cb = (r * -11059 + g * -21709 + b * 32768) / 65536 + 128;
    ycbcr->cr = (r *  32768 + g * -27439 + b * -5329) / 65536 + 128;
}

static inline void cap_comp(int *x) {
    if (*x < 0) {
        *x = 0;
    } else if (*x > 255) {
        *x = 255;
    }
}

gdImagePtr img_palettize(gdImagePtr rgb, int *palette, int palette_size) {
    assert(rgb != NULL);
    assert(palette != NULL);
    assert(palette_size >= 2 && palette_size < 256);

    // Create paletized image
    gdImagePtr res = gdImageCreate(gdImageSX(rgb), gdImageSY(rgb));
    if (!res) {
        return NULL;
    }

    // Allocate space for palette in YCbCr
    struct ycbcr_t *pal_ycbcr = calloc(palette_size, sizeof(struct ycbcr_t));
    if (!pal_ycbcr) {
        gdImageDestroy(res);
        return NULL;
    }

    /*
     * Initialize the column's error array.
     *
     * Note that we are storing two extra values so we don't have to do boundary checking at
     * the left and right edges of the image.
     *
     * To reduce shifts and increase accuracy, each entry is stored with 16x times the error,
     * and gets divided by that amount when it is read.
     */
    struct ycbcr_t *forward = calloc(gdImageSX(rgb) + 2, sizeof(struct ycbcr_t));
    if (!forward) {
        free(pal_ycbcr);
        gdImageDestroy(res);
        return NULL;
    }

    // Convert palette to YCbCr and allocate in image
    for (int i = 0; i < palette_size; i++) {
        int c = palette[i];
        rgb_to_ycbcr(c, pal_ycbcr + i);
        gdImageColorAllocate(res, gdTrueColorGetRed(c), gdTrueColorGetGreen(c), gdTrueColorGetBlue(c));
    }

    for (int y = 0; y < gdImageSY(rgb); y++) {
        // Load current row error and reset its storage
        struct ycbcr_t row_err = forward[1];
        forward[1].y = forward[1].cb = forward[1].cr = 0;

        for (int x = 0; x < gdImageSX(rgb); x++) {
            struct ycbcr_t pix;
            rgb_to_ycbcr(gdImageGetTrueColorPixel(rgb, x, y), &pix);

            // Add error for current pixel
            pix.y  += row_err.y  / 16;
            pix.cb += row_err.cb / 16;
            pix.cr += row_err.cr / 16;

            // Cap in case it went to imaginary color territory
            cap_comp(&pix.y);
            cap_comp(&pix.cb);
            cap_comp(&pix.cr);

            /*
             * Iterate through all candidate colors and find the nearest one using the
             * squared Euclidean distance.
             */
            int best_idx = 0;
            struct ycbcr_t best_err = { 0 };
            int best_score = 0x7FFFFFFF;
            for (int can_idx = 0; can_idx < palette_size; can_idx++) {
                struct ycbcr_t can_err = {
                    .y  = pix.y  - pal_ycbcr[can_idx].y,
                    .cb = pix.cb - pal_ycbcr[can_idx].cb,
                    .cr = pix.cr - pal_ycbcr[can_idx].cr,
                };

                int can_score = (
                                    can_err.y  * can_err.y  +
                                    can_err.cb * can_err.cb +
                                    can_err.cr * can_err.cr
                                );

                if (can_score < best_score) {
                    best_idx   = can_idx;
                    best_score = can_score;
                    best_err   = can_err;
                }
            }

            // Set current pixel
            gdImageSetPixel(res, x, y, best_idx);

            // Propagate error within the current row, to the pixel to the right
            row_err.y  = best_err.y  * 7 + forward[x + 2].y;
            row_err.cb = best_err.cb * 7 + forward[x + 2].cb;
            row_err.cr = best_err.cr * 7 + forward[x + 2].cr;

            // Add error to bottom left
            forward[x + 0].y  += best_err.y  * 3;
            forward[x + 0].cb += best_err.cb * 3;
            forward[x + 0].cr += best_err.cr * 3;

            // Add error to bottom center
            forward[x + 1].y  += best_err.y  * 5;
            forward[x + 1].cb += best_err.cb * 5;
            forward[x + 1].cr += best_err.cr * 5;

            // Set error to bottom right
            forward[x + 2].y   = best_err.y  * 1;
            forward[x + 2].cb  = best_err.cb * 1;
            forward[x + 2].cr  = best_err.cr * 1;
        }
    }

    free(forward);
    free(pal_ycbcr);
    return res;
}

gdImagePtr img_crop_to_fit(gdImagePtr orig, int width, int height) {
    assert(orig != NULL);
    assert(width >= 1);
    assert(height >= 1);

    gdImagePtr res;
    if (gdImageTrueColor(orig)) {
        res = gdImageCreateTrueColor(width, height);
    } else {
        res = gdImageCreate(width, height);
    }

    if (!res) {
        return NULL;
    }

    if (gdImageSY(orig) * width <= gdImageSX(orig) * height) {
        // Image is wider than expected, so we will crop the left and right sides

        int crop_width = gdImageSY(orig) * width / height;
        int crop_sx = gdImageSX(orig) / 2 - crop_width / 2;
        gdImageCopyResampled(
            res,             // Dest img
            orig,            // Src image
            0,               // Dest X
            0,               // Dest Y
            crop_sx,         // Src X
            0,               // Src Y
            width,           // Dest width
            height,          // Dest height
            crop_width,      // Src width
            gdImageSY(orig)  // Src height
        );
    } else {
        // Image is taller than expected, so we will crop the top and bottom sides

        int crop_height = gdImageSX(orig) * height / width;
        int crop_sy = gdImageSY(orig) / 2 - crop_height / 2;
        gdImageCopyResampled(
            res,             // Dest img
            orig,            // Src image
            0,               // Dest X
            0,               // Dest Y
            0,               // Src X
            crop_sy,         // Src Y
            width,           // Dest width
            height,          // Dest height
            gdImageSX(orig), // Src width
            crop_height      // Src height
        );
    }

    return res;
}
