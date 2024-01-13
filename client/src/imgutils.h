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
// Image utilities
//-----------------------------------------------------------------------------
#ifndef IMGUTILS_H__
#define IMGUTILS_H__

#include <gd.h>

/*
 * Converts a true color image to a palette image, using Floyd-Steinberg dithering.
 *
 * For color matching, this function uses the Euclidean distance between colors in the
 * YCbCr color space, which yields to better results than using sRGB directly.
 *
 * A comparison can be found at https://twitter.com/Socram4x8/status/1733157380097995205/photo/1.
 */
gdImagePtr img_palettize(gdImagePtr rgb, int * palette, int palette_size);

/*
 * This function scales and crops the image to the given size.
 * Think of "background-size: cover" in CSS.
 */
gdImagePtr img_crop_to_fit(gdImagePtr orig, int width, int height);

#endif
