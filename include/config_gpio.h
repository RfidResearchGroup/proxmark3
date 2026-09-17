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
// GPIO pin mapping for the Proxmark[?]
//-----------------------------------------------------------------------------

#ifndef CONFIG_GPIO_H_
#define CONFIG_GPIO_H_

// Select a GPIO map config for building device.

/**
 * TODO DXL:
 *  After the complete migration, please select different GPIO configurations according to the compilation target,
 *  and do not include all of them!
 */

#ifdef PM5
#include "config_gpio_proxmark5.h"
#endif
#include "config_gpio_proxmark3.h" // TODO DXL: For test... include it.

/*

#ifdef PM5
#include "config_gpio_proxmark5.h"
#else
#include "config_gpio_proxmark3.h"
#endif

*/

#endif // CONFIG_GPIO_H_
