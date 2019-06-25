/* config.h
 * Greg Cook, 23/Feb/2019
 */

/* CRC RevEng: arbitrary-precision CRC calculator and algorithm finder
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018,
 * 2019  Gregory Cook
 *
 * This file is part of CRC RevEng.
 *
 * CRC RevEng is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CRC RevEng is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CRC RevEng.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CONFIG_H
#define CONFIG_H 1

/*****************************************
 *                                       *
 *  Start of user configuration options  *
 *                                       *
 *****************************************/

/* A type to contain polynomial coefficient bitmaps.
 * Can be changed to 'unsigned long long' for some extended compilers.
 * Adjust BMP_C(), BMP_BIT and BMP_SUB below if this is changed.
 */

#define BMP_T unsigned long

/* Creates an appropriate numeric constant for bmp_t.
 * If the underlying type is 'unsigned long long', change UL to ULL.
 */

#define BMP_C(n) (n##UL)

/* Define BMPMACRO to turn the definitions of the size of a bmp_t into
 * compile-time constants.  This improves efficiency but makes the code
 * platform-specific.
 */

/* #define BMPMACRO 1 */

/* Some enterprise users may wish to disable the -F switch to minimise CPU
 * usage.  To do this, define the macro ALWPCK.
 */

/* #define ALWPCK   1 */

/* Define PRESETS to compile CRC RevEng with the preset models from the
 * CRC Catalogue.  This implies BMPMACRO and so makes the code platform-
 * specific.
 */

#ifdef _WIN32
#define PRESETS  1 //
#endif


/* Macros defining the size of a bmp_t.
 * Their values only matter if PRESETS and/or BMPMACRO are defined, in
 * which case edit the macros below to suit your architecture.
 * Otherwise, BMP_BIT and BMP_SUB will be redefined as aliases of bmpbit
 * and bmpsub, global objects initialised at run time.
 */

/* Size in bits of a bmp_t.  Not necessarily a power of two. */

#define BMP_BIT   32

/* The highest power of two that is strictly less than BMP_BIT.
 * Initialises the index of a binary search for set bits in a bmp_t.
 */

#define BMP_SUB   16

/*****************************************
 *                                       *
 *   End of user configuration options   *
 *                                       *
 *****************************************/

#endif /* CONFIG_H */
