/*****************************************************************************
 * This file is part of iClassCipher. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IClassCipher.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

#ifndef CIPHER_H
#define CIPHER_H
#include <stdint.h>

/**
* Definition 1 (Cipher state). A cipher state of iClass s is an element of F 40/2
* consisting of the following four components:
* 	1. the left register l = (l 0 . . . l 7 ) ∈ F 8/2 ;
* 	2. the right register r = (r 0 . . . r 7 ) ∈ F 8/2 ;
* 	3. the top register t = (t 0 . . . t 15 ) ∈ F 16/2 .
* 	4. the bottom register b = (b 0 . . . b 7 ) ∈ F 8/2 .
**/
typedef struct {
	uint8_t l;
	uint8_t r;
	uint8_t b;
	uint16_t t;
} State;

void printarr(char * name, uint8_t* arr, int len);
int calc_iclass_mac(uint8_t *cc_nr_p, uint8_t *div_key_p, uint8_t *mac);

#endif // CIPHER_H
