/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY. 
 * 
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL 
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL, 
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES. 
 * 
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS. 
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
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
 * by the Free Software Foundation, or, at your option, any later version. 
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 ****************************************************************************/

#ifndef IKEYS_H
#define IKEYS_H


/**
 * @brief
 *Definition 11. Let the function hash0 : F 82 × F 82 × (F 62 ) 8 → (F 82 ) 8 be defined as
 *	hash0(x, y, z [0] . . . z [7] ) = k [0] . . . k [7] where
 * z'[i] = (z[i] mod (63-i)) + i	i =  0...3
 * z'[i+4] = (z[i+4] mod (64-i)) + i	i =  0...3
 * ẑ = check(z');
 * @param c
 * @param k this is where the diversified key is put (should be 8 bytes)
 * @return
 */
void hash0(uint64_t c, uint8_t k[8]);
int doKeyTests(uint8_t debuglevel);
/**
 * @brief Performs Elite-class key diversification
 * @param csn
 * @param key
 * @param div_key
 */

void diversifyKey(uint8_t csn[8], uint8_t key[8], uint8_t div_key[8]);
/**
 * @brief Permutes a key from standard NIST format to Iclass specific format
 * @param key
 * @param dest
 */

#endif // IKEYS_H
