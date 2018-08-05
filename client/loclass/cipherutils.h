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


#ifndef CIPHERUTILS_H
#define CIPHERUTILS_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
	uint8_t * buffer;
	uint8_t numbits;
	uint8_t position;
} BitstreamIn;

typedef struct {
	uint8_t * buffer;
	uint8_t numbits;
	uint8_t position;
}BitstreamOut;

bool headBit( BitstreamIn *stream);
bool tailBit( BitstreamIn *stream);
void pushBit( BitstreamOut *stream, bool bit);
int bitsLeft( BitstreamIn *stream);
#ifndef ON_DEVICE
int testCipherUtils(void);
int testMAC();
#endif
void push6bits( BitstreamOut* stream, uint8_t bits);
void EncryptDES(bool key[56], bool outBlk[64], bool inBlk[64], int verbose) ;
void x_num_to_bytes(uint64_t n, size_t len, uint8_t* dest);
uint64_t x_bytes_to_num(uint8_t* src, size_t len);
uint8_t reversebytes(uint8_t b);
void reverse_arraybytes(uint8_t* arr, size_t len);
void reverse_arraycopy(uint8_t* arr, uint8_t* dest, size_t len);
void printarr(char * name, uint8_t* arr, int len);
void printvar(char * name, uint8_t* arr, int len);
void printarr_human_readable(char * title, uint8_t* arr, int len);
#endif // CIPHERUTILS_H
