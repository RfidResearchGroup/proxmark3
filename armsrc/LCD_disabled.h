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
// LCD code
//-----------------------------------------------------------------------------

#ifndef __LCD_H
#define __LCD_H

// The resolution of the LCD
#define LCD_XRES    132
#define LCD_YRES    132

// 8bpp Color Mode - Some basic colors defined for ease of use
// remember 8bpp color = 3xRed, 3xGreen & 2xBlue bits
// organised as RRRGGGBB

#define BLACK       0x00
#define BLUE        0x03
#define GREEN       0x1C
#define CYAN        0x1F
#define RED         0xE0
#define MAGENTA     0xE3
#define YELLOW      0xFC
#define WHITE       0xFF

// EPSON LCD command set
#define ECASET      0x115
#define EPWRCTR     0x120
#define ENOP        0x125
#define ERAMWR      0x15C
#define ERAMRD      0x15D
#define EPASET      0x175
#define EEPSRRD1    0x17C
#define EEPSRRD2    0x17D
#define EVOLCTR     0x181
#define ETMPGRD     0x182
#define ESLPOUT     0x194
#define ESLPIN      0x195
#define EDISNOR     0x1A6
#define EDISINV     0x1A7
#define EPTLIN      0x1A8
#define EPTLOUT     0x1A9
#define EASCSET     0x1AA
#define ESCSTART    0x1AB
#define EDISOFF     0x1AE
#define EDISON      0x1AF
#define ECOMSCN     0x1BB
#define EDATCTL     0x1BC
#define EDISCTL     0x1CA
#define EEPCOUT     0x1CC
#define EEPCTIN     0x1CD
#define ERGBSET8    0x1CE
#define EOSCON      0x1D1
#define EOSCOFF     0x1D2
#define EVOLUP      0x1D6
#define EVOLDOWN    0x1D7
#define ERMWIN      0x1E0
#define ERMWOUT     0x1EE
#define EEPMWR      0x1FC
#define EEPMRD      0x1FD

// PHILIPS LCD command set
#define PNOP        0x100
#define PSWRESET    0x101
#define PBSTROFF    0x102
#define PBSTRON     0x103
#define PRDDIDIF    0x104
#define PRDDST      0x109
#define PSLEEPIN    0x110
#define PSLEEPOUT   0x111
#define PPTLON      0x112
#define PNORON      0x113
#define PINVOFF     0x120
#define PINVON      0x121
#define PDALO       0x122
#define PDAL        0x123
#define PSETCON     0x125
#define PDISPOFF    0x128
#define PDISPON     0x129
#define PCASET      0x12A
#define PPASET      0x12B
#define PRAMWR      0x12C
#define PRGBSET     0x12D
#define PPTLAR      0x130
#define PVSCRDEF    0x133
#define PTEOFF      0x134
#define PTEON       0x135
#define PMADCTL     0x136
#define PSEP        0x137
#define PIDMOFF     0x138
#define PIDMON      0x139
#define PCOLMOD     0x13A
#define PSETVOP     0x1B0
#define PBRS        0x1B4
#define PTRS        0x1B6
#define PFINV       0x1B9
#define PDOR        0x1BA
#define PTCDFE      0x1BD
#define PTCVOPE     0x1BF
#define PEC         0x1C0
#define PSETMUL     0x1C2
#define PTCVOPAB    0x1C3
#define PTCVOPCD    0x1C4
#define PTCDF       0x1C5
#define PDF8C       0x1C6
#define PSETBS      0x1C7
#define PRDTEMP     0x1C8
#define PNLI        0x1C9
#define PRDID1      0x1DA
#define PRDID2      0x1DB
#define PRDID3      0x1DC
#define PSFD        0x1EF
#define PECM        0x1F0

void LCDSend(unsigned int data);
void LCDInit(void);
void LCDReset(void);
void LCDSetXY(unsigned char x, unsigned char y);
void LCDSetPixel(unsigned char x, unsigned char y, unsigned char color);
void LCDString(const char *lcd_string, const char *font_style, unsigned char x, unsigned char y, unsigned char fcolor, unsigned char bcolor);
void LCDFill(unsigned char xs, unsigned char ys, unsigned char width, unsigned char height, unsigned char color);

#endif
