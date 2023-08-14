//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, April 2006
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
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//-----------------------------------------------------------------------------
#ifndef __FPGALOADER_H
#define __FPGALOADER_H

#include "common.h"

#define FpgaDisableSscDma(void) AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
#define FpgaEnableSscDma(void) AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;

// definitions for multiple FPGA config files support
#define FPGA_BITSTREAM_LF 1
#define FPGA_BITSTREAM_HF 2
#define FPGA_BITSTREAM_HF_FELICA 3
#define FPGA_BITSTREAM_HF_15 4

/*
  Communication between ARM / FPGA is done inside armsrc/fpgaloader.c (function FpgaSendCommand)
  Send 16 bit command / data pair to FPGA

  BUGBUG -- Conflicts with information in ../fpga/define.v

  The bit format is: C3 C2 C1 C0 D11 D10 D9 D8 D7 D6 D5 D4 D3 D2 D1 D0
  where
    C is 4bit command
    D is 12bit data

-----+--------- frame layout --------------------
bit  |    15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
-----+-------------------------------------------
cmd  |     x  x  x  x
major|                          x x x
opt  |                                      x x
divi |                          x x x x x x x x
thres|                          x x x x x x x x
-----+-------------------------------------------
*/

// Definitions for the FPGA commands.
// BOTH HF / LF
#define FPGA_CMD_SET_CONFREG                        (1<<12) // C

// LF
#define FPGA_CMD_SET_DIVISOR                        (2<<12) // C
#define FPGA_CMD_SET_USER_BYTE1                     (3<<12) // C

// HF
#define FPGA_CMD_TRACE_ENABLE                       (2<<12) // C

// Definitions for the FPGA configuration word.
#define FPGA_MAJOR_MODE_MASK                        0x01C0
#define FPGA_MINOR_MODE_MASK                        0x003F

// LF
#define FPGA_MAJOR_MODE_LF_READER                   (0<<6)
#define FPGA_MAJOR_MODE_LF_EDGE_DETECT              (1<<6)
#define FPGA_MAJOR_MODE_LF_PASSTHRU                 (2<<6)
#define FPGA_MAJOR_MODE_LF_ADC                      (3<<6)

// HF
#define FPGA_MAJOR_MODE_HF_READER                   (0<<6) // D
#define FPGA_MAJOR_MODE_HF_SIMULATOR                (1<<6) // D
#define FPGA_MAJOR_MODE_HF_ISO14443A                (2<<6) // D
#define FPGA_MAJOR_MODE_HF_SNIFF                    (3<<6) // D
#define FPGA_MAJOR_MODE_HF_ISO18092                 (4<<6) // D
#define FPGA_MAJOR_MODE_HF_GET_TRACE                (5<<6) // D
#define FPGA_MAJOR_MODE_HF_FSK_READER               (6<<6) // D

// BOTH HF / LF
#define FPGA_MAJOR_MODE_OFF                         (7<<6) // D


// Options for LF_READER
#define FPGA_LF_ADC_READER_FIELD                    0x1

// Options for LF_EDGE_DETECT
#define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          FPGA_CMD_SET_USER_BYTE1
#define FPGA_LF_EDGE_DETECT_READER_FIELD            0x1
#define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             0x2

// Options for the HF reader
#define FPGA_HF_READER_MODE_RECEIVE_IQ              (0<<0)
#define FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE       (1<<0)
#define FPGA_HF_READER_MODE_RECEIVE_PHASE           (2<<0)
#define FPGA_HF_READER_MODE_SEND_FULL_MOD           (3<<0)
#define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD        (4<<0)
#define FPGA_HF_READER_MODE_SNIFF_IQ                (5<<0)
#define FPGA_HF_READER_MODE_SNIFF_AMPLITUDE         (6<<0)
#define FPGA_HF_READER_MODE_SNIFF_PHASE             (7<<0)
#define FPGA_HF_READER_MODE_SEND_JAM                (8<<0)

#define FPGA_HF_READER_SUBCARRIER_848_KHZ           (0<<4)
#define FPGA_HF_READER_SUBCARRIER_424_KHZ           (1<<4)
#define FPGA_HF_READER_SUBCARRIER_212_KHZ           (2<<4)
#define FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ     (3<<4)

// Options for the HF simulated tag, how to modulate
#define FPGA_HF_SIMULATOR_NO_MODULATION             0x0 // 0000
#define FPGA_HF_SIMULATOR_MODULATE_BPSK             0x1 // 0001
#define FPGA_HF_SIMULATOR_MODULATE_212K             0x2 // 0010
#define FPGA_HF_SIMULATOR_MODULATE_424K             0x4 // 0100
#define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        0x5 // 0101
//  no 848K

// Options for ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER                   0x0
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN             0x1
#define FPGA_HF_ISO14443A_TAGSIM_MOD                0x2
#define FPGA_HF_ISO14443A_READER_LISTEN             0x3
#define FPGA_HF_ISO14443A_READER_MOD                0x4

//options for Felica.
#define FPGA_HF_ISO18092_FLAG_NOMOD                 0x1 // 0001 disable modulation module
#define FPGA_HF_ISO18092_FLAG_424K                  0x2 // 0010 should enable 414k mode (untested). No autodetect
#define FPGA_HF_ISO18092_FLAG_READER                0x4 // 0100 enables antenna power, to act as a reader instead of tag

void FpgaSendCommand(uint16_t cmd, uint16_t v);
void FpgaWriteConfWord(uint16_t v);
void FpgaEnableTracing(void);
void FpgaDisableTracing(void);
void FpgaDownloadAndGo(int bitstream_version);
// void FpgaGatherVersion(int bitstream_version, char *dst, int len);
void FpgaSetupSsc(uint16_t fpga_mode);
void SetupSpi(int mode);
bool FpgaSetupSscDma(uint8_t *buf, uint16_t len);
void Fpga_print_status(void);
int FpgaGetCurrent(void);
void SetAdcMuxFor(uint32_t whichGpio);

// extern and generel turn off the antenna method
void switch_off(void);

#endif
