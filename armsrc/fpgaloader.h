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

/*
  SEE ALSO: fpga/define.v
*/

// definitions for multiple FPGA config files support
//

/*
  Each FPGA bitstream may interpret commands and other frames differently.
  To ensure can always turn off the FPGA, the following frame must be the
  same for all FPGA bitstreams:

+------ Common "turn off FPGA" frame -------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  0  0  0  1  0  0  0  1  1  1  0  0  0  0  0  0 | C = FPGA_CMD_SET_CONFREG
|  C  C  C  C           M  M  M                   | M = FPGA_MAJOR_MODE_OFF
+-------------------------------------------------+
*/

// This leaves 15 commands that each major mode can define.
#define FPGA_BITSTREAM_LF 1
#define FPGA_BITSTREAM_HF 2
#define FPGA_BITSTREAM_HF_FELICA 3
#define FPGA_BITSTREAM_HF_15 4
#define FPGA_BITSTREAM_MIN_VALID 1
#define FPGA_BITSTREAM_MAX_VALID 4

// Definitions for the FPGA commands.

// For all FPGA bitstreams (LF, HF, HF_FELICA, HF_15, ...)
#define FPGA_CMD_SET_CONFREG                        (1<<12) // C
#define FPGA_MAJOR_MODE_OFF                         (7<<6)  // M
#define FPGA_MAJOR_MODE_MASK                        0x01C0


/*
  Hic Sunt Dracones.
  Code in fpgaloader.c enables 16-bits per transfer only if:
  * bitstream is either FPGA_BITSTREAM_HF or FPGA_BITSTREAM_HF_15
    AND
  * HF mode is either FPGA_MAJOR_MODE_HF_READER or FPGA_MAJOR_MODE_HF_FSK_READER

  Historically, the major mode location and bitmask was shared by both LF and HF.
  There is no requirement that this be the case for all bitstreams.
*/


#if true // FPGA_BITSTREAM_LF

/*
+------ LF frame layout current ------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C           M  M  M  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_LF_* parameter
|  C  C  C  C              D  D  D  D  D  D  D  D | C = FPGA_CMD_SET_DIVISOR, D = divisor
|  C  C  C  C              T  T  T  T  T  T  T  T | C = FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, T = threshold
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
+-------------------------------------------------+
*/

// Additional commands for LF bitstream
#define FPGA_CMD_SET_DIVISOR                        (2<<12) // C
#define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          (3<<12) // C
#define FPGA_CMD_SET_USER_BYTE1                     (3<<12) // C

// LF
#define FPGA_MAJOR_MODE_LF_READER                   (0<<6)
#define FPGA_MAJOR_MODE_LF_EDGE_DETECT              (1<<6)
#define FPGA_MAJOR_MODE_LF_PASSTHRU                 (2<<6) // In PASSTHRU mode, SSP_DIN: connects to the CROSS_LO line; SSP_DOUT: high == we're modulating the antenna, low == listening to antenna
#define FPGA_MAJOR_MODE_LF_ADC                      (3<<6)

// Options for LF_READER
#define FPGA_LF_ADC_READER_FIELD                    0x1

// Options for LF_EDGE_DETECT
#define FPGA_LF_EDGE_DETECT_READER_FIELD            0x1
#define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             0x2

#endif // FPGA_BITSTREAM_LF

#if true // FPGA_BITSTREAM_HF (also used for FPGA_BITSTREAM_HF_15)

/*
+------ HF frame layout current ------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C           M  M  M  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_HF_* parameter
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
+-------------------------------------------------+
*/

// HF additional commands
#define FPGA_CMD_TRACE_ENABLE                       (2<<12) // C

// HF major modes for FPGA_CMD_SET_CONFREG
#define FPGA_MAJOR_MODE_HF_READER                   (0<<6) // M 0b000
#define FPGA_MAJOR_MODE_HF_SIMULATOR                (1<<6) // M 0b001
#define FPGA_MAJOR_MODE_HF_ISO14443A                (2<<6) // M 0b010
#define FPGA_MAJOR_MODE_HF_SNIFF                    (3<<6) // M 0b011
#define FPGA_MAJOR_MODE_HF_ISO18092                 (4<<6) // M 0b100
#define FPGA_MAJOR_MODE_HF_GET_TRACE                (5<<6) // M 0b101
#define FPGA_MAJOR_MODE_HF_FSK_READER               (6<<6) // M 0b110
//                                                         // M 0b111 is reserved for common "off" command

// Options for FPGA_MAJOR_MODE_HF_READER
#define FPGA_HF_READER_MODE_RECEIVE_IQ              (0<<0) // P 0b_00_0000
#define FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE       (1<<0) // P 0b_00_0001
#define FPGA_HF_READER_MODE_RECEIVE_PHASE           (2<<0) // P 0b_00_0010
#define FPGA_HF_READER_MODE_SEND_FULL_MOD           (3<<0) // P 0b_00_0011
#define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD        (4<<0) // P 0b_00_0100
#define FPGA_HF_READER_MODE_SNIFF_IQ                (5<<0) // P 0b_00_0101
#define FPGA_HF_READER_MODE_SNIFF_AMPLITUDE         (6<<0) // P 0b_00_0110
#define FPGA_HF_READER_MODE_SNIFF_PHASE             (7<<0) // P 0b_00_0111
#define FPGA_HF_READER_MODE_SEND_JAM                (8<<0) // P 0b_00_1000
#define FPGA_HF_READER_SUBCARRIER_848_KHZ           (0<<4) // P 0b_00_0000
#define FPGA_HF_READER_SUBCARRIER_424_KHZ           (1<<4) // P 0b_01_0000
#define FPGA_HF_READER_SUBCARRIER_212_KHZ           (2<<4) // P 0b_10_0000
#define FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ     (3<<4) // P 0b_11_0000


// Options for FPGA_MAJOR_MODE_HF_SIMULATOR (the HF simulated tag, how to modulate)
#define FPGA_HF_SIMULATOR_NO_MODULATION             0x0 // P 0b_00_0000
#define FPGA_HF_SIMULATOR_MODULATE_BPSK             0x1 // P 0b_00_0001
#define FPGA_HF_SIMULATOR_MODULATE_212K             0x2 // P 0b_00_0010
#define FPGA_HF_SIMULATOR_MODULATE_424K             0x4 // P 0b_00_0100
#define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        0x5 // P 0b_00_0101
//  no 848K

// Options for FPGA_MAJOR_MODE_HF_ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER                   0x0 // P 0b_00_0000
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN             0x1 // P 0b_00_0001
#define FPGA_HF_ISO14443A_TAGSIM_MOD                0x2 // P 0b_00_0010
#define FPGA_HF_ISO14443A_READER_LISTEN             0x3 // P 0b_00_0011
#define FPGA_HF_ISO14443A_READER_MOD                0x4 // P 0b_00_0100

// No options defined for FPGA_MAJOR_MODE_HF_SNIFF

// Options for FPGA_MAJOR_MODE_HF_ISO18092 (Felica)
#define FPGA_HF_ISO18092_FLAG_NOMOD                 0x1 // P 0b_00_0001 - disable modulation module
#define FPGA_HF_ISO18092_FLAG_424K                  0x2 // P 0b_00_0010 - should enable 414k mode (untested). No autodetect
#define FPGA_HF_ISO18092_FLAG_READER                0x4 // P 0b_00_0100 - enables antenna power, to act as a reader instead of tag

// No options defined for FPGA_MAJOR_MODE_HF_GET_TRACE
// No options defined for FPGA_MAJOR_MODE_HF_FSK_READER

#endif // FPGA_BITSTREAM_HF (also used for FPGA_BITSTREAM_HF_15)

// No commands or options defined for FPGA_BITSTREAM_HF_FELICA

#if true  // FPGA_BITSTREAM_HF_15

// FPGA_BITSTREAM_HF_15 appears to support READER and SIMULATOR modes
// from FPGA_BITSTREAM_HF, with existing code using the following:
//     FPGA_MAJOR_MODE_HF_READER
//         FPGA_HF_READER_MODE_RECEIVE_IQ
//         FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE
//         FPGA_HF_READER_MODE_SEND_FULL_MOD
//         FPGA_HF_READER_MODE_SEND_SHALLOW_MOD
//         FPGA_HF_READER_MODE_SNIFF_IQ
//         FPGA_HF_READER_MODE_SNIFF_AMPLITUDE
//         FPGA_HF_READER_MODE_SEND_JAM
//         FPGA_HF_READER_SUBCARRIER_848_KHZ
//         FPGA_HF_READER_SUBCARRIER_424_KHZ
//         FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ
//
//     FPGA_MAJOR_MODE_HF_SIMULATOR
//         FPGA_HF_SIMULATOR_NO_MODULATION
//         FPGA_HF_SIMULATOR_MODULATE_424K

#endif // FPGA_BITSTREAM_HF_15





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
