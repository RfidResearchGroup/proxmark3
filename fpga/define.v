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
//
// The FPGA is responsible for interfacing between the A/D, the coil drivers,
// and the ARM. In the low-frequency modes it passes the data straight
// through, so that the ARM gets raw A/D samples over the SSP. In the high-
// frequency modes, the FPGA might perform some demodulation first, to
// reduce the amount of data that we must send to the ARM.
//-----------------------------------------------------------------------------

/*
 Communication between ARM / FPGA is done inside armsrc/fpgaloader.c see: function FpgaSendCommand()
 Send 16 bit command / data pair to FPGA with the bit format:

+------ frame layout circa 2020 ------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C  M  M  M  M  P  P  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_LF_* or FPGA_HF_* parameter
|  C  C  C  C              D  D  D  D  D  D  D  D | C = FPGA_CMD_SET_DIVISOR, D = divisor
|  C  C  C  C              T  T  T  T  T  T  T  T | C = FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, T = threshold
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
+-------------------------------------------------+

+------ frame layout current ---------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C           M  M  M  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_LF_* or FPGA_HF_* parameter
|  C  C  C  C              D  D  D  D  D  D  D  D | C = FPGA_CMD_SET_DIVISOR, D = divisor
|  C  C  C  C              T  T  T  T  T  T  T  T | C = FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, T = threshold
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
+-------------------------------------------------+

  shift_reg receive this 16bit frame

  LF command
  ----------
  shift_reg[15:12] == 4bit command
  LF has three commands (FPGA_CMD_SET_CONFREG, FPGA_CMD_SET_DIVISOR, FPGA_CMD_SET_EDGE_DETECT_THRESHOLD)
  Current commands uses only 2bits. We have room for up to 4bits of commands total (7).

  LF data
  -------
  shift_reg[11:0] == 12bit data
  lf data is divided into MAJOR MODES and configuration values.

  The major modes uses 3bits (0,1,2,3,7 | 000, 001, 010, 011, 111)
    000 FPGA_MAJOR_MODE_LF_READER        = Act as LF reader (modulate)
    001 FPGA_MAJOR_MODE_LF_EDGE_DETECT   = Simulate LF
    010 FPGA_MAJOR_MODE_LF_PASSTHRU      = Passthrough mode, CROSS_LO line connected to SSP_DIN. SSP_DOUT logic level controls if we modulate / listening
    011 FPGA_MAJOR_MODE_LF_ADC           = refactor hitag2, clear ADC sampling
    111 FPGA_MAJOR_MODE_OFF              = turn off sampling.

  Each one of this major modes can have options. Currently these two major modes uses options.
   - FPGA_MAJOR_MODE_LF_READER
   - FPGA_MAJOR_MODE_LF_EDGE_DETECT

   FPGA_MAJOR_MODE_LF_READER
   -------------------------------------
    lf_field = 1bit  (FPGA_LF_ADC_READER_FIELD)

    You can send FPGA_CMD_SET_DIVISOR to set with FREQUENCY the fpga should sample at
    divisor = 8bits shift_reg[7:0]

   FPGA_MAJOR_MODE_LF_EDGE_DETECT
   ------------------------------------------
    lf_ed_toggle_mode = 1bits
    lf_ed_threshold = 8bits threshold defaults to 127

    You can send FPGA_CMD_SET_EDGE_DETECT_THRESHOLD to set a custom threshold
    lf_ed_threshold = 8bits threshold value.

  conf_word 12bits
    conf_word[7:5]  = 3bit major mode.
    conf_word[0]    = 1bit lf_field
    conf_word[1]    = 1bit lf_ed_toggle_mode
    conf_word[7:0]  = 8bit divisor
    conf_word[7:0]  = 8bit threshold

*/
// Defining commands, modes and options. This must be aligned to the definitions in armsrc/fpgaloader.h
// Note: the definitions here are without shifts

// Definitions for the FPGA commands.
`define FPGA_CMD_SET_CONFREG                        1
`define FPGA_CMD_SET_DIVISOR                        2
`define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          3
`define FPGA_CMD_TRACE_ENABLE                       2

// Major modes
`define FPGA_MAJOR_MODE_LF_READER                   0
`define FPGA_MAJOR_MODE_LF_EDGE_DETECT              1
`define FPGA_MAJOR_MODE_LF_PASSTHRU                 2
`define FPGA_MAJOR_MODE_LF_ADC                      3
`define FPGA_MAJOR_MODE_HF_READER                   0
`define FPGA_MAJOR_MODE_HF_SIMULATOR                1
`define FPGA_MAJOR_MODE_HF_ISO14443A                2
`define FPGA_MAJOR_MODE_HF_SNIFF                    3
`define FPGA_MAJOR_MODE_HF_ISO18092                 4
`define FPGA_MAJOR_MODE_HF_GET_TRACE                5
`define FPGA_MAJOR_MODE_OFF                         7

// Options for LF_READER
`define FPGA_LF_ADC_READER_FIELD                    1

// Options for LF_EDGE_DETECT
`define FPGA_LF_EDGE_DETECT_READER_FIELD            1
`define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             2

// Options for the generic HF reader
`define FPGA_HF_READER_MODE_RECEIVE_IQ              0
`define FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE       1
`define FPGA_HF_READER_MODE_RECEIVE_PHASE           2
`define FPGA_HF_READER_MODE_SEND_FULL_MOD           3
`define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD        4
`define FPGA_HF_READER_MODE_SNIFF_IQ                5
`define FPGA_HF_READER_MODE_SNIFF_AMPLITUDE         6
`define FPGA_HF_READER_MODE_SNIFF_PHASE             7
`define FPGA_HF_READER_MODE_SEND_JAM                8
`define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD_RDV4   9

`define FPGA_HF_READER_SUBCARRIER_848_KHZ           0
`define FPGA_HF_READER_SUBCARRIER_424_KHZ           1
`define FPGA_HF_READER_SUBCARRIER_212_KHZ           2
`define FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ     3

// Options for the HF simulated tag, how to modulate
`define FPGA_HF_SIMULATOR_NO_MODULATION             0
`define FPGA_HF_SIMULATOR_MODULATE_BPSK             1
`define FPGA_HF_SIMULATOR_MODULATE_212K             2
`define FPGA_HF_SIMULATOR_MODULATE_424K             4
`define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        5

// Options for ISO14443A
`define FPGA_HF_ISO14443A_SNIFFER                   0
`define FPGA_HF_ISO14443A_TAGSIM_LISTEN             1
`define FPGA_HF_ISO14443A_TAGSIM_MOD                2
`define FPGA_HF_ISO14443A_READER_LISTEN             3
`define FPGA_HF_ISO14443A_READER_MOD                4

// Options for ISO18092 / Felica
`define FPGA_HF_ISO18092_FLAG_NOMOD                 1 // 0001 disable modulation module
`define FPGA_HF_ISO18092_FLAG_424K                  2 // 0010 should enable 414k mode (untested). No autodetect
`define FPGA_HF_ISO18092_FLAG_READER                4 // 0100 enables antenna power, to act as a reader instead of tag
