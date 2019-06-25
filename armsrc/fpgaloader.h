//-----------------------------------------------------------------------------
// Jonathan Westhues, April 2006
// iZsh <izsh at fail0verflow.com>, 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//-----------------------------------------------------------------------------
#ifndef __FPGALOADER_H
#define __FPGALOADER_H

#include <stdint.h>
#include <stdbool.h>
#include "apps.h"
#include "fpga.h"
#include "common.h"     // standard definitions
#include "proxmark3.h"  // common area
#include "string.h"
#include "BigBuf.h"     // bigbuf mem
#include "zlib.h"       // uncompress


void FpgaSendCommand(uint16_t cmd, uint16_t v);
void FpgaWriteConfWord(uint8_t v);
void FpgaDownloadAndGo(int bitstream_version);
// void FpgaGatherVersion(int bitstream_version, char *dst, int len);
void FpgaSetupSsc(void);
void SetupSpi(int mode);
bool FpgaSetupSscDma(uint8_t *buf, int len);
void Fpga_print_status(void);
int FpgaGetCurrent(void);
#define FpgaDisableSscDma(void) AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
#define FpgaEnableSscDma(void) AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;
void SetAdcMuxFor(uint32_t whichGpio);

// extern and generel turn off the antenna method
void switch_off(void);

// definitions for multiple FPGA config files support
#define FPGA_BITSTREAM_LF 1
#define FPGA_BITSTREAM_HF 2
//#define FPGA_BITSTREAM_FELICA 3

// Definitions for the FPGA commands.
#define FPGA_CMD_SET_CONFREG                        (1<<12)
#define FPGA_CMD_SET_DIVISOR                        (2<<12)
#define FPGA_CMD_SET_USER_BYTE1                     (3<<12)
// Definitions for the FPGA configuration word.
// LF
#define FPGA_MAJOR_MODE_LF_ADC                      (0<<5)
#define FPGA_MAJOR_MODE_LF_EDGE_DETECT              (1<<5)
#define FPGA_MAJOR_MODE_LF_PASSTHRU                 (2<<5)
// HF
#define FPGA_MAJOR_MODE_HF_READER_TX                (0<<5)
#define FPGA_MAJOR_MODE_HF_READER_RX_XCORR          (1<<5)
#define FPGA_MAJOR_MODE_HF_SIMULATOR                (2<<5)
#define FPGA_MAJOR_MODE_HF_ISO14443A                (3<<5)
#define FPGA_MAJOR_MODE_HF_SNOOP                    (4<<5)
#define FPGA_MAJOR_MODE_HF_FELICA                   (5<<5)
// BOTH
#define FPGA_MAJOR_MODE_OFF_LF                      (6<<5)
#define FPGA_MAJOR_MODE_OFF                         (7<<5)

// Options for LF_ADC
#define FPGA_LF_ADC_READER_FIELD                    (1<<0)
// Options for LF_EDGE_DETECT
#define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          FPGA_CMD_SET_USER_BYTE1
#define FPGA_LF_EDGE_DETECT_READER_FIELD            (1<<0)
#define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             (1<<1)
// Options for the HF reader, tx to tag
#define FPGA_HF_READER_TX_SHALLOW_MOD               (1<<0)
// Options for the HF reader, correlating against rx from tag
#define FPGA_HF_READER_RX_XCORR_848_KHZ             (1<<0)
#define FPGA_HF_READER_RX_XCORR_SNOOP               (1<<1)
#define FPGA_HF_READER_RX_XCORR_QUARTER             (1<<2)
// Options for the HF simulated tag, how to modulate
#define FPGA_HF_SIMULATOR_NO_MODULATION             0x0 // 0000
#define FPGA_HF_SIMULATOR_MODULATE_BPSK             0x1 // 0001
#define FPGA_HF_SIMULATOR_MODULATE_212K             0x2 // 0010
#define FPGA_HF_SIMULATOR_MODULATE_424K             0x4 // 0100
#define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        0x5 // 0101
//  no 848K

// Options for ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER                   (0<<0)
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN             (1<<0)
#define FPGA_HF_ISO14443A_TAGSIM_MOD                (2<<0)
#define FPGA_HF_ISO14443A_READER_LISTEN             (3<<0)
#define FPGA_HF_ISO14443A_READER_MOD                (4<<0)

//options for Felica.
#define FPGA_MAJOR_MODE_ISO18092                    (5<<5) // 01010 0000
#define FPGA_HF_ISO18092_FLAG_NOMOD                 (1<<0) // 0001 disable modulation module
#define FPGA_HF_ISO18092_FLAG_424K                  (2<<0) // 0010 should enable 414k mode (untested). No autodetect
#define FPGA_HF_ISO18092_FLAG_READER                (4<<0) // 0100 enables antenna power, to act as a reader instead of tag

#endif
