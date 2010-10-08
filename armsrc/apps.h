//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------

#ifndef __APPS_H
#define __APPS_H

#include <stdint.h>
#include <stddef.h>
typedef unsigned char byte_t;

// The large multi-purpose buffer, typically used to hold A/D samples,
// maybe processed in some way.
uint32_t BigBuf[8000];

// This may be used (sparingly) to declare a function to be copied to
// and executed from RAM
#define RAMFUNC __attribute((long_call, section(".ramfunc")))

/// appmain.h
void ReadMem(int addr);
void __attribute__((noreturn)) AppMain(void);
void SamyRun(void);
//void DbpIntegers(int a, int b, int c);
void DbpString(char *str);
void Dbprintf(const char *fmt, ...);

void ToSendStuffBit(int b);
void ToSendReset(void);
void ListenReaderField(int limit);
void AcquireRawAdcSamples125k(int at134khz);
void DoAcquisition125k(void);
extern int ToSendMax;
extern uint8_t ToSend[];
extern uint32_t BigBuf[];

/// fpga.h
void FpgaSendCommand(uint16_t cmd, uint16_t v);
void FpgaWriteConfWord(uint8_t v);
void FpgaDownloadAndGo(void);
void FpgaGatherVersion(char *dst, int len);
void FpgaSetupSsc(void);
void SetupSpi(int mode);
void FpgaSetupSscDma(uint8_t *buf, int len);
void SetAdcMuxFor(uint32_t whichGpio);

// Definitions for the FPGA commands.
#define FPGA_CMD_SET_CONFREG						(1<<12)
#define FPGA_CMD_SET_DIVISOR						(2<<12)
// Definitions for the FPGA configuration word.
#define FPGA_MAJOR_MODE_LF_READER					(0<<5)
#define FPGA_MAJOR_MODE_LF_SIMULATOR				(1<<5)
#define FPGA_MAJOR_MODE_HF_READER_TX				(2<<5)
#define FPGA_MAJOR_MODE_HF_READER_RX_XCORR			(3<<5)
#define FPGA_MAJOR_MODE_HF_SIMULATOR				(4<<5)
#define FPGA_MAJOR_MODE_HF_ISO14443A				(5<<5)
#define FPGA_MAJOR_MODE_LF_PASSTHRU					(6<<5)
#define FPGA_MAJOR_MODE_OFF							(7<<5)
// Options for the HF reader, tx to tag
#define FPGA_HF_READER_TX_SHALLOW_MOD				(1<<0)
// Options for the HF reader, correlating against rx from tag
#define FPGA_HF_READER_RX_XCORR_848_KHZ				(1<<0)
#define FPGA_HF_READER_RX_XCORR_SNOOP				(1<<1)
#define FPGA_HF_READER_RX_XCORR_QUARTER_FREQ			(1<<2)
// Options for the HF simulated tag, how to modulate
#define FPGA_HF_SIMULATOR_NO_MODULATION				(0<<0)
#define FPGA_HF_SIMULATOR_MODULATE_BPSK				(1<<0)
#define FPGA_HF_SIMULATOR_MODULATE_212K				(2<<0)
// Options for ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER					(0<<0)
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN				(1<<0)
#define FPGA_HF_ISO14443A_TAGSIM_MOD				(2<<0)
#define FPGA_HF_ISO14443A_READER_LISTEN				(3<<0)
#define FPGA_HF_ISO14443A_READER_MOD				(4<<0)

/// lfops.h
void AcquireRawAdcSamples125k(int at134khz);
void ModThenAcquireRawAdcSamples125k(int delay_off,int period_0,int period_1,uint8_t *command);
void ReadTItag(void);
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc);
void AcquireTiType(void);
void AcquireRawBitsTI(void);
void SimulateTagLowFrequency(int period, int gap, int ledcontrol);
void CmdHIDsimTAG(int hi, int lo, int ledcontrol);
void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol);
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen);

/// iso14443.h
void SimulateIso14443Tag(void);
void AcquireRawAdcSamplesIso14443(uint32_t parameter);
void ReadSRI512Iso14443(uint32_t parameter);
void ReadSRIX4KIso14443(uint32_t parameter);
void ReadSTMemoryIso14443(uint32_t parameter,uint32_t dwLast);
void SnoopIso14443(void);

/// iso14443a.h
void RAMFUNC SnoopIso14443a(void);
void SimulateIso14443aTag(int tagType, int TagUid);	// ## simulate iso14443a tag
void ReaderIso14443a(UsbCommand * c, UsbCommand * ack);
void ReaderMifare(uint32_t parameter);

/// iso15693.h
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(uint32_t parameter);	// Simulate an ISO15693 reader - greg
void SimTagIso15693(uint32_t parameter);	// simulate an ISO15693 tag - greg

/// util.h

#endif
