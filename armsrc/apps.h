//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
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
#include "common.h"
#include "hitag2.h"
#include "mifare.h"

// The large multi-purpose buffer, typically used to hold A/D samples,
// maybe processed in some way.
uint32_t BigBuf[10000];
// BIG CHANGE - UNDERSTAND THIS BEFORE WE COMMIT
#define TRACE_OFFSET          0
#define TRACE_SIZE         3000
#define RECV_CMD_OFFSET    3032
#define RECV_CMD_SIZE        64
#define RECV_RES_OFFSET    3096
#define RECV_RES_SIZE        64
#define DMA_BUFFER_OFFSET  3160
#define DMA_BUFFER_SIZE    4096
#define FREE_BUFFER_OFFSET 7256
#define FREE_BUFFER_SIZE   2744

extern const uint8_t OddByteParity[256];
extern uint8_t *trace; // = (uint8_t *) BigBuf;
extern int traceLen;   // = 0;
extern int rsamples;   // = 0;
extern int tracing;    // = TRUE;
extern uint8_t trigger;

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
void Dbhexdump(int len, uint8_t *d, bool bAsci);

int AvgAdc(int ch);

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
bool FpgaSetupSscDma(uint8_t *buf, int len);
#define FpgaDisableSscDma(void)	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
#define FpgaEnableSscDma(void) AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;
void SetAdcMuxFor(uint32_t whichGpio);

// Definitions for the FPGA commands.
#define FPGA_CMD_SET_CONFREG						(1<<12)
#define FPGA_CMD_SET_DIVISOR						(2<<12)
// Definitions for the FPGA configuration word.
#define FPGA_MAJOR_MODE_LF_READER					(0<<5)
#define FPGA_MAJOR_MODE_LF_EDGE_DETECT				(1<<5)
#define FPGA_MAJOR_MODE_HF_READER_TX				(2<<5)
#define FPGA_MAJOR_MODE_HF_READER_RX_XCORR			(3<<5)
#define FPGA_MAJOR_MODE_HF_SIMULATOR				(4<<5)
#define FPGA_MAJOR_MODE_HF_ISO14443A				(5<<5)
#define FPGA_MAJOR_MODE_LF_PASSTHRU					(6<<5)
#define FPGA_MAJOR_MODE_OFF							(7<<5)
// Options for LF_EDGE_DETECT
#define FPGA_LF_EDGE_DETECT_READER_FIELD 			(1<<0)
// Options for the HF reader, tx to tag
#define FPGA_HF_READER_TX_SHALLOW_MOD				(1<<0)
// Options for the HF reader, correlating against rx from tag
#define FPGA_HF_READER_RX_XCORR_848_KHZ				(1<<0)
#define FPGA_HF_READER_RX_XCORR_SNOOP				(1<<1)
#define FPGA_HF_READER_RX_XCORR_QUARTER_FREQ		(1<<2)
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
void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT); // Clone an HID card to T5557/T5567
void WriteEM410x(uint32_t card, uint32_t id_hi, uint32_t id_lo);
void CopyIndala64toT55x7(int hi, int lo); // Clone Indala 64-bit tag by UID to T55x7
void CopyIndala224toT55x7(int uid1, int uid2, int uid3, int uid4, int uid5, int uid6, int uid7); // Clone Indala 224-bit tag by UID to T55x7
void T55xxWriteBlock(uint32_t Data, uint32_t Block, uint32_t Pwd, uint8_t PwdMode);
void T55xxReadBlock(uint32_t Block, uint32_t Pwd, uint8_t PwdMode );
void T55xxReadTrace(void);
int DemodPCF7931(uint8_t **outBlocks);
int IsBlock0PCF7931(uint8_t *Block);
int IsBlock1PCF7931(uint8_t *Block);
void ReadPCF7931();
void EM4xReadWord(uint8_t Address, uint32_t Pwd, uint8_t PwdMode);
void EM4xWriteWord(uint32_t Data, uint8_t Address, uint32_t Pwd, uint8_t PwdMode);

/// iso14443.h
void SimulateIso14443Tag(void);
void AcquireRawAdcSamplesIso14443(uint32_t parameter);
void ReadSRI512Iso14443(uint32_t parameter);
void ReadSRIX4KIso14443(uint32_t parameter);
void ReadSTMemoryIso14443(uint32_t parameter,uint32_t dwLast);
void RAMFUNC SnoopIso14443(void);

/// iso14443a.h
void RAMFUNC SnoopIso14443a(uint8_t param);
void SimulateIso14443aTag(int tagType, int uid_1st, int uid_2nd);	// ## simulate iso14443a tag
void ReaderIso14443a(UsbCommand * c);
// Also used in iclass.c
int RAMFUNC LogTrace(const uint8_t * btBytes, int iLen, int iSamples, uint32_t dwParity, int bReader);
uint32_t GetParity(const uint8_t * pbtCmd, int iLen);
void iso14a_set_trigger(bool enable);
void iso14a_clear_trace();
void iso14a_set_tracing(bool enable);
void RAMFUNC SniffMifare(uint8_t param);

/// epa.h
void EPA_PACE_Collect_Nonce(UsbCommand * c);

// mifarecmd.h
void ReaderMifare(uint32_t parameter);
void MifareReadBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *data);
void MifareReadSector(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareNested(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareChkKeys(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void Mifare1ksim(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareSetDbgLvl(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareEMemClr(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareEMemSet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareEMemGet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);  // Work with "magic Chinese" card
void MifareCGetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);

/// iso15693.h
void RecordRawAdcSamplesIso15693(void);
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(uint32_t parameter);	// Simulate an ISO15693 reader - greg
void SimTagIso15693(uint32_t parameter);	// simulate an ISO15693 tag - greg
void BruteforceIso15693Afi(uint32_t speed); // find an AFI of a tag - atrox
void DirectTag15693Command(uint32_t datalen,uint32_t speed, uint32_t recv, uint8_t data[]); // send arbitrary commands from CLI - atrox 
void SetDebugIso15693(uint32_t flag);

/// iclass.h
void RAMFUNC SnoopIClass(void);
void SimulateIClass(uint8_t arg0, uint8_t *datain);
void ReaderIClass(uint8_t arg0);

// hitag2.h
void SnoopHitag(uint32_t type);
void SimulateHitagTag(bool tag_mem_supplied, byte_t* data);
void ReaderHitag(hitag_function htf, hitag_data* htd);

// cmd.h
bool cmd_receive(UsbCommand* cmd);
bool cmd_send(uint32_t cmd, uint32_t arg0, uint32_t arg1, uint32_t arg2, void* data, size_t len);

/// util.h

#endif
