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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdarg.h>
#include "common.h"
#include "usb_cdc.h"
#include "crc32.h"
#include "lfdemod.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "hitag2.h"
#include "hitagS.h"
#include "mifare.h"
#include "pcf7931.h"
#include "desfire.h"
#include "iso14443b.h"
#include "Standalone/standalone.h"
#include "flashmem.h"

extern const uint8_t OddByteParity[256];
extern int rsamples;   // = 0;
extern int tracing;    // = TRUE;
extern uint8_t trigger;

// This may be used (sparingly) to declare a function to be copied to
// and executed from RAM
#define RAMFUNC __attribute((long_call, section(".ramfunc")))

/// appmain.h
void ReadMem(int addr);
void __attribute__((noreturn)) AppMain(void);
//void DbpIntegers(int a, int b, int c);
void DbpString(char *str);
void Dbprintf(const char *fmt, ...);
void DbprintfEx(uint32_t cmd, const char *fmt, ...);
void Dbhexdump(int len, uint8_t *d, bool bAsci);

// ADC Vref = 3300mV, and an (10M+1M):1M voltage divider on the HF input can measure voltages up to 36300 mV
#define MAX_ADC_HF_VOLTAGE 36300
// ADC Vref = 3300mV,  (240k-10M):240k voltage divider,  140800 mV
#define MAX_ADC_HF_VOLTAGE_RDV40 140800
// ADC Vref = 3300mV, and an (10000k+240k):240k voltage divider on the LF input can measure voltages up to 140800 mV
#define MAX_ADC_LF_VOLTAGE 140800
uint16_t AvgAdc(int ch);

void print_result(char *name, uint8_t *buf, size_t len);
void PrintToSendBuffer(void);
void ToSendStuffBit(int b);
void ToSendReset(void);
void ListenReaderField(int limit);
extern int ToSendMax;
extern uint8_t ToSend[];

extern void StandAloneMode(void);
extern void printStandAloneModes(void);

/// lfops.h
extern uint8_t decimation;
extern uint8_t bits_per_sample ;
extern bool averaging;

void AcquireRawAdcSamples125k(int divisor);
void ModThenAcquireRawAdcSamples125k(uint32_t delay_off, uint32_t period_0, uint32_t period_1, uint8_t *command);
void ReadTItag(void);
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc);

void AcquireTiType(void);
void AcquireRawBitsTI(void);
void SimulateTagLowFrequencyEx(int period, int gap, int ledcontrol, int numcycles);
void SimulateTagLowFrequency(int period, int gap, int ledcontrol);
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen);
void CmdHIDsimTAGEx(uint32_t hi, uint32_t lo, int ledcontrol, int numcycles);
void CmdHIDsimTAG(uint32_t hi, uint32_t lo, int ledcontrol);
void CmdFSKsimTAG(uint16_t arg1, uint16_t arg2, size_t size, uint8_t *BitStream);
void CmdASKsimTag(uint16_t arg1, uint16_t arg2, size_t size, uint8_t *BitStream);
void CmdPSKsimTag(uint16_t arg1, uint16_t arg2, size_t size, uint8_t *BitStream);
void CmdHIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol);
void CmdAWIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol); // Realtime demodulation mode for AWID26
void CmdEM410xdemod(int findone, uint32_t *high, uint64_t *low, int ledcontrol);
void CmdIOdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol);
void CopyIOtoT55x7(uint32_t hi, uint32_t lo); // Clone an ioProx card to T5557/T5567
void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT); // Clone an HID card to T5557/T5567
void CopyVikingtoT55xx(uint32_t block1, uint32_t block2, uint8_t Q5);
void WriteEM410x(uint32_t card, uint32_t id_hi, uint32_t id_lo);
void CopyIndala64toT55x7(uint32_t hi, uint32_t lo); // Clone Indala 64-bit tag by UID to T55x7
void CopyIndala224toT55x7(uint32_t uid1, uint32_t uid2, uint32_t uid3, uint32_t uid4, uint32_t uid5, uint32_t uid6, uint32_t uid7); // Clone Indala 224-bit tag by UID to T55x7
void T55xxResetRead(void);
void T55xxWriteBlock(uint32_t Data, uint8_t Block, uint32_t Pwd, uint8_t PwdMode);
void T55xxWriteBlockExt(uint32_t Data, uint8_t Block, uint32_t Pwd, uint8_t PwdMode);
void T55xxReadBlock(uint16_t arg0, uint8_t Block, uint32_t Pwd);
void T55xxWakeUp(uint32_t Pwd);
void TurnReadLFOn(uint32_t delay);
void EM4xReadWord(uint8_t addr, uint32_t pwd, uint8_t usepwd);
void EM4xWriteWord(uint32_t flag, uint32_t data, uint32_t pwd);
void Cotag(uint32_t arg0);

/// iso14443b.h
void SimulateIso14443bTag(uint32_t pupi);
void AcquireRawAdcSamplesIso14443b(uint32_t parameter);
void ReadSTMemoryIso14443b(uint8_t numofblocks);
void RAMFUNC SniffIso14443b(void);
void SendRawCommand14443B(uint32_t, uint32_t, uint8_t, uint8_t[]);
void SendRawCommand14443B_Ex(UsbCommand *c);
void ClearFpgaShiftingRegisters(void);

// iso14443a.h
void RAMFUNC SniffIso14443a(uint8_t param);
void SimulateIso14443aTag(int tagType, int flags, uint8_t *data);
void ReaderIso14443a(UsbCommand *c);

// Also used in iclass.c
//bool RAMFUNC LogTrace(const uint8_t *btBytes, uint16_t len, uint32_t timestamp_start, uint32_t timestamp_end, uint8_t *parity, bool readerToTag);
void GetParity(const uint8_t *pbtCmd, uint16_t len, uint8_t *parity);
void iso14a_set_trigger(bool enable);
// also used in emv
bool prepare_allocated_tag_modulation(tag_response_info_t * response_info);
int GetIso14443aCommandFromReader(uint8_t *received, uint8_t *parity, int *len);

// epa.h
void EPA_PACE_Collect_Nonce(UsbCommand * c);
void EPA_PACE_Replay(UsbCommand *c);

// mifarecmd.h
void MifareReadBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *data);
void MifareUReadBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareUC_Auth(uint8_t arg0, uint8_t *datain);
void MifareUReadCard(uint8_t arg0, uint16_t arg1, uint8_t arg2, uint8_t *datain);
void MifareReadSector(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
//void MifareUWriteBlockCompat(uint8_t arg0,uint8_t *datain);
void MifareUWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareNested(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareAcquireEncryptedNonces(uint32_t arg0, uint32_t arg1, uint32_t flags, uint8_t *datain);
void MifareAcquireNonces(uint32_t arg0, uint32_t arg1, uint32_t flags, uint8_t *datain);
void MifareChkKeys(uint16_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareChkKeys_fast(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void Mifare1ksim(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);
void MifareSetDbgLvl(uint16_t arg0);
void MifareEMemClr(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareEMemSet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareEMemGet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareCSetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);  // Work with "magic Chinese" card
void MifareCGetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);
void MifareCIdent();  // is "magic chinese" card?
void MifareSetMod(uint8_t mod, uint8_t *key);
void MifareUSetPwd(uint8_t arg0, uint8_t *datain);
void OnSuccessMagic();
void OnErrorMagic(uint8_t reason);

int32_t dist_nt(uint32_t nt1, uint32_t nt2);
void ReaderMifare(bool first_try, uint8_t block, uint8_t keytype );
//void RAMFUNC SniffMifare(uint8_t param);

//desfire
void Mifare_DES_Auth1(uint8_t arg0,uint8_t *datain);
void Mifare_DES_Auth2(uint32_t arg0, uint8_t *datain);					   

// mifaredesfire.h
bool InitDesfireCard();
void MifareSendCommand(uint8_t arg0,uint8_t arg1, uint8_t *datain);
void MifareDesfireGetInformation();
void MifareDES_Auth1(uint8_t arg0,uint8_t arg1,uint8_t arg2, uint8_t *datain);
void ReaderMifareDES(uint32_t param, uint32_t param2, uint8_t * datain);
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout);
size_t CreateAPDU( uint8_t *datain, size_t len, uint8_t *dataout);
void OnSuccess();
void OnError(uint8_t reason);

// desfire_crypto.h
void *mifare_cryto_preprocess_data (desfiretag_t tag, void *data, size_t *nbytes, size_t offset, int communication_settings);
void *mifare_cryto_postprocess_data (desfiretag_t tag, void *data, size_t *nbytes, int communication_settings);
void mifare_cypher_single_block (desfirekey_t  key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size);
void mifare_cypher_blocks_chained (desfiretag_t tag, desfirekey_t key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation);
size_t key_block_size (const desfirekey_t  key);
size_t padded_data_length (const size_t nbytes, const size_t block_size);
size_t maced_data_length (const desfirekey_t  key, const size_t nbytes);
size_t enciphered_data_length (const desfiretag_t tag, const size_t nbytes, int communication_settings);
void cmac_generate_subkeys (desfirekey_t key);
void cmac (const desfirekey_t  key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac);

// iso15693.h
void RecordRawAdcSamplesIso15693(void);
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(uint32_t parameter);	// Simulate an ISO15693 reader - greg
void SimTagIso15693(uint32_t parameter, uint8_t *uid);	// simulate an ISO15693 tag - greg
void BruteforceIso15693Afi(uint32_t speed); // find an AFI of a tag - atrox
void DirectTag15693Command(uint32_t datalen,uint32_t speed, uint32_t recv, uint8_t *data); // send arbitrary commands from CLI - atrox 
void Iso15693InitReader(void);

// iclass.h
void RAMFUNC SniffIClass(void);
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void ReaderIClass(uint8_t arg0);
void ReaderIClass_Replay(uint8_t arg0,uint8_t *MAC);
void iClass_Authentication(uint8_t *MAC);
void iClass_Authentication_fast(uint64_t arg0, uint64_t arg1, uint8_t *datain);
void iClass_WriteBlock(uint8_t blockNo, uint8_t *data);
void iClass_ReadBlk(uint8_t blockNo);
bool iClass_ReadBlock(uint8_t blockNo, uint8_t *data, uint8_t datalen);
void iClass_Dump(uint8_t blockno, uint8_t numblks);
void iClass_Clone(uint8_t startblock, uint8_t endblock, uint8_t *data);
void iClass_ReadCheck(uint8_t blockNo, uint8_t keyType);

// hitag2.h
void SnoopHitag(uint32_t type);
void SimulateHitagTag(bool tag_mem_supplied, byte_t* data);
void ReaderHitag(hitag_function htf, hitag_data* htd);
void WriterHitag(hitag_function htf, hitag_data* htd, int page);

//hitagS.h
void SimulateHitagSTag(bool tag_mem_supplied, byte_t* data);
void ReadHitagS(hitag_function htf, hitag_data* htd);
void WritePageHitagS(hitag_function htf, hitag_data* htd,int page);
void check_challenges(bool file_given, byte_t* data);

// cmd.h
bool cmd_receive(UsbCommand* cmd);
bool cmd_send(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void* data, size_t len);

// util.h
void HfSnoop(int , int);

//felica.c
extern void felica_sendraw(UsbCommand *c);
extern void felica_sniff(uint32_t samples, uint32_t triggers);
extern void felica_sim_lite(uint64_t uid);
extern void felica_dump_lite_s();


#ifdef __cplusplus
}
#endif

#endif
