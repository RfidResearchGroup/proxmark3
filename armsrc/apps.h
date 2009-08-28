//-----------------------------------------------------------------------------
// Definitions internal to the app source.
// Jonathan Westhues, Aug 2005
// Added ISO14443-A support by Gerhard de Koning Gans, April 2008
//-----------------------------------------------------------------------------

#ifndef __APPS_H
#define __APPS_H

// The large multi-purpose buffer, typically used to hold A/D samples,
// maybe processed in some way.
DWORD BigBuf[12000];

/// appmain.h
void ReadMem(int addr);
void AppMain(void);
void SamyRun(void);
void DbpIntegers(int a, int b, int c);
void DbpString(char *str);
void ToSendStuffBit(int b);
void ToSendReset(void);
void ListenReaderField(int limit);
void AcquireRawAdcSamples125k(BOOL at134khz);
void DoAcquisition125k(BOOL at134khz);
extern int ToSendMax;
extern BYTE ToSend[];
extern DWORD BigBuf[];

/// fpga.h
void FpgaSendCommand(WORD cmd, WORD v);
void FpgaWriteConfWord(BYTE v);
void FpgaDownloadAndGo(void);
void FpgaGatherVersion(char *dst, int len);
void FpgaSetupSsc(void);
void SetupSpi(int mode);
void FpgaSetupSscDma(BYTE *buf, int len);
void SetAdcMuxFor(int whichGpio);

// Definitions for the FPGA commands.
#define FPGA_CMD_SET_CONFREG								(1<<12)
#define FPGA_CMD_SET_DIVISOR								(2<<12)
// Definitions for the FPGA configuration word.
#define FPGA_MAJOR_MODE_LF_READER						(0<<5)
#define FPGA_MAJOR_MODE_LF_SIMULATOR				(1<<5)
#define FPGA_MAJOR_MODE_HF_READER_TX				(2<<5)
#define FPGA_MAJOR_MODE_HF_READER_RX_XCORR	(3<<5)
#define FPGA_MAJOR_MODE_HF_SIMULATOR				(4<<5)
#define FPGA_MAJOR_MODE_HF_ISO14443A				(5<<5)
#define FPGA_MAJOR_MODE_LF_PASSTHRU					(6<<5)
#define FPGA_MAJOR_MODE_OFF									(7<<5)
// Options for the HF reader, tx to tag
#define FPGA_HF_READER_TX_SHALLOW_MOD				(1<<0)
// Options for the HF reader, correlating against rx from tag
#define FPGA_HF_READER_RX_XCORR_848_KHZ			(1<<0)
#define FPGA_HF_READER_RX_XCORR_SNOOP				(1<<1)
// Options for the HF simulated tag, how to modulate
#define FPGA_HF_SIMULATOR_NO_MODULATION			(0<<0)
#define FPGA_HF_SIMULATOR_MODULATE_BPSK			(1<<0)
// Options for ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER						(0<<0)
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN			(1<<0)
#define FPGA_HF_ISO14443A_TAGSIM_MOD				(2<<0)
#define FPGA_HF_ISO14443A_READER_LISTEN			(3<<0)
#define FPGA_HF_ISO14443A_READER_MOD				(4<<0)

/// lfops.h
void AcquireRawAdcSamples125k(BOOL at134khz);
void DoAcquisition125k(BOOL at134khz);
void ModThenAcquireRawAdcSamples125k(int delay_off,int period_0,int period_1,BYTE *command);
void ReadTItag();
void WriteTItag(DWORD idhi, DWORD idlo, WORD crc);
void AcquireTiType(void);
void AcquireRawBitsTI(void);
void SimulateTagLowFrequency(int period, int ledcontrol);
void CmdHIDsimTAG(int hi, int lo, int ledcontrol);
void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol);
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen);

/// iso14443.h
void SimulateIso14443Tag(void);
void AcquireRawAdcSamplesIso14443(DWORD parameter);
void ReadSRI512Iso14443(DWORD parameter);
void SnoopIso14443(void);

/// iso14443a.h
void SnoopIso14443a(void);
void SimulateIso14443aTag(int tagType, int TagUid);	// ## simulate iso14443a tag
void ReaderIso14443a(DWORD parameter);

/// iso15693.h
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(DWORD parameter);	// Simulate an ISO15693 reader - greg
void SimTagIso15693(DWORD parameter);	// simulate an ISO15693 tag - greg

/// util.h
#define LED_RED 1
#define LED_ORANGE 2
#define LED_GREEN 4
#define LED_RED2 8
#define BUTTON_HOLD 1
#define BUTTON_NO_CLICK 0
#define BUTTON_SINGLE_CLICK -1
#define BUTTON_DOUBLE_CLICK -2
#define BUTTON_ERROR -99
int strlen(char *str);
void *memcpy(void *dest, const void *src, int len);
void *memset(void *dest, int c, int len);
int memcmp(const void *av, const void *bv, int len);
char *strncat(char *dest, const char *src, unsigned int n);
void SpinDelay(int ms);
void SpinDelayUs(int us);
void LED(int led, int ms);
void LEDsoff();
int BUTTON_CLICKED(int ms);
int BUTTON_HELD(int ms);
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_information);

#endif
