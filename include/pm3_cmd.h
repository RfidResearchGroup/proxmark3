//-----------------------------------------------------------------------------
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions for all the types of commands that may be sent over USB; our
// own protocol.
//-----------------------------------------------------------------------------

#ifndef __PM3_CMD_H
#define __PM3_CMD_H

#include "common.h"

// Use it e.g. when using slow links such as BT
#define USART_SLOW_LINK

#define PM3_CMD_DATA_SIZE 512
#define PM3_CMD_DATA_SIZE_MIX ( PM3_CMD_DATA_SIZE - 3 * sizeof(uint64_t) )

typedef struct {
    uint64_t cmd;
    uint64_t arg[3];
    union {
        uint8_t  asBytes[PM3_CMD_DATA_SIZE];
        uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
    } d;
} PACKED PacketCommandOLD;

typedef struct {
    uint32_t magic;
    uint16_t length : 15;  // length of the variable part, 0 if none.
    bool ng : 1;
    uint16_t cmd;
} PACKED PacketCommandNGPreamble;

#define COMMANDNG_PREAMBLE_MAGIC  0x61334d50 // PM3a
#define COMMANDNG_POSTAMBLE_MAGIC 0x3361     // a3

typedef struct {
    uint16_t crc;
} PACKED PacketCommandNGPostamble;

// For internal usage
typedef struct {
    uint16_t cmd;
    uint16_t length;
    uint32_t magic;      //  NG
    uint16_t crc;        //  NG
    uint64_t oldarg[3];  //  OLD
    union {
        uint8_t  asBytes[PM3_CMD_DATA_SIZE];
        uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
    } data;
    bool ng;             // does it store NG data or OLD data?
} PacketCommandNG;

// For reception and CRC check
typedef struct {
    PacketCommandNGPreamble pre;
    uint8_t data[PM3_CMD_DATA_SIZE];
    PacketCommandNGPostamble foopost; // Probably not at that offset!
} PACKED PacketCommandNGRaw;

typedef struct {
    uint64_t cmd;
    uint64_t arg[3];
    union {
        uint8_t  asBytes[PM3_CMD_DATA_SIZE];
        uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
    } d;
} PACKED PacketResponseOLD;

typedef struct {
    uint32_t magic;
    uint16_t length : 15;  // length of the variable part, 0 if none.
    bool ng : 1;
    int16_t  status;
    uint16_t cmd;
} PACKED PacketResponseNGPreamble;

#define RESPONSENG_PREAMBLE_MAGIC  0x62334d50 // PM3b
#define RESPONSENG_POSTAMBLE_MAGIC 0x3362     // b3

typedef struct {
    uint16_t crc;
} PACKED PacketResponseNGPostamble;

// For internal usage
typedef struct {
    uint16_t cmd;
    uint16_t length;
    uint32_t magic;      //  NG
    int16_t  status;     //  NG
    uint16_t crc;        //  NG
    uint64_t oldarg[3];  //  OLD
    union {
        uint8_t  asBytes[PM3_CMD_DATA_SIZE];
        uint32_t asDwords[PM3_CMD_DATA_SIZE / 4];
    } data;
    bool ng;             // does it store NG data or OLD data?
} PacketResponseNG;

// For reception and CRC check
typedef struct {
    PacketResponseNGPreamble pre;
    uint8_t data[PM3_CMD_DATA_SIZE];
    PacketResponseNGPostamble foopost; // Probably not at that offset!
} PACKED PacketResponseNGRaw;

// A struct used to send sample-configs over USB
typedef struct {
    int8_t decimation;
    int8_t bits_per_sample;
    int8_t averaging;
    int16_t divisor;
    int16_t trigger_threshold;
    int32_t samples_to_skip;
    bool verbose;
} PACKED sample_config;
/*
typedef struct {
    uint16_t start_gap;
    uint16_t write_gap;
    uint16_t write_0;
    uint16_t write_1;
    uint16_t read_gap;
} t55xx_config;
*/

// Extended to support 1 of 4 timing
typedef struct  {
    uint16_t start_gap;
    uint16_t write_gap;
    uint16_t write_0;
    uint16_t write_1;
    uint16_t read_gap;
    uint16_t write_2;
    uint16_t write_3;
} t55xx_config_t;

// This setup will allow for the 4 downlink modes "m" as well as other items if needed.
// Given the one struct we can then read/write to flash/client in one go.
typedef struct {
    t55xx_config_t m[4]; // mode
} t55xx_configurations_t;

/*typedef struct  {
    uint16_t start_gap [4];
    uint16_t write_gap [4];
    uint16_t write_0   [4];
    uint16_t write_1   [4];
    uint16_t write_2   [4];
    uint16_t write_3   [4];
    uint16_t read_gap  [4];
} t55xx_config;
*/
typedef struct {
    uint8_t version;
    uint32_t baudrate;
    bool via_fpc                       : 1;
    bool via_usb                       : 1;
    // rdv4
    bool compiled_with_flash           : 1;
    bool compiled_with_smartcard       : 1;
    bool compiled_with_fpc_usart       : 1;
    bool compiled_with_fpc_usart_dev   : 1;
    bool compiled_with_fpc_usart_host  : 1;
    // lf
    bool compiled_with_lf              : 1;
    bool compiled_with_hitag           : 1;
    // hf
    bool compiled_with_hfsniff         : 1;
    bool compiled_with_hfplot          : 1;
    bool compiled_with_iso14443a       : 1;
    bool compiled_with_iso14443b       : 1;
    bool compiled_with_iso15693        : 1;
    bool compiled_with_felica          : 1;
    bool compiled_with_legicrf         : 1;
    bool compiled_with_iclass          : 1;
    bool compiled_with_nfcbarcode      : 1;
    // misc
    bool compiled_with_lcd             : 1;

    // rdv4
    bool hw_available_flash            : 1;
    bool hw_available_smartcard        : 1;
} PACKED capabilities_t;
#define CAPABILITIES_VERSION 4
extern capabilities_t pm3_capabilities;

// For CMD_LF_T55XX_WRITEBL
typedef struct {
    uint32_t data;
    uint32_t pwd;
    uint8_t blockno;
    uint8_t flags;
} PACKED t55xx_write_block_t;

typedef struct {
    uint8_t data[128];
    uint8_t bitlen;
    uint32_t time;
} PACKED t55xx_test_block_t;

// For CMD_LF_HID_SIMULATE (FSK)
typedef struct {
    uint32_t hi2;
    uint32_t hi;
    uint32_t lo;
    uint8_t longFMT;
} PACKED lf_hidsim_t;

// For CMD_LF_FSK_SIMULATE (FSK)
typedef struct {
    uint8_t fchigh;
    uint8_t fclow;
    uint8_t separator;
    uint8_t clock;
    uint8_t data[];
} PACKED lf_fsksim_t;

// For CMD_LF_ASK_SIMULATE (ASK)
typedef struct {
    uint8_t encoding;
    uint8_t invert;
    uint8_t separator;
    uint8_t clock;
    uint8_t data[];
} PACKED lf_asksim_t;

// For CMD_LF_PSK_SIMULATE (PSK)
typedef struct {
    uint8_t carrier;
    uint8_t invert;
    uint8_t clock;
    uint8_t data[];
} PACKED lf_psksim_t;

// For CMD_LF_NRZ_SIMULATE (NRZ)
typedef struct {
    uint8_t invert;
    uint8_t separator;
    uint8_t clock;
    uint8_t data[];
} PACKED lf_nrzsim_t;

typedef struct {
    uint8_t blockno;
    uint8_t keytype;
    uint8_t key[6];
} PACKED mf_readblock_t;

typedef struct {
    uint8_t sectorcnt;
    uint8_t keytype;
} PACKED mfc_eload_t;

typedef struct {
    uint8_t status;
    uint8_t CSN[8];
    uint8_t CONFIG[8];
    uint8_t CC[8];
    uint8_t AIA[8];
} PACKED iclass_reader_t;

typedef struct {
    const char *desc;
    const char *value;
} PACKED ecdsa_publickey_t;

// For the bootloader
#define CMD_DEVICE_INFO                                                   0x0000
//#define CMD_SETUP_WRITE                                                   0x0001
#define CMD_FINISH_WRITE                                                  0x0003
#define CMD_HARDWARE_RESET                                                0x0004
#define CMD_START_FLASH                                                   0x0005
#define CMD_CHIP_INFO                                                     0x0006
#define CMD_BL_VERSION                                                    0x0007
#define CMD_NACK                                                          0x00fe
#define CMD_ACK                                                           0x00ff

// For general mucking around
#define CMD_DEBUG_PRINT_STRING                                            0x0100
#define CMD_DEBUG_PRINT_INTEGERS                                          0x0101
#define CMD_DEBUG_PRINT_BYTES                                             0x0102
#define CMD_LCD_RESET                                                     0x0103
#define CMD_LCD                                                           0x0104
#define CMD_BUFF_CLEAR                                                    0x0105
#define CMD_READ_MEM                                                      0x0106
#define CMD_VERSION                                                       0x0107
#define CMD_STATUS                                                        0x0108
#define CMD_PING                                                          0x0109
#define CMD_DOWNLOAD_EML_BIGBUF                                           0x0110
#define CMD_DOWNLOADED_EML_BIGBUF                                         0x0111
#define CMD_CAPABILITIES                                                  0x0112
#define CMD_QUIT_SESSION                                                  0x0113
#define CMD_SET_DBGMODE                                                   0x0114
#define CMD_STANDALONE                                                    0x0115
#define CMD_WTX                                                           0x0116
#define CMD_TIA                                                           0x0117
#define CMD_BREAK_LOOP                                                    0x0118

// RDV40, Flash memory operations
#define CMD_FLASHMEM_WRITE                                                0x0121
#define CMD_FLASHMEM_WIPE                                                 0x0122
#define CMD_FLASHMEM_DOWNLOAD                                             0x0123
#define CMD_FLASHMEM_DOWNLOADED                                           0x0124
#define CMD_FLASHMEM_INFO                                                 0x0125
#define CMD_FLASHMEM_SET_SPIBAUDRATE                                      0x0126

// RDV40, High level flashmem SPIFFS Manipulation
// ALL function will have a lazy or Safe version
// that will be handled as argument of safety level [0..2] respectiveley normal / lazy / safe
// However as how design is, MOUNT and UNMOUNT only need/have lazy as safest level so a safe level will still execute a lazy version
// see spiffs.c for more about the normal/lazy/safety information)
#define CMD_SPIFFS_MOUNT                                                  0x0130
#define CMD_SPIFFS_UNMOUNT                                                0x0131
#define CMD_SPIFFS_WRITE                                                  0x0132
// We take +0x1000 when having a variant of similar function (todo : make it an argument!)
#define CMD_SPIFFS_APPEND                                                 0x1132

#define CMD_SPIFFS_READ                                                   0x0133
//We use no open/close instruvtion, as they are handled internally.
#define CMD_SPIFFS_REMOVE                                                 0x0134
#define CMD_SPIFFS_RM                                                     CMD_SPIFFS_REMOVE
#define CMD_SPIFFS_RENAME                                                 0x0135
#define CMD_SPIFFS_MV                                                     CMD_SPIFFS_RENAME
#define CMD_SPIFFS_COPY                                                   0x0136
#define CMD_SPIFFS_CP                                                     CMD_SPIFFS_COPY
#define CMD_SPIFFS_STAT                                                   0x0137
#define CMD_SPIFFS_FSTAT                                                  0x0138
#define CMD_SPIFFS_INFO                                                   0x0139
#define CMD_SPIFFS_FORMAT                                                 CMD_FLASHMEM_WIPE
// This take a +0x2000 as they are high level helper and special functions
// As the others, they may have safety level argument if it makkes sense
#define CMD_SPIFFS_PRINT_TREE                                             0x2130
#define CMD_SPIFFS_GET_TREE                                               0x2131
#define CMD_SPIFFS_TEST                                                   0x2132
#define CMD_SPIFFS_PRINT_FSINFO                                           0x2133
#define CMD_SPIFFS_DOWNLOAD                                               0x2134
#define CMD_SPIFFS_DOWNLOADED                                             0x2135
#define CMD_SPIFFS_CHECK                                                  0x3000
// more ?


// RDV40,  Smart card operations
#define CMD_SMART_RAW                                                     0x0140
#define CMD_SMART_UPGRADE                                                 0x0141
#define CMD_SMART_UPLOAD                                                  0x0142
#define CMD_SMART_ATR                                                     0x0143
#define CMD_SMART_SETBAUD                                                 0x0144
#define CMD_SMART_SETCLOCK                                                0x0145

// RDV40,  FPC USART
#define CMD_USART_RX                                                      0x0160
#define CMD_USART_TX                                                      0x0161
#define CMD_USART_TXRX                                                    0x0162
#define CMD_USART_CONFIG                                                  0x0163

// For low-frequency tags
#define CMD_LF_TI_READ                                                    0x0202
#define CMD_LF_TI_WRITE                                                   0x0203
#define CMD_LF_ACQ_RAW_ADC                                                0x0205
#define CMD_LF_MOD_THEN_ACQ_RAW_ADC                                       0x0206
#define CMD_DOWNLOAD_BIGBUF                                               0x0207
#define CMD_DOWNLOADED_BIGBUF                                             0x0208
#define CMD_LF_UPLOAD_SIM_SAMPLES                                         0x0209
#define CMD_LF_SIMULATE                                                   0x020A
#define CMD_LF_HID_DEMOD                                                  0x020B
#define CMD_LF_HID_SIMULATE                                               0x020C
#define CMD_LF_SET_DIVISOR                                                0x020D
#define CMD_LF_SIMULATE_BIDIR                                             0x020E
#define CMD_SET_ADC_MUX                                                   0x020F
#define CMD_LF_HID_CLONE                                                  0x0210
#define CMD_LF_EM410X_WRITE                                               0x0211
#define CMD_LF_T55XX_READBL                                               0x0214
#define CMD_LF_T55XX_WRITEBL                                              0x0215
#define CMD_LF_T55XX_RESET_READ                                           0x0216
#define CMD_LF_PCF7931_READ                                               0x0217
#define CMD_LF_PCF7931_WRITE                                              0x0223
#define CMD_LF_EM4X_READWORD                                              0x0218
#define CMD_LF_EM4X_WRITEWORD                                             0x0219
#define CMD_LF_IO_DEMOD                                                   0x021A
#define CMD_LF_EM410X_DEMOD                                               0x021C
// Sampling configuration for LF reader/sniffer
#define CMD_LF_SAMPLING_SET_CONFIG                                        0x021D
#define CMD_LF_FSK_SIMULATE                                               0x021E
#define CMD_LF_ASK_SIMULATE                                               0x021F
#define CMD_LF_PSK_SIMULATE                                               0x0220
#define CMD_LF_NRZ_SIMULATE                                               0x0232
#define CMD_LF_AWID_DEMOD                                                 0x0221
#define CMD_LF_VIKING_CLONE                                               0x0222
#define CMD_LF_T55XX_WAKEUP                                               0x0224
#define CMD_LF_COTAG_READ                                                 0x0225
#define CMD_LF_T55XX_SET_CONFIG                                           0x0226
#define CMD_LF_SAMPLING_PRINT_CONFIG                                      0x0227
#define CMD_LF_SAMPLING_GET_CONFIG                                        0x0228

#define CMD_LF_T55XX_CHK_PWDS                                             0x0230
#define CMD_LF_T55XX_DANGERRAW                                            0x0231

/* CMD_SET_ADC_MUX: ext1 is 0 for lopkd, 1 for loraw, 2 for hipkd, 3 for hiraw */

// For the 13.56 MHz tags
#define CMD_HF_ISO15693_ACQ_RAW_ADC                                       0x0300
#define CMD_HF_SRI_READ                                                   0x0303
#define CMD_HF_ISO14443B_COMMAND                                          0x0305
#define CMD_HF_ISO15693_READER                                            0x0310
#define CMD_HF_ISO15693_SIMULATE                                          0x0311
#define CMD_HF_ISO15693_RAWADC                                            0x0312
#define CMD_HF_ISO15693_COMMAND                                           0x0313
#define CMD_HF_ISO15693_FINDAFI                                           0x0315
#define CMD_LF_SNIFF_RAW_ADC                                              0x0317

// For Hitag2 transponders
#define CMD_LF_HITAG_SNIFF                                                0x0370
#define CMD_LF_HITAG_SIMULATE                                             0x0371
#define CMD_LF_HITAG_READER                                               0x0372

// For HitagS
#define CMD_LF_HITAGS_TEST_TRACES                                         0x0367
#define CMD_LF_HITAGS_SIMULATE                                            0x0368
#define CMD_LF_HITAGS_READ                                                0x0373
#define CMD_LF_HITAGS_WRITE                                               0x0375

#define CMD_HF_ISO14443A_ANTIFUZZ                                         0x0380
#define CMD_HF_ISO14443B_SIMULATE                                         0x0381
#define CMD_HF_ISO14443B_SNIFF                                            0x0382

#define CMD_HF_ISO14443A_SNIFF                                            0x0383
#define CMD_HF_ISO14443A_SIMULATE                                         0x0384

#define CMD_HF_ISO14443A_READER                                           0x0385

#define CMD_HF_LEGIC_SIMULATE                                             0x0387
#define CMD_HF_LEGIC_READER                                               0x0388
#define CMD_HF_LEGIC_WRITER                                               0x0389

#define CMD_HF_EPA_COLLECT_NONCE                                          0x038A
#define CMD_HF_EPA_REPLAY                                                 0x038B

#define CMD_HF_LEGIC_INFO                                                 0x03BC
#define CMD_HF_LEGIC_ESET                                                 0x03BD

#define CMD_HF_ICLASS_READCHECK                                           0x038F
#define CMD_HF_ICLASS_CLONE                                               0x0390
#define CMD_HF_ICLASS_DUMP                                                0x0391
#define CMD_HF_ICLASS_SNIFF                                               0x0392
#define CMD_HF_ICLASS_SIMULATE                                            0x0393
#define CMD_HF_ICLASS_READER                                              0x0394
#define CMD_HF_ICLASS_REPLAY                                              0x0395
#define CMD_HF_ICLASS_READBL                                              0x0396
#define CMD_HF_ICLASS_WRITEBL                                             0x0397
#define CMD_HF_ICLASS_EML_MEMSET                                          0x0398
#define CMD_HF_ICLASS_AUTH                                                0x0399
#define CMD_HF_ICLASS_CHKKEYS                                             0x039A

// For ISO1092 / FeliCa
#define CMD_HF_FELICA_SIMULATE                                            0x03A0
#define CMD_HF_FELICA_SNIFF                                               0x03A1
#define CMD_HF_FELICA_COMMAND                                             0x03A2
//temp
#define CMD_HF_FELICALITE_DUMP                                            0x03AA
#define CMD_HF_FELICALITE_SIMULATE                                        0x03AB

// For measurements of the antenna tuning
#define CMD_MEASURE_ANTENNA_TUNING                                        0x0400
#define CMD_MEASURE_ANTENNA_TUNING_HF                                     0x0401
#define CMD_MEASURE_ANTENNA_TUNING_LF                                     0x0402
#define CMD_LISTEN_READER_FIELD                                           0x0420
#define CMD_HF_DROPFIELD                                                  0x0430

// For direct FPGA control
#define CMD_FPGA_MAJOR_MODE_OFF                                           0x0500

// For mifare commands
#define CMD_HF_MIFARE_EML_MEMCLR                                          0x0601
#define CMD_HF_MIFARE_EML_MEMSET                                          0x0602
#define CMD_HF_MIFARE_EML_MEMGET                                          0x0603
#define CMD_HF_MIFARE_EML_LOAD                                            0x0604

// magic chinese card commands
#define CMD_HF_MIFARE_CSETBL                                              0x0605
#define CMD_HF_MIFARE_CGETBL                                              0x0606
#define CMD_HF_MIFARE_CIDENT                                              0x0607

#define CMD_HF_MIFARE_SIMULATE                                            0x0610

#define CMD_HF_MIFARE_READER                                              0x0611
#define CMD_HF_MIFARE_NESTED                                              0x0612
#define CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES                                0x0613
#define CMD_HF_MIFARE_ACQ_NONCES                                          0x0614
#define CMD_HF_MIFARE_STATIC_NESTED                                       0x0615

#define CMD_HF_MIFARE_READBL                                              0x0620
#define CMD_HF_MIFAREU_READBL                                             0x0720
#define CMD_HF_MIFARE_READSC                                              0x0621
#define CMD_HF_MIFAREU_READCARD                                           0x0721
#define CMD_HF_MIFARE_WRITEBL                                             0x0622
#define CMD_HF_MIFAREU_WRITEBL                                            0x0722

#define CMD_HF_MIFARE_CHKKEYS                                             0x0623
#define CMD_HF_MIFARE_SETMOD                                              0x0624
#define CMD_HF_MIFARE_CHKKEYS_FAST                                        0x0625
#define CMD_HF_MIFARE_CHKKEYS_FILE                                        0x0626

#define CMD_HF_MIFARE_SNIFF                                               0x0630
#define CMD_HF_MIFARE_MFKEY                                               0x0631
#define CMD_HF_MIFARE_PERSONALIZE_UID                                     0x0632

//ultralightC
#define CMD_HF_MIFAREUC_AUTH                                              0x0724
//0x0725 and 0x0726 no longer used
#define CMD_HF_MIFAREUC_SETPWD                                            0x0727

// mifare desfire
#define CMD_HF_DESFIRE_READBL                                             0x0728
#define CMD_HF_DESFIRE_WRITEBL                                            0x0729
#define CMD_HF_DESFIRE_AUTH1                                              0x072a
#define CMD_HF_DESFIRE_AUTH2                                              0x072b
#define CMD_HF_DESFIRE_READER                                             0x072c
#define CMD_HF_DESFIRE_INFO                                               0x072d
#define CMD_HF_DESFIRE_COMMAND                                            0x072e

#define CMD_HF_MIFARE_NACK_DETECT                                         0x0730
#define CMD_HF_MIFARE_STATIC_NONCE                                        0x0731

// MFU OTP TearOff
#define CMD_HF_MFU_OTP_TEAROFF                                            0x0740

#define CMD_HF_SNIFF                                                      0x0800
#define CMD_HF_PLOT                                                       0x0801

// Fpga plot download
#define CMD_FPGAMEM_DOWNLOAD                                              0x0802
#define CMD_FPGAMEM_DOWNLOADED                                            0x0803

// For ThinFilm Kovio
#define CMD_HF_THINFILM_READ                                              0x0810
#define CMD_HF_THINFILM_SIMULATE                                          0x0811

#define CMD_UNKNOWN                                                       0xFFFF

//Mifare simulation flags
#define FLAG_INTERACTIVE        0x01
#define FLAG_4B_UID_IN_DATA     0x02
#define FLAG_7B_UID_IN_DATA     0x04
#define FLAG_10B_UID_IN_DATA    0x08
#define FLAG_UID_IN_EMUL        0x10
#define FLAG_NR_AR_ATTACK       0x20
#define FLAG_MF_MINI            0x80
#define FLAG_MF_1K              0x100
#define FLAG_MF_2K              0x200
#define FLAG_MF_4K              0x400
#define FLAG_FORCED_ATQA        0x800
#define FLAG_FORCED_SAK         0x1000

//Iclass reader flags
#define FLAG_ICLASS_READER_ONLY_ONCE   0x01
#define FLAG_ICLASS_READER_CC          0x02
#define FLAG_ICLASS_READER_CSN         0x04
#define FLAG_ICLASS_READER_CONF        0x08
#define FLAG_ICLASS_READER_AIA         0x10
#define FLAG_ICLASS_READER_ONE_TRY     0x20
#define FLAG_ICLASS_READER_CEDITKEY    0x40

// Dbprintf flags
#define FLAG_RAWPRINT    0x00
#define FLAG_LOG         0x01
#define FLAG_NEWLINE     0x02
#define FLAG_INPLACE     0x04
#define FLAG_ANSI        0x08

// Error codes                          Usages:

// Success, transfer nonces            pm3:        Sending nonces back to client
#define PM3_SNONCES             1
// Success (no error)
#define PM3_SUCCESS             0

// Undefined error
#define PM3_EUNDEF             -1
// Invalid argument(s)                  client:     user input parsing
#define PM3_EINVARG            -2
// Operation not supported by device    client/pm3: probably only on pm3 once client becomes universal
#define PM3_EDEVNOTSUPP        -3
// Operation timed out                  client:     no response in time from pm3
#define PM3_ETIMEOUT           -4
// Operation aborted (by user)          client/pm3: kbd/button pressed
#define PM3_EOPABORTED         -5
// Not (yet) implemented                client/pm3: TBD placeholder
#define PM3_ENOTIMPL           -6
// Error while RF transmission          client/pm3: fail between pm3 & card
#define PM3_ERFTRANS           -7
// Input / output error                 pm3:        error in client frame reception
#define PM3_EIO                -8
// Buffer overflow                      client/pm3: specified buffer too large for the operation
#define PM3_EOVFLOW            -9
// Software error                       client/pm3: e.g. error in parsing some data
#define PM3_ESOFT             -10
// Flash error                          client/pm3: error in RDV4 Flash operation
#define PM3_EFLASH            -11
// Memory allocation error              client:     error in memory allocation (maybe also for pm3 BigBuff?)
#define PM3_EMALLOC           -12
// File error                           client:     error related to file access on host
#define PM3_EFILE             -13
// Generic TTY error
#define PM3_ENOTTY            -14
// Initialization error                 pm3:        error related to trying to initalize the pm3 / fpga for different operations
#define PM3_EINIT             -15
// Expected a different answer error    client/pm3: error when expecting one answer and got another one
#define PM3_EWRONGANSVER      -16
// Memory out-of-bounds error           client/pm3: error when a read/write is outside the expected array
#define PM3_EOUTOFBOUND       -17
// exchange with card error             client/pm3: error when cant get answer from card or got an incorrect answer
#define PM3_ECARDEXCHANGE     -18

// Failed to create APDU,
#define PM3_EAPDU_ENCODEFAIL  -19
// APDU responded with a failure code
#define PM3_EAPDU_FAIL        -20
// No data                              pm3:        no data available, no host frame available (not really an error)
#define PM3_ENODATA           -98
// Quit program                         client:     reserved, order to quit the program
#define PM3_EFATAL            -99

// LF
#define LF_FREQ2DIV(f) ((int)(((12000.0 + (f)/2.0)/(f))-1))
#define LF_DIVISOR_125 LF_FREQ2DIV(125)
#define LF_DIVISOR_134 LF_FREQ2DIV(134.2)
#define LF_DIV2FREQ(d) (12000.0/((d)+1))

// Receiving from USART need more than 30ms as we used on USB
// else we get errors about partial packet reception
// FTDI   9600 hw status        -> we need 20ms
// FTDI 115200 hw status        -> we need 50ms
// FTDI 460800 hw status        -> we need 30ms
// BT   115200 hf mf fchk 1 dic -> we need 140ms
// all zero's configure: no timeout for read/write used.
// took settings from libnfc/buses/uart.c

// uart_windows.c & uart_posix.c
# define UART_FPC_CLIENT_RX_TIMEOUT_MS  200
# define UART_USB_CLIENT_RX_TIMEOUT_MS  20
# define UART_TCP_CLIENT_RX_TIMEOUT_MS  500


// CMD_DEVICE_INFO response packet has flags in arg[0], flag definitions:
/* Whether a bootloader that understands the common_area is present */
#define DEVICE_INFO_FLAG_BOOTROM_PRESENT             (1<<0)

/* Whether a osimage that understands the common_area is present */
#define DEVICE_INFO_FLAG_OSIMAGE_PRESENT             (1<<1)

/* Set if the bootloader is currently executing */
#define DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM        (1<<2)

/* Set if the OS is currently executing */
#define DEVICE_INFO_FLAG_CURRENT_MODE_OS             (1<<3)

/* Set if this device understands the extend start flash command */
#define DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH     (1<<4)

/* Set if this device understands the chip info command */
#define DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO       (1<<5)

/* Set if this device understands the version command */
#define DEVICE_INFO_FLAG_UNDERSTANDS_VERSION         (1<<6)

#define BL_VERSION_MAJOR(version) ((uint32_t)(version) >> 22)
#define BL_VERSION_MINOR(version) (((uint32_t)(version) >> 12) & 0x3ff)
#define BL_VERSION_PATCH(version) ((uint32_t)(version) & 0xfff)
#define BL_MAKE_VERSION(major, minor, patch) (((major) << 22) | ((minor) << 12) | (patch))
// Some boundaries to distinguish valid versions from corrupted info
#define BL_VERSION_FIRST_MAJOR    1
#define BL_VERSION_LAST_MAJOR     99
#define BL_VERSION_INVALID  0
// Different versions here. Each version should increase the numbers
#define BL_VERSION_1_0_0    BL_MAKE_VERSION(1, 0, 0)


/* CMD_START_FLASH may have three arguments: start of area to flash,
   end of area to flash, optional magic.
   The bootrom will not allow to overwrite itself unless this magic
   is given as third parameter */

#define START_FLASH_MAGIC 0x54494f44 // 'DOIT'

#endif
