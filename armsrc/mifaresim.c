//-----------------------------------------------------------------------------
// Merlok - June 2011, 2012
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Mifare Classic Card Simulation
//-----------------------------------------------------------------------------

// Verbose Mode:
// MF_DBG_NONE          0
// MF_DBG_ERROR         1
// MF_DBG_ALL           2
// MF_DBG_EXTENDED      4
//
//  /!\ Printing Debug message is disrupting emulation, 
//  Only use with caution during debugging 


#include "iso14443a.h"
#include "mifaresim.h"
#include "iso14443crc.h"
#include "crapto1/crapto1.h"
#include "BigBuf.h"
#include "string.h"
#include "mifareutil.h"
#include "fpgaloader.h"
#include "proxmark3.h"
#include "usb_cdc.h"
#include "cmd.h"
#include "protocols.h"
#include "apps.h"

static tUart Uart;

uint8_t MifareCardType;

static bool IsTrailerAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {
    uint8_t sector_trailer[16];
    emlGetMem(sector_trailer, blockNo, 1);
    uint8_t AC = ((sector_trailer[7] >> 5) & 0x04)
                 | ((sector_trailer[8] >> 2) & 0x02)
                 | ((sector_trailer[8] >> 7) & 0x01);
    switch (action) {
        case AC_KEYA_READ: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_KEYA_READ");
            return false;
        }
        case AC_KEYA_WRITE: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_KEYA_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x04 || AC == 0x03)));
        }
        case AC_KEYB_READ: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_KEYB_READ");
            return (keytype == AUTHKEYA && (AC == 0x00 || AC == 0x02 || AC == 0x01));
        }
        case AC_KEYB_WRITE: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_KEYB_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x04))
                    || (keytype == AUTHKEYB && (AC == 0x04 || AC == 0x03)));
        }
        case AC_AC_READ: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_AC_READ");
            return ((keytype == AUTHKEYA)
                    || (keytype == AUTHKEYB && !(AC == 0x00 || AC == 0x02 || AC == 0x01)));
        }
        case AC_AC_WRITE: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsTrailerAccessAllowed: AC_AC_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x03 || AC == 0x05)));
        }
        default:
            return false;
    }
}


static bool IsDataAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {

    uint8_t sector_trailer[16];
    emlGetMem(sector_trailer, SectorTrailer(blockNo), 1);

    uint8_t sector_block;
    if (blockNo <= MIFARE_2K_MAXBLOCK) {
        sector_block = blockNo & 0x03;
    } else {
        sector_block = (blockNo & 0x0f) / 5;
    }

    uint8_t AC;
    switch (sector_block) {
        case 0x00: {
            AC = ((sector_trailer[7] >> 2) & 0x04)
                 | ((sector_trailer[8] << 1) & 0x02)
                 | ((sector_trailer[8] >> 4) & 0x01);
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed: case 0x00 - %02x", AC);
            break;
        }
        case 0x01: {
            AC = ((sector_trailer[7] >> 3) & 0x04)
                 | ((sector_trailer[8] >> 0) & 0x02)
                 | ((sector_trailer[8] >> 5) & 0x01);
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed: case 0x01 - %02x", AC);
            break;
        }
        case 0x02: {
            AC = ((sector_trailer[7] >> 4) & 0x04)
                 | ((sector_trailer[8] >> 1) & 0x02)
                 | ((sector_trailer[8] >> 6) & 0x01);
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed: case 0x02  - %02x", AC);
            break;
        }
        default:
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed: Error");
            return false;
    }

    switch (action) {
        case AC_DATA_READ: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed - AC_DATA_READ: OK");
            return ((keytype == AUTHKEYA && !(AC == 0x03 || AC == 0x05 || AC == 0x07))
                    || (keytype == AUTHKEYB && !(AC == 0x07)));
        }
        case AC_DATA_WRITE: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed - AC_DATA_WRITE: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x04 || AC == 0x06 || AC == 0x03)));
        }
        case AC_DATA_INC: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("IsDataAccessAllowed - AC_DATA_INC: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x06)));
        }
        case AC_DATA_DEC_TRANS_REST: {
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("AC_DATA_DEC_TRANS_REST: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x06 || AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x06 || AC == 0x01)));
        }
    }

    return false;
}

static bool IsAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {
    if (IsSectorTrailer(blockNo)) {
        return IsTrailerAccessAllowed(blockNo, keytype, action);
    } else {
        return IsDataAccessAllowed(blockNo, keytype, action);
    }
}

static void MifareSimInit(uint16_t flags, uint8_t *datain, tag_response_info_t **responses, uint32_t *cuid, uint8_t *uid_len) {

    // SPEC: https://www.nxp.com/docs/en/application-note/AN10833.pdf
    // ATQA

    static uint8_t rATQA_Mini_4B[]  = {0x44, 0x00};       	// indicate Mifare classic Mini 4Byte UID
    static uint8_t rATQA_Mini_7B[]  = {0x44, 0x00};       	// indicate Mifare classic Mini 7Byte UID
    static uint8_t rATQA_Mini_10B[] = {0x44, 0x00};       	// indicate Mifare classic Mini 10Byte UID

    static uint8_t rATQA_1k_4B[]  = {0x04, 0x00}; 				// indicate Mifare classic 1k 4Byte UID
    static uint8_t rATQA_1k_7B[]  = {0x44, 0x00}; 		 		// indicate Mifare classic 1k 7Byte UID
    static uint8_t rATQA_1k_10B[] = {0x42, 0x00};				  // indicate Mifare classic 4k 10Byte UID

    static uint8_t rATQA_2k_4B[]  = {0x04, 0x00}; 					// indicate Mifare classic 2k 4Byte UID
    static uint8_t rATQA_2k_7B[]  = {0x44, 0x00}; 					// indicate Mifare classic 2k 7Byte UID
    static uint8_t rATQA_2k_10B[] = {0x42, 0x00};				  // indicate Mifare classic 4k 10Byte UID

    static uint8_t rATQA_4k_4B[]  = {0x02, 0x00};				  // indicate Mifare classic 4k 4Byte UID
    static uint8_t rATQA_4k_7B[]  = {0x42, 0x00};				  // indicate Mifare classic 4k 7Byte UID
    static uint8_t rATQA_4k_10B[] = {0x42, 0x00};				  // indicate Mifare classic 4k 10Byte UID

    static uint8_t rATQA[] = {0x00, 0x00};

    // SAK + CRC
    static uint8_t rSAK_mini[] = {0x09, 0x3f, 0xcc};				// mifare Mini
    static uint8_t rSAK_1[]    = {0x08, 0xb6, 0xdd};				// mifare 1k
    static uint8_t rSAK_2[]    = {0x08, 0xb6, 0xdd};				// mifare 2k
    static uint8_t rSAK_4[]    = {0x18, 0x37, 0xcd};				// mifare 4k

    static uint8_t rUIDBCC1[]  = {0x00, 0x00, 0x00, 0x00, 0x00};	// UID 1st cascade level
    static uint8_t rUIDBCC2[]  = {0x00, 0x00, 0x00, 0x00, 0x00};	// UID 2nd cascade level
    static uint8_t rUIDBCC3[]  = {0x00, 0x00, 0x00, 0x00, 0x00};	// UID 3nd cascade level

    static uint8_t rSAK1[]     = {0x04, 0xda, 0x17}; 			// Acknowledge but indicate UID is not finished. Used for any MIFARE Classic CL1 with double UID size

    *uid_len = 0;

    // -- Determine the UID
    // Can be set from emulator memory or incoming data
    // Length: 4,7,or 10 bytes
    if ((flags & FLAG_UID_IN_EMUL) == FLAG_UID_IN_EMUL) {
        emlGetMemBt(datain, 0, 10);  // load 10bytes from EMUL to the datain pointer. to be used below.
    }

    if ((flags & FLAG_4B_UID_IN_DATA) == FLAG_4B_UID_IN_DATA) { 	// get UID from datain
        memcpy(rUIDBCC1, datain, 4);
        *uid_len = 4;
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MifareSimInit - FLAG_4B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_4B_UID_IN_DATA, flags, rUIDBCC1);
    } else if ((flags & FLAG_7B_UID_IN_DATA) == FLAG_7B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain, 3);
        memcpy(rUIDBCC2, datain + 3, 4);
        *uid_len = 7;
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MifareSimInit - FLAG_7B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_7B_UID_IN_DATA, flags, rUIDBCC1);
    } else if ((flags & FLAG_10B_UID_IN_DATA) == FLAG_10B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain,   3);
        memcpy(&rUIDBCC2[1], datain + 3, 3);
        memcpy(rUIDBCC3,    datain + 6, 4);
        *uid_len = 10;
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MifareSimInit - FLAG_10B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_10B_UID_IN_DATA, flags, rUIDBCC1);
    }

    switch (*uid_len) {

        // UID 4B
        case 4:
            switch (MifareCardType) {
                case 0: // Mifare Mini
                    memcpy(rATQA, rATQA_Mini_4B, sizeof rATQA_Mini_4B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_Mini_4B");
                    break;
                case 1: // Mifare 1K
                    memcpy(rATQA, rATQA_1k_4B, sizeof rATQA_1k_4B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_1k_4B");
                    break;
                case 2: // Mifare 2K
                    memcpy(rATQA, rATQA_2k_4B, sizeof rATQA_2k_4B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_2k_4B");
                    break;
                case 4: // Mifare 4K
                    memcpy(rATQA, rATQA_4k_4B, sizeof rATQA_4k_4B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_4k_4B");
                    break;
            }

            // save CUID
            *cuid = bytes_to_num(rUIDBCC1, 4);
            // BCC
            rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
            if (MF_DBGLEVEL >= MF_DBG_NONE)	{
                Dbprintf("4B UID: %02x%02x%02x%02x", rUIDBCC1[0], rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3]);
            }
            break;

        // UID 7B
        case 7:

            switch (MifareCardType) {
                case 0: // Mifare Mini
                    memcpy(rATQA, rATQA_Mini_7B, sizeof rATQA_Mini_7B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_Mini_7B");
                    break;
                case 1: // Mifare 1K
                    memcpy(rATQA, rATQA_1k_7B, sizeof rATQA_1k_7B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_1k_7B");
                    break;
                case 2: // Mifare 2K
                    memcpy(rATQA, rATQA_2k_7B, sizeof rATQA_2k_7B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_2k_7B");
                    break;
                case 4: // Mifare 4K
                    memcpy(rATQA, rATQA_4k_7B, sizeof rATQA_4k_7B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_4k_4B");
                    break;
            }

            // save CUID
            *cuid = bytes_to_num(rUIDBCC2, 4);
            // CascadeTag, CT
            rUIDBCC1[0] = MIFARE_SELECT_CT;
            // BCC
            rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
            rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
            if (MF_DBGLEVEL >= MF_DBG_NONE)	{
                Dbprintf("7B UID: %02x %02x %02x %02x %02x %02x %02x",
                         rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3], rUIDBCC2[0], rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3]);
            }
            break;

        // UID 10B
        case 10:
            switch (MifareCardType) {
                case 0: // Mifare Mini
                    memcpy(rATQA, rATQA_Mini_10B, sizeof rATQA_Mini_10B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_Mini_10B");
                    break;
                case 1: // Mifare 1K
                    memcpy(rATQA, rATQA_1k_10B, sizeof rATQA_1k_10B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_1k_10B");
                    break;
                case 2: // Mifare 2K
                    memcpy(rATQA, rATQA_2k_10B, sizeof rATQA_2k_10B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_2k_10B");
                    break;
                case 4: // Mifare 4K
                    memcpy(rATQA, rATQA_4k_10B, sizeof rATQA_4k_10B);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("=> Using rATQA_4k_10B");
                    break;
            }

            // save CUID
            *cuid = bytes_to_num(rUIDBCC3, 4);
            // CascadeTag, CT
            rUIDBCC1[0] = MIFARE_SELECT_CT;
            rUIDBCC2[0] = MIFARE_SELECT_CT;
            // BCC
            rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
            rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
            rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3];

            if (MF_DBGLEVEL >= MF_DBG_NONE)	{
                Dbprintf("10B UID: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                         rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3],
                         rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3],
                         rUIDBCC3[0], rUIDBCC3[1], rUIDBCC3[2], rUIDBCC3[3]
                        );
            }
            break;
        default:
            break;
    }

    static tag_response_info_t responses_init[TAG_RESPONSE_COUNT] = {
        { .response = rATQA,     .response_n = sizeof(rATQA)     },		  // Answer to request - respond with card type
        { .response = rUIDBCC1,  .response_n = sizeof(rUIDBCC1)  },	  	// Anticollision cascade1 - respond with first part of uid
        { .response = rUIDBCC2,  .response_n = sizeof(rUIDBCC2)  },		  // Anticollision cascade2 - respond with 2nd part of uid
        { .response = rUIDBCC3,  .response_n = sizeof(rUIDBCC3)  },		  // Anticollision cascade3 - respond with 3th part of uid
        { .response = rSAK_mini, .response_n = sizeof(rSAK_mini) },     // SAK Mifare Mini
        { .response = rSAK_1,    .response_n = sizeof(rSAK_1)    },	    // SAK Mifare 1K
        { .response = rSAK_2,    .response_n = sizeof(rSAK_2)    },	    // SAK Mifare 2K
        { .response = rSAK_4,    .response_n = sizeof(rSAK_4)    },	    // SAK Mifare 4K
        { .response = rSAK1,     .response_n = sizeof(rSAK1)     }		  // Acknowledge select - Need another cascades
    };

    // Prepare ("precompile") the responses of the anticollision phase. There will be not enough time to do this at the moment the reader sends its REQA or SELECT
    // There are 7 predefined responses with a total of 18 bytes data to transmit. Coded responses need one byte per bit to transfer (data, parity, start, stop, correction)
    // 18 * 8 data bits, 18 * 1 parity bits, 5 start bits, 5 stop bits, 5 correction bits  ->   need 177 bytes buffer

    uint8_t *free_buffer_pointer = BigBuf_malloc(ALLOCATED_TAG_MODULATION_BUFFER_SIZE);
    size_t free_buffer_size = ALLOCATED_TAG_MODULATION_BUFFER_SIZE;

    for (size_t i = 0; i < TAG_RESPONSE_COUNT; i++) {
        prepare_allocated_tag_modulation(&responses_init[i], &free_buffer_pointer, &free_buffer_size);
    }

    *responses = responses_init;

    // indices into responses array:
#define ATQA     0
#define UIDBCC1  1
#define UIDBCC2  2
#define UIDBCC3  3
#define SAK_MINI 4
#define SAK_1    5
#define SAK_2    6
#define SAK_4    7
#define SAK1     8

}

static bool HasValidCRC(uint8_t *receivedCmd, uint16_t receivedCmd_len) {
    uint8_t CRC_byte_1, CRC_byte_2;
    compute_crc(CRC_14443_A, receivedCmd, receivedCmd_len - 2, &CRC_byte_1, &CRC_byte_2);
    return (receivedCmd[receivedCmd_len - 2] == CRC_byte_1 && receivedCmd[receivedCmd_len - 1] == CRC_byte_2);
}


/**
*MIFARE 1K simulate.
*
*@param flags :
*	FLAG_INTERACTIVE - In interactive mode, we are expected to finish the operation with an ACK
* FLAG_4B_UID_IN_DATA - means that there is a 4-byte UID in the data-section, we're expected to use that
* FLAG_7B_UID_IN_DATA - means that there is a 7-byte UID in the data-section, we're expected to use that
* FLAG_10B_UID_IN_DATA	- use 10-byte UID in the data-section not finished
*	FLAG_NR_AR_ATTACK  - means we should collect NR_AR responses for bruteforcing later
*@param exitAfterNReads, exit simulation after n blocks have been read, 0 is infinite ...
* (unless reader attack mode enabled then it runs util it gets enough nonces to recover all keys attmpted)
*/
void Mifare1ksim(uint16_t flags, uint8_t exitAfterNReads, uint8_t arg2, uint8_t *datain) {
    tag_response_info_t *responses;
    uint8_t	cardSTATE = MFEMUL_NOFIELD;
    uint8_t uid_len = 0; // 4,7, 10
    uint32_t cuid = 0;

    int vHf = 0;	// in mV

    uint32_t selTimer = 0;
    uint32_t authTimer = 0;

    uint8_t blockNo;

    uint32_t nr;
    uint32_t ar;

    bool encrypted_data;

    uint8_t cardWRBL = 0;
    uint8_t cardAUTHSC = 0;
    uint8_t cardAUTHKEY = AUTHKEYNONE;  // no authentication
    uint32_t cardRr = 0;
    uint32_t ans = 0;

    uint32_t cardINTREG = 0;
    uint8_t cardINTBLOCK = 0;
    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint32_t numReads = 0;	//Counts numer of times reader reads a block
    uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_dec[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
    uint16_t receivedCmd_len;

    uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t response_par[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint8_t rAUTH_AT[] = {0x00, 0x00, 0x00, 0x00};

    //Here, we collect UID,sector,keytype,NT,AR,NR,NT2,AR2,NR2
    // This will be used in the reader-only attack.

    //allow collecting up to 7 sets of nonces to allow recovery of up to 7 keys
#define ATTACK_KEY_COUNT 7 // keep same as define in cmdhfmf.c -> readerAttack() (Cannot be more than 7)
    nonces_t ar_nr_resp[ATTACK_KEY_COUNT * 2]; //*2 for 2 separate attack types (nml, moebius) 36 * 7 * 2 bytes = 504 bytes
    memset(ar_nr_resp, 0x00, sizeof(ar_nr_resp));

    uint8_t ar_nr_collected[ATTACK_KEY_COUNT * 2]; //*2 for 2nd attack type (moebius)
    memset(ar_nr_collected, 0x00, sizeof(ar_nr_collected));
    uint8_t	nonce1_count = 0;
    uint8_t	nonce2_count = 0;
    uint8_t	moebius_n_count = 0;
    bool gettingMoebius = false;
    uint8_t	mM = 0; //moebius_modifier for collection storage

    // Authenticate response - nonce
    uint8_t rAUTH_NT[4];
    uint8_t rAUTH_NT_keystream[4];
    uint32_t nonce = 0;

    if ((flags & FLAG_MF_MINI) == FLAG_MF_MINI) {
        MifareCardType = 0;
        Dbprintf("Mifare Mini");
    }
    if ((flags & FLAG_MF_1K) == FLAG_MF_1K) {
        MifareCardType = 1;
        Dbprintf("Mifare 1K");
    }
    if ((flags & FLAG_MF_2K) == FLAG_MF_2K) {
        MifareCardType = 2;
        Dbprintf("Mifare 2K");
    }
    if ((flags & FLAG_MF_4K) == FLAG_MF_4K) {
        MifareCardType = 4;
        Dbprintf("Mifare 4K");
    }

    MifareSimInit(flags, datain, &responses, &cuid, &uid_len);

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();
    // clear trace
    clear_trace();
    set_tracing(true);
    LED_D_ON();
    ResetSspClk();

    bool finished = false;
    bool button_pushed = BUTTON_PRESS();

    while (!button_pushed && !finished && !usb_poll_validate_length()) {
        WDT_HIT();

        // find reader field
        if (cardSTATE == MFEMUL_NOFIELD) {
            vHf = (MAX_ADC_HF_VOLTAGE_RDV40 * AvgAdc(ADC_CHAN_HF)) >> 10;
            if (vHf > MF_MINFIELDV) {
                cardSTATE_TO_IDLE();
                LED_A_ON();
            }
            button_pushed = BUTTON_PRESS();
            continue;
        }

        //Now, get data
        int res = EmGetCmd(receivedCmd, &receivedCmd_len, receivedCmd_par);

        if (res == 2) { //Field is off!
            LEDsoff();
            cardSTATE = MFEMUL_NOFIELD;
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("cardSTATE = MFEMUL_NOFIELD");
            continue;
        } else if (res == 1) { // button pressed
            button_pushed = true;
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("Button pressed");
            break;
        }

        // WUPA in HALTED state or REQA or WUPA in any other state
        if (receivedCmd_len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
            selTimer = GetTickCount();
            if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("EmSendPrecompiledCmd(&responses[ATQA]);");
            EmSendPrecompiledCmd(&responses[ATQA]);

            // init crypto block
            crypto1_destroy(pcs);
            cardAUTHKEY = AUTHKEYNONE;
            nonce = prng_successor(selTimer, 32);
            // prepare NT for nested authentication
            num_to_bytes(nonce, 4, rAUTH_NT);
            num_to_bytes(cuid ^ nonce, 4, rAUTH_NT_keystream);

            LED_B_OFF();
            LED_C_OFF();
            cardSTATE = MFEMUL_SELECT1;
            continue;
        }

        switch (cardSTATE) {
            case MFEMUL_NOFIELD:
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MFEMUL_NOFIELD");
            case MFEMUL_HALTED:
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MFEMUL_HALTED");
            case MFEMUL_IDLE: {
                LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MFEMUL_IDLE");
                break;
            }

            // The anti-collision sequence, which is a mandatory part of the card activation sequence.
            // It auto with 4-byte UID (= Single Size UID),
            // 7 -byte UID (= Double Size UID) or 10-byte UID (= Triple Size UID).

            // Cascade Level 1
            //
            // In the Cascade Level 1, the card send the anti-collision command CL1 (0x93) and the PICC returns
            // either the 4-byte UID (UID0...UID4) and one-byte BCC
            // or a Cascade Tag (CT) followed by the first 3 byte of the UID (UID0...UID2) and onebyte BCC.
            //
            // The CT (0x88) indicates that the UID is not yet complete, and another Cascade Level is needed
            //
            // The UID0 byte of a 4-byte UID must not be 0x88.
            // The CL1 then must be selected, using the Select command CL1 (0x93). The PICC returns its SAK CL1, which indicates
            // whether the UID is complete or not, and (if so),
            // the type of card and whether the card supports T=CL.

            case MFEMUL_SELECT1: {
                // select all - 0x93 0x20 (Anti Collision CL1)
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("cardSTATE = MFEMUL_SELECT1 - receivedCmd_len: %d - receivedCmd[0]: %02x - receivedCmd[1]: %02x", receivedCmd_len, receivedCmd[0], receivedCmd[1]);
                if (receivedCmd_len == 2 && (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmd[1] == 0x20)) {
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("SELECT ALL CL1 received - EmSendPrecompiledCmd(%02x)", &responses[UIDBCC1]);
                    EmSendPrecompiledCmd(&responses[UIDBCC1]);
                    break;
                }

                // select card - 0x93 0x70 (Select CL1)
                if (receivedCmd_len == 9 &&
                        (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT &&
                         receivedCmd[1] == 0x70 &&
                         memcmp(&receivedCmd[2], responses[UIDBCC1].response, 4) == 0)) {
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("SELECT CL1 %02x%02x%02x%02x received", receivedCmd[2], receivedCmd[3], receivedCmd[4], receivedCmd[5]);

                    // Send SAK according UID len
                    switch (uid_len) {
                        case 4:
                            switch (MifareCardType) {
                                case 0: // Mifare Mini
                                    EmSendPrecompiledCmd(&responses[SAK_MINI]);
                                    break;
                                case 1: // Mifare 1K
                                    EmSendPrecompiledCmd(&responses[SAK_1]);
                                    break;
                                case 2: // Mifare 2K
                                    EmSendPrecompiledCmd(&responses[SAK_2]);
                                    break;
                                case 4: // Mifare 4K
                                    EmSendPrecompiledCmd(&responses[SAK_4]);
                                    break;
                            }

                            LED_B_ON();
                            cardSTATE = MFEMUL_WORK;
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT1] cardSTATE = MFEMUL_WORK");
                            break;
                        case 7:
                            // SAK => Need another select round
                            EmSendPrecompiledCmd(&responses[SAK1]);
                            cardSTATE	= MFEMUL_SELECT2;
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT1] cardSTATE = MFEMUL_SELECT2");
                            break;
                        case 10:
                            // SAK => Need another select round
                            EmSendPrecompiledCmd(&responses[SAK1]);
                            cardSTATE	= MFEMUL_SELECT2;
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT1] cardSTATE = MFEMUL_SELECT2");
                            break;
                        default:
                            break;
                    } // End Switch (uid_len)

                } else {
                    // IDLE
                    cardSTATE_TO_IDLE();
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT1] cardSTATE = MFEMUL_IDLE");
                }
                // Break Case MFEMUL_SELECT1
                break;
            }


            // Cascade Level 2
            //
            // If the UID is not yet complete, the PCD continues with an anti-collision CL2 command (0x95),
            // and the PICC returns
            // • either the last 4 bytes of the Double Size UID (UID3...UID6) and one-byte BCC,
            // • or a Cascade Tag (CT) followed by the next 3 bytes of the Triple Size UID (UID3...UID5) and one-byte BCC.
            // The CT (0x88) indicates that the UID is not yet complete, and another Cascade Level  has to follow.
            //
            // The UID3 byte of a 7 byte or 10-byte UID must not be 0x88
            // The CL2 then must be selected, using the Select command CL2 (0x95).
            // The PICC returns its SAK CL2, which indicates
            // whether the UID is complete or not, and (if so),
            // the type of card and whether the card supports T=CL.

            // select all cl2 - 0x95 0x20

            case MFEMUL_SELECT2: {
                if (receivedCmd_len == 2 &&
                        (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmd[1] == 0x20)) {
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("[MFEMUL_SELECT2] SELECT ALL CL2 received");
                    EmSendPrecompiledCmd(&responses[UIDBCC2]);
                    break;
                }

                // select cl2 card - 0x95 0x70 xxxxxxxxxxxx
                if (receivedCmd_len == 9 &&
                        (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 &&
                         receivedCmd[1] == 0x70 &&
                         memcmp(&receivedCmd[2], responses[UIDBCC2].response, 4) == 0)) {

                    switch (uid_len) {
                        case 7:
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT2] SELECT CL2 %02x%02x%02x%02x received", receivedCmd[2], receivedCmd[3], receivedCmd[4], receivedCmd[5]);

                            switch (MifareCardType) {
                                case 0: // Mifare Mini
                                    EmSendPrecompiledCmd(&responses[SAK_MINI]);
                                    break; 
                                case 1: // Mifare 1K
                                    EmSendPrecompiledCmd(&responses[SAK_1]);
                                    break;
                                case 2: // Mifare 2K
                                    EmSendPrecompiledCmd(&responses[SAK_2]);
                                    break;
                                case 4: // Mifare 4K
                                    EmSendPrecompiledCmd(&responses[SAK_4]);
                                    break;
                            }
                            cardSTATE = MFEMUL_WORK;
                            LED_B_ON();
                            break;
                        case 10:
                            // SAK => Need another select round
                            EmSendPrecompiledCmd(&responses[SAK1]);
                            cardSTATE = MFEMUL_SELECT3;
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT2] cardSTATE = MFEMUL_SELECT3");
                        default:
                            break;
                    }

                } else {
                    // IDLE
                    cardSTATE_TO_IDLE();
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT2] cardSTATE = MFEMUL_IDLE");
                }
                // Break Case MFEMUL_SELECT2
                break;
            }


            // Cascade Level 3
            // Select command CL3 (0x97)
            //
            // If the UID is not yet complete, the PCD continues with an anti-collision CL3 command (0x97)
            // and the PICC returns the last 4 bytes of the Triple Size UID (UID6...UID9) and one-byte BCC.
            // The PICC returns its SAK CL3, which indicates the type of card and whether the card supports T=CL

            case MFEMUL_SELECT3: {
                if (!uid_len) {
                    LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    break;
                }
                if (receivedCmd_len == 2 && (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmd[1] == 0x20)) {
                    EmSendPrecompiledCmd(&responses[UIDBCC3]);
                    break;
                }
                if (receivedCmd_len == 9 &&
                        (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 &&
                         receivedCmd[1] == 0x70 &&
                         memcmp(&receivedCmd[2], responses[UIDBCC3].response, 4) == 0)) {

                    switch (MifareCardType) {
                        case 0: // Mifare Mini
                            EmSendPrecompiledCmd(&responses[SAK_MINI]);
                            break;
                        case 1: // Mifare 1K
                            EmSendPrecompiledCmd(&responses[SAK_1]);
                            break;
                        case 2: // Mifare 2K
                            EmSendPrecompiledCmd(&responses[SAK_2]);
                            break;
                        case 4: // Mifare 4K
                            EmSendPrecompiledCmd(&responses[SAK_4]);
                            break;
                    }

                    cardSTATE = MFEMUL_WORK;
                    LED_B_ON();
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_SELECT3] --> WORK. anticol3 time: %d", GetTickCount() - selTimer);
                        Dbprintf("[MFEMUL_SELECT3] cardSTATE = MFEMUL_WORK");
                    }
                    continue;
                } else {
                    // IDLE
                    cardSTATE_TO_IDLE();
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT3] cardSTATE = MFEMUL_IDLE");
                }
                // Break Case MFEMUL_SELECT3
                break;
            }

            // WORK
            case MFEMUL_WORK: {

                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("[MFEMUL_WORK] Enter in case");

                if (receivedCmd_len != 4) {
                    LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, receivedCmd_dec);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] All commands must have exactly 4 bytes: receivedCmd_len=%d - Cmd: %02X", receivedCmd_len, receivedCmd_dec);
                    break;
                }

                if (receivedCmd_len == 0) {
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] NO CMD received");
                    break;
                }

                encrypted_data = (cardAUTHKEY != AUTHKEYNONE);
                if (encrypted_data) {
                    // decrypt seqence
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, receivedCmd_dec);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Decrypt seqence");
                } else {
                    // Data in clear
                    memcpy(receivedCmd_dec, receivedCmd, receivedCmd_len);
                }

                if (!HasValidCRC(receivedCmd_dec, receivedCmd_len)) { // all commands must have a valid CRC
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] All commands must have a valid CRC %02X (%d)", receivedCmd_dec, receivedCmd_len);
                    break;
                }

                if (receivedCmd_len == 4 && (receivedCmd_dec[0] == MIFARE_AUTH_KEYA || receivedCmd_dec[0] == MIFARE_AUTH_KEYB)) {

                    // Reader asks for AUTH: 6X XX
                    // RCV: 60 XX => Using KEY A
                    // RCV: 61 XX => Using KEY B
                    // XX: Block number

                    // if authenticating to a block that shouldn't exist - as long as we are not doing the reader attack
                    if (receivedCmd_dec[1] > MIFARE_4K_MAXBLOCK && !((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK)) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Reader tried to operate (0x%02x) on out of range block: %d (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], receivedCmd_dec[1]);
                        break;
                    }

                    authTimer = GetTickCount();

                    // received block num -> sector
                    // Example: 6X  [00]
                    // 4K tags have 16 blocks per sector 32..39
                    cardAUTHSC = MifareBlockToSector(receivedCmd_dec[1]);

                    // cardAUTHKEY: 60 => Auth use Key A
                    // cardAUTHKEY: 61 => Auth use Key B
                    cardAUTHKEY = receivedCmd_dec[0] & 0x01;

                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] KEY %c: %012" PRIx64, (cardAUTHKEY == 0) ? 'A' : 'B', emlGetKey(cardAUTHSC, cardAUTHKEY));

                    // first authentication
                    crypto1_destroy(pcs);

                    // Load key into crypto
                    crypto1_create(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));

                    if (!encrypted_data) {
                        // Receive Cmd in clear txt
                        // Update crypto state (UID ^ NONCE)
                        crypto1_word(pcs, cuid ^ nonce, 0);
                        // rAUTH_NT contains prepared nonce for authenticate
                        EmSendCmd(rAUTH_NT, sizeof(rAUTH_NT));
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Reader authenticating for block %d (0x%02x) with key %c - nonce: %02X - ciud: %02X", receivedCmd_dec[1], receivedCmd_dec[1], (cardAUTHKEY == 0) ? 'A' : 'B', rAUTH_AT, cuid);
                    } else {
                        // nested authentication
                        /*
                        ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0);
                        num_to_bytes(ans, 4, rAUTH_AT);
                        */
                        // rAUTH_NT, rAUTH_NT_keystream contains prepared nonce and keystream for nested authentication
                        // we need calculate parity bits for non-encrypted sequence
                        mf_crypto1_encryptEx(pcs, rAUTH_NT, rAUTH_NT_keystream, response, 4, response_par);
                        EmSendCmdPar(response, 4, response_par);
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Reader doing nested authentication for block %d (0x%02x) with key %c", receivedCmd_dec[1], receivedCmd_dec[1], (cardAUTHKEY == 0) ? 'A' : 'B');
                    }

                    cardSTATE = MFEMUL_AUTH1;
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_AUTH1 - rAUTH_AT: %02X", rAUTH_AT);
                    continue;
                }

                // rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
                // BUT... ACK --> NACK
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_ACK) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    break;
                }

                // rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_NACK_NA) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_ACK) : CARD_ACK);
                    break;
                }

                //if (!encrypted_data) { // all other commands must be encrypted (authenticated)
                //     if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Commands must be encrypted (authenticated)");
                //     break;
                //}

                // case MFEMUL_WORK => if Cmd is Read, Write, Inc, Dec, Restore, Transfert
                if (receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK
                        || receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK
                        || receivedCmd_dec[0] == MIFARE_CMD_INC
                        || receivedCmd_dec[0] == MIFARE_CMD_DEC
                        || receivedCmd_dec[0] == MIFARE_CMD_RESTORE
                        || receivedCmd_dec[0] == MIFARE_CMD_TRANSFER) {
                    // Check if Block num is not too far
                    if (receivedCmd_dec[1] > MIFARE_4K_MAXBLOCK) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on out of range block: %d (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], receivedCmd_dec[1]);
                        break;
                    }
                    if (receivedCmd_dec[1] / 4 != cardAUTHSC) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on block (0x%02x) not authenticated for (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], cardAUTHSC);
                        break;
                    }
                }

                // case MFEMUL_WORK => CMD READ block
                if (receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK) {
                    blockNo = receivedCmd_dec[1];
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Reader reading block %d (0x%02x)", blockNo, blockNo);
                    emlGetMem(response, blockNo, 1);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)  {
                        Dbprintf("[MFEMUL_WORK - ISO14443A_CMD_READBLOCK] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                                 response[14], response[15]);
                    }

                    // Access permission managment:
                    //
                    // Sector Trailer:
                    // - KEY A access
                    // - KEY B access
                    // - AC bits access
                    //
                    // Data block:
                    // - Data access

                    // If permission is not allowed, data is cleared (00) in emulator memeory.
                    // ex: a0a1a2a3a4a561e789c1b0b1b2b3b4b5 => 00000000000061e789c1b0b1b2b3b4b5


                    // Check if selected Block is a Sector Trailer
                    if (IsSectorTrailer(blockNo)) {

                        if (!IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYA_READ)) {
                            memset(response, 0x00, 6); 	// keyA can never be read
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyA can never be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                        if (!IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYB_READ)) {
                            memset(response + 10, 0x00, 6); 	// keyB cannot be read
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyB cannot be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                        if (!IsAccessAllowed(blockNo, cardAUTHKEY, AC_AC_READ)) {
                            memset(response + 6, 0x00, 4); 	// AC bits cannot be read
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] AC bits cannot be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                    } else {
                        if (!IsAccessAllowed(blockNo, cardAUTHKEY, AC_DATA_READ)) {
                            memset(response, 0x00, 16);		// datablock cannot be read
                            if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] Data block %d (0x%02x) cannot be read", blockNo, blockNo);
                        }
                    }
                    AddCrc14A(response, 16);
                    mf_crypto1_encrypt(pcs, response, MAX_MIFARE_FRAME_SIZE, response_par);
                    EmSendCmdPar(response, MAX_MIFARE_FRAME_SIZE, response_par);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_WORK - EmSendCmdPar] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                                 response[14], response[15]);
                    }
                    numReads++;

                    if (exitAfterNReads > 0 && numReads == exitAfterNReads) {
                        Dbprintf("[MFEMUL_WORK] %d reads done, exiting", numReads);
                        finished = true;
                    }
                    break;

                } // End receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK

                // case MFEMUL_WORK => CMD WRITEBLOCK
                if (receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK) {
                    blockNo = receivedCmd_dec[1];
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0xA0 write block %d (%02x)", blockNo, blockNo);
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    cardWRBL = blockNo;
                    cardSTATE = MFEMUL_WRITEBL2;
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_WRITEBL2");
                    break;
                }

                // case MFEMUL_WORK => CMD INC/DEC/REST
                if (receivedCmd_dec[0] == MIFARE_CMD_INC || receivedCmd_dec[0] == MIFARE_CMD_DEC || receivedCmd_dec[0] == MIFARE_CMD_RESTORE) {
                    blockNo = receivedCmd_dec[1];
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x inc(0xC1)/dec(0xC0)/restore(0xC2) block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                    if (emlCheckValBl(blockNo)) {
                        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate on block, but emlCheckValBl failed, nacking");
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        break;
                    }
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    cardWRBL = blockNo;

                    // INC
                    if (receivedCmd_dec[0] == MIFARE_CMD_INC) {
                        cardSTATE = MFEMUL_INTREG_INC;
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_INC");
                    }

                    // DEC
                    if (receivedCmd_dec[0] == MIFARE_CMD_DEC) {
                        cardSTATE = MFEMUL_INTREG_DEC;
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_DEC");
                    }

                    // REST
                    if (receivedCmd_dec[0] == MIFARE_CMD_RESTORE) {
                        cardSTATE = MFEMUL_INTREG_REST;
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_REST");
                    }
                    break;

                } // End case MFEMUL_WORK => CMD INC/DEC/REST


                // case MFEMUL_WORK => CMD TRANSFER
                if (receivedCmd_dec[0] == MIFARE_CMD_TRANSFER) {
                    blockNo = receivedCmd_dec[1];
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x transfer block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                    if (emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd_dec[1]))
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                    else
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    break;
                }

                // case MFEMUL_WORK => CMD HALT
                if (receivedCmd_dec[0] == ISO14443A_CMD_HALT && receivedCmd[1] == 0x00) {
                    LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    LED_B_OFF();
                    LED_C_OFF();
                    cardSTATE = MFEMUL_HALTED;
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_HALTED");
                    break;
                }

                // case MFEMUL_WORK => CMD RATS
                if (receivedCmd[0] == ISO14443A_CMD_RATS) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("[MFEMUL_WORK] RCV RATS => NACK");
                    break;
                }

                // case MFEMUL_WORK => command not allowed
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("Received command not allowed, nacking");
                EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                break;
            }

            // AUTH1
            case MFEMUL_AUTH1: {
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("[MFEMUL_AUTH1] Enter case");

                if (receivedCmd_len != 4) {
                    cardSTATE_TO_IDLE();
                    LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)	Dbprintf("MFEMUL_AUTH1: receivedCmd_len != 8 (%d) => cardSTATE_TO_IDLE())", receivedCmd_len);
                    break;
                }

                nr = bytes_to_num(receivedCmd, 4);
                ar = bytes_to_num(&receivedCmd[4], 4);

                // Collect AR/NR per keytype & sector
                if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {
                    if (MF_DBGLEVEL >= 0)	Dbprintf("FLAG_NR_AR_ATTACK");
                    for (uint8_t i = 0; i < ATTACK_KEY_COUNT; i++) {
                        if (ar_nr_collected[i + mM] == 0 || ((cardAUTHSC == ar_nr_resp[i + mM].sector) && (cardAUTHKEY == ar_nr_resp[i + mM].keytype) && (ar_nr_collected[i + mM] > 0))) {
                            // if first auth for sector, or matches sector and keytype of previous auth
                            if (ar_nr_collected[i + mM] < 2) {
                                // if we haven't already collected 2 nonces for this sector
                                if (ar_nr_resp[ar_nr_collected[i + mM]].ar != ar) {
                                    // Avoid duplicates... probably not necessary, ar should vary.
                                    if (ar_nr_collected[i + mM] == 0) {
                                        // first nonce collect
                                        ar_nr_resp[i + mM].cuid = cuid;
                                        ar_nr_resp[i + mM].sector = cardAUTHSC;
                                        ar_nr_resp[i + mM].keytype = cardAUTHKEY;
                                        ar_nr_resp[i + mM].nonce = nonce;
                                        ar_nr_resp[i + mM].nr = nr;
                                        ar_nr_resp[i + mM].ar = ar;
                                        nonce1_count++;
                                        // add this nonce to first moebius nonce
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].cuid = cuid;
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].sector = cardAUTHSC;
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].keytype = cardAUTHKEY;
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].nonce = nonce;
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].nr = nr;
                                        ar_nr_resp[i + ATTACK_KEY_COUNT].ar = ar;
                                        ar_nr_collected[i + ATTACK_KEY_COUNT]++;
                                    } else { // second nonce collect (std and moebius)
                                        ar_nr_resp[i + mM].nonce2 = nonce;
                                        ar_nr_resp[i + mM].nr2 = nr;
                                        ar_nr_resp[i + mM].ar2 = ar;
                                        if (!gettingMoebius) {
                                            nonce2_count++;
                                            // check if this was the last second nonce we need for std attack
                                            if (nonce2_count == nonce1_count) {
                                                // done collecting std test switch to moebius
                                                // first finish incrementing last sample
                                                ar_nr_collected[i + mM]++;
                                                // switch to moebius collection
                                                gettingMoebius = true;
                                                mM = ATTACK_KEY_COUNT;
                                                nonce = nonce * 7;
                                                break;
                                            }
                                        } else {
                                            moebius_n_count++;
                                            // if we've collected all the nonces we need - finish.
                                            if (nonce1_count == moebius_n_count) finished = true;
                                        }
                                    }
                                    ar_nr_collected[i + mM]++;
                                }
                            }
                            // we found right spot for this nonce stop looking
                            break;
                        }
                    }
                }

                // --- crypto
                crypto1_word(pcs, nr, 1);
                cardRr = ar ^ crypto1_word(pcs, 0, 0);

                // test if auth KO
                if (cardRr != prng_successor(nonce, 64)) {
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_AUTH1] AUTH FAILED for sector %d with key %c. [nr=%08x  cardRr=%08x] [nt=%08x succ=%08x]"
                                 , cardAUTHSC
                                 , (cardAUTHKEY == 0) ? 'A' : 'B'
                                 , nr
                                 , cardRr
                                 , nonce // nt
                                 , prng_successor(nonce, 64)
                                );
                    }
                    cardAUTHKEY = AUTHKEYNONE;	// not authenticated
                    // LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    EmSend4bit(CARD_NACK_NA);
                    cardSTATE_TO_IDLE();
                    break;
                }

                ans = prng_successor(nonce, 96);
                num_to_bytes(ans, 4, rAUTH_AT);
                mf_crypto1_encrypt(pcs, rAUTH_AT, 4, response_par);
                EmSendCmdPar(rAUTH_AT, 4, response_par);

                if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
                    Dbprintf("[MFEMUL_AUTH1] AUTH COMPLETED for sector %d with key %c. time=%d",
                             cardAUTHSC,
                             cardAUTHKEY == 0 ? 'A' : 'B',
                             GetTickCount() - authTimer
                            );
                }
                LED_C_ON();
                cardSTATE = MFEMUL_WORK;
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_AUTH1] cardSTATE = MFEMUL_WORK");
                break;
            }

            // WRITE BL2
            case MFEMUL_WRITEBL2: {
                if (receivedCmd_len == MAX_MIFARE_FRAME_SIZE) {
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, receivedCmd_dec);
                    if (HasValidCRC(receivedCmd_dec, receivedCmd_len)) {
                        if (IsSectorTrailer(cardWRBL)) {
                            emlGetMem(response, cardWRBL, 1);
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_KEYA_WRITE)) {
                                memcpy(receivedCmd_dec, response, 6);	// don't change KeyA
                            }
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_KEYB_WRITE)) {
                                memcpy(receivedCmd_dec + 10, response + 10, 6);	// don't change KeyA
                            }
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_AC_WRITE)) {
                                memcpy(receivedCmd_dec + 6, response + 6, 4);	// don't change AC bits
                            }
                        } else {
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_DATA_WRITE)) {
                                memcpy(receivedCmd_dec, response, 16);	// don't change anything
                            }
                        }
                        emlSetMem(receivedCmd_dec, cardWRBL, 1);
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));	// always ACK?
                        cardSTATE = MFEMUL_WORK;
                        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WRITEBL2] cardSTATE = MFEMUL_WORK");
                        break;
                    }
                }
                cardSTATE_TO_IDLE();
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_WRITEBL2] cardSTATE = MFEMUL_IDLE");
                LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                break;
            }

            // INC
            case MFEMUL_INTREG_INC: {
                if (receivedCmd_len == 6) {
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                    if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        cardSTATE_TO_IDLE();
                        break;
                    }
                    LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                    cardINTREG = cardINTREG + ans;

                    cardSTATE = MFEMUL_WORK;
                    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_INC] cardSTATE = MFEMUL_WORK");
                    break;
                }
            }

            // DEC
            case MFEMUL_INTREG_DEC: {
                if (receivedCmd_len == 6) {  //  Data is encrypted
                    // Decrypted cmd
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                    if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        cardSTATE_TO_IDLE();
                        break;
                    }
                }
                LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                cardINTREG = cardINTREG - ans;
                cardSTATE = MFEMUL_WORK;
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_DEC] cardSTATE = MFEMUL_WORK");
                break;
            }

            // REST
            case MFEMUL_INTREG_REST: {
                mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                    cardSTATE_TO_IDLE();
                    break;
                }
                LogTrace(Uart.output, Uart.len, Uart.startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
                cardSTATE = MFEMUL_WORK;
                if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_REST] cardSTATE = MFEMUL_WORK");
                break;
            }

        }  // End Switch Loop

        button_pushed = BUTTON_PRESS();

    }  // End While Loop


    // NR AR ATTACK
    if (((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) && (MF_DBGLEVEL >= 1)) {
        for (uint8_t	i = 0; i < ATTACK_KEY_COUNT; i++) {
            if (ar_nr_collected[i] == 2) {
                Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i < ATTACK_KEY_COUNT / 2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
                Dbprintf("../tools/mfkey/mfkey32 %08x %08x %08x %08x %08x %08x",
                         ar_nr_resp[i].cuid,  //UID
                         ar_nr_resp[i].nonce, //NT
                         ar_nr_resp[i].nr,    //NR1
                         ar_nr_resp[i].ar,    //AR1
                         ar_nr_resp[i].nr2,   //NR2
                         ar_nr_resp[i].ar2    //AR2
                        );
            }
        }
    }

    for (uint8_t	i = ATTACK_KEY_COUNT; i < ATTACK_KEY_COUNT * 2; i++) {
        if (ar_nr_collected[i] == 2) {
            Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i < ATTACK_KEY_COUNT / 2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
            Dbprintf("../tools/mfkey/mfkey32v2 %08x %08x %08x %08x %08x %08x %08x",
                     ar_nr_resp[i].cuid,  //UID
                     ar_nr_resp[i].nonce, //NT
                     ar_nr_resp[i].nr,    //NR1
                     ar_nr_resp[i].ar,    //AR1
                     ar_nr_resp[i].nonce2,//NT2
                     ar_nr_resp[i].nr2,   //NR2
                     ar_nr_resp[i].ar2    //AR2
                    );
        }
    }

    if (MF_DBGLEVEL >= 1)	{
        Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", get_tracing(), BigBuf_get_traceLen());
    }


    if ((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE) {  // Interactive mode flag, means we need to send ACK
        //Send the collected ar_nr in the response
        cmd_send(CMD_ACK, CMD_SIMULATE_MIFARE_CARD, button_pushed, 0, &ar_nr_resp, sizeof(ar_nr_resp));
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    set_tracing(false);

}
