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
#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "common.h"

//The following data is taken from http://www.proxmark.org/forum/viewtopic.php?pid=13501#p13501
/*
ISO14443A (usually NFC tags)
    26 (7bits) = REQA
    30 = Read (usage: 30+1byte block number+2bytes ISO14443A-CRC - answer: 16bytes)
    A2 = Write (usage: A2+1byte block number+4bytes data+2bytes ISO14443A-CRC - answer: 0A [ACK] or 00 [NAK])
    52 (7bits) = WUPA (usage: 52(7bits) - answer: 2bytes ATQA)
    93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
    93 70 = Select (usage: 9370+5bytes 9320 answer - answer: 1byte SAK)
    95 20 = Anticollision of cascade level2
    95 70 = Select of cascade level2
    50 00 = Halt (usage: 5000+2bytes ISO14443A-CRC - no answer from card)

    E0 = RATS
    D0 = PPS
Mifare
    60 = Authenticate with KeyA
    61 = Authenticate with KeyB
    40 (7bits) = Used to put Chinese Changeable UID cards in special mode (must be followed by 43 (8bits) - answer: 0A)
    C0 = Decrement
    C1 = Increment
    C2 = Restore
    B0 = Transfer
Ultralight C
    A0 = Compatibility Write (to accommodate MIFARE commands)
    1A = Step1 Authenticate
    AF = Step2 Authenticate

NTAG i2c 2K
    C2 = SECTOR_SELECT

ISO14443B
    05 = REQB
    1D = ATTRIB
    50 = HALT

    BA = PING (reader -> tag)
    AB = PONG (tag -> reader)
SRIX4K (tag does not respond to 05)
    06 00 = INITIATE
    0E xx = SELECT ID (xx = Chip-ID)
    0B = Get UID
    08 yy = Read Block (yy = block number)
    09 yy dd dd dd dd = Write Block (yy = block number; dd dd dd dd = data to be written)
    0C = Reset to Inventory
    0F = Completion
    0A 11 22 33 44 55 66 = Authenticate (11 22 33 44 55 66 = data to authenticate)


ISO15693
    MANDATORY COMMANDS (all ISO15693 tags must support those)
        01 = Inventory (usage: 260100+2bytes ISO15693-CRC - answer: 12bytes)
        02 = Stay Quiet
    OPTIONAL COMMANDS (not all tags support them)
        20 = Read Block (usage: 0220+1byte block number+2bytes ISO15693-CRC - answer: 4bytes)
        21 = Write Block (usage: 0221+1byte block number+4bytes data+2bytes ISO15693-CRC - answer: 4bytes)
        22 = Lock Block
        23 = Read Multiple Blocks (usage: 0223+1byte 1st block to read+1byte last block to read+2bytes ISO15693-CRC)
        24 = Write Multiple Blocks
        25 = Select
        26 = Reset to Ready
        27 = Write AFI
        28 = Lock AFI
        29 = Write DSFID
        2A = Lock DSFID
        2B = Get_System_Info (usage: 022B+2bytes ISO15693-CRC - answer: 14 or more bytes)
        2C = Read Multiple Block Security Status (usage: 022C+1byte 1st block security to read+1byte last block security to read+2bytes ISO15693-CRC)

EM Microelectronic CUSTOM COMMANDS
    A5 = Active EAS (followed by 1byte IC Manufacturer code+1byte EAS type)
    A7 = Write EAS ID (followed by 1byte IC Manufacturer code+2bytes EAS value)
    B8 = Get Protection Status for a specific block (followed by 1byte IC Manufacturer code+1byte block number+1byte of how many blocks after the previous is needed the info)
    E4 = Login (followed by 1byte IC Manufacturer code+4bytes password)
NXP/Philips CUSTOM COMMANDS
    A0 = Inventory Read
    A1 = Fast Inventory Read
    A2 = Set EAS
    A3 = Reset EAS
    A4 = Lock EAS
    A5 = EAS Alarm
    A6 = Password Protect EAS
    A7 = Write EAS ID
    A8 = Read EPC
    B0 = Inventory Page Read
    B1 = Fast Inventory Page Read
    B2 = Get Random Number
    B3 = Set Password
    B4 = Write Password
    B5 = Lock Password
    B6 = Bit Password Protection
    B7 = Lock Page Protection Condition
    B8 = Get Multiple Block Protection Status
    B9 = Destroy SLI
    BA = Enable Privacy
    BB = 64bit Password Protection
    40 = Long Range CMD (Standard ISO/TR7003:1990)

ISO 7816-4 Basic interindustry commands. For command APDU's.
    B0 = READ BINARY
    D0 = WRITE BINARY
    D6 = UPDATE BINARY
    0E = ERASE BINARY
    B2 = READ RECORDS
    D2 = WRITE RECORDS
    E2 = APPEND RECORD
    DC = UPDATE RECORD
    CA = GET DATA
    DA = PUT DATA
    A4 = SELECT FILE
    20 = VERIFY
    88 = INTERNAL AUTHENTICATION
    82 = EXTERNAL AUTHENTICATION
    B4 = GET CHALLENGE
    70 = MANAGE CHANNEL

    For response APDU's
    90 00 = OK
    6x xx = ERROR
*/
// these cmds are adjusted to ISO15693 and Manchester encoding requests.
// for instance ICLASS_CMD_SELECT  0x81 tells if ISO14443b/BPSK coding/106 kbits/s
// for instance ICLASS_CMD_SELECT  0x41 tells if ISO14443b/BPSK coding/423 kbits/s
//
#define ICLASS_CMD_HALT             0x0
#define ICLASS_CMD_SELECT           0x1
#define ICLASS_CMD_ACTALL           0xA
#define ICLASS_CMD_DETECT           0xF

#define ICLASS_CMD_PAGESEL          0x4
#define ICLASS_CMD_CHECK            0x5
#define ICLASS_CMD_READ4            0x6
#define ICLASS_CMD_UPDATE           0x7
#define ICLASS_CMD_READCHECK        0x8
#define ICLASS_CMD_READ_OR_IDENTIFY 0xC
#define ICLASS_CMD_ACT              0xE

#define ICLASS_CREDIT(x)            (((x) & 0x10) == 0x10)
#define ICLASS_DEBIT(x)             (((x) & 0x80) == 0x80)


#define ECP_HEADER                  0x6A

// 7bit Apple Magsafe wake up command
#define MAGSAFE_CMD_WUPA_1          0x7A
#define MAGSAFE_CMD_WUPA_2          0x7B
#define MAGSAFE_CMD_WUPA_3          0x7C
#define MAGSAFE_CMD_WUPA_4          0x7D

#define ISO14443A_CMD_REQA          0x26
#define ISO14443A_CMD_READBLOCK     0x30
#define ISO14443A_CMD_WUPA          0x52
#define ISO14443A_CMD_OPTS          0x35
#define ISO14443A_CMD_ANTICOLL_OR_SELECT     0x93
#define ISO14443A_CMD_ANTICOLL_OR_SELECT_2   0x95
#define ISO14443A_CMD_ANTICOLL_OR_SELECT_3   0x97
#define ISO14443A_CMD_WRITEBLOCK    0xA0
#define ISO14443A_CMD_HALT          0x50
#define ISO14443A_CMD_RATS          0xE0
#define ISO14443A_CMD_PPS           0xD0
#define ISO14443A_CMD_NXP_DESELECT  0xC2
#define ISO14443A_CMD_WTX           0xF2

#define MIFARE_SELECT_CT            0x88
#define MIFARE_AUTH_KEYA            0x60
#define MIFARE_AUTH_KEYB            0x61
#define MIFARE_MAGICWUPC1           0x40
#define MIFARE_MAGICWUPC2           0x43
#define MIFARE_MAGICWIPEC           0x41
#define MIFARE_CMD_DEC              0xC0
#define MIFARE_CMD_INC              0xC1
#define MIFARE_CMD_RESTORE          0xC2
#define MIFARE_CMD_TRANSFER         0xB0

#define MIFARE_MAGIC_GDM_AUTH_KEY   0x80
#define MIFARE_MAGIC_GDM_READBLOCK  0x38
#define MIFARE_MAGIC_GDM_WRITEBLOCK 0xA8
#define MIFARE_MAGIC_GDM_READ_CFG   0xE0
#define MIFARE_MAGIC_GDM_WRITE_CFG  0xE1

#define MIFARE_EV1_PERSONAL_UID     0x40
#define MIFARE_EV1_SETMOD           0x43
#define MIFARE_EV1_UIDF0            0x00
#define MIFARE_EV1_UIDF1            0x40
#define MIFARE_EV1_UIDF2            0x20
#define MIFARE_EV1_UIDF3            0x60

#define MIFARE_ULC_WRITE            0xA2
#define MIFARE_ULC_COMP_WRITE       0xA0
#define MIFARE_ULC_AUTH_1           0x1A
#define MIFARE_ULC_AUTH_2           0xAF

#define MIFARE_ULEV1_AUTH           0x1B
#define MIFARE_ULEV1_VERSION        0x60
#define MIFARE_ULEV1_FASTREAD       0x3A
#define MIFARE_ULEV1_READ_CNT       0x39
#define MIFARE_ULEV1_INCR_CNT       0xA5
#define MIFARE_ULEV1_READSIG        0x3C
#define MIFARE_ULEV1_CHECKTEAR      0x3E
#define MIFARE_ULEV1_VCSL           0x4B

// New Mifare UL Nano commands.  Ref:: (https://www.nxp.com/docs/en/data-sheet/MF0UN_H_00.pdf)
#define MIFARE_ULNANO_WRITESIG      0xA9
#define MIFARE_ULNANO_LOCKSIG       0xAC

// NTAG i2k 2K  uses sector 0, and sector 1 to have access to
// block 0x00-0xFF.
#define NTAG_I2C_SELECT_SECTOR      0xC2
#define NTAG_I2C_FASTWRITE          0xA6

//NTAG 213TT (tamper) command
#define NTAGTT_CMD_READ_TT          0xA4

// mifare 4bit card answers
#define CARD_ACK      0x0A  // 1010 - ACK
#define CARD_NACK_IV  0x00  // 0000 - NACK, invalid argument (invalid page address)
#define CARD_NACK_PA  0x01  // 0001 - NACK, parity / crc error
#define CARD_NACK_NA  0x04  // 0100 - NACK, not allowed (command not allowed)
#define CARD_NACK_TR  0x05  // 0101 - NACK, transmission error
#define CARD_NACK_EE  0x07  // 0111 - NACK, EEPROM write error

// Magic Generation 1, parameter "work flags"
// bit 0 - need get UID
// bit 1 - send wupC (wakeup chinese)
// bit 2 - send HALT cmd after sequence
// bit 3 - turn on FPGA
// bit 4 - turn off FPGA
// bit 5 - set datain instead of issuing USB reply (called via ARM for StandAloneMode14a)
#define MAGIC_UID                   0x01
#define MAGIC_WUPC                  0x02
#define MAGIC_HALT                  0x04
#define MAGIC_INIT                  0x08
#define MAGIC_OFF                   0x10
#define MAGIC_DATAIN                0x20
#define MAGIC_WIPE                  0x40
#define MAGIC_SINGLE                (MAGIC_WUPC | MAGIC_HALT | MAGIC_INIT | MAGIC_OFF) //0x1E

// by CMD_HF_MIFARE_CIDENT
#define MAGIC_GEN_1A        1
#define MAGIC_GEN_1B        2
#define MAGIC_GEN_2         4
#define MAGIC_GEN_UNFUSED   5
#define MAGIC_SUPER_GEN1    6
#define MAGIC_SUPER_GEN2    7
#define MAGIC_NTAG21X       8
#define MAGIC_GEN_3         9
#define MAGIC_GEN_4GTU      10
#define MAGIC_GEN_4GDM      11
#define MAGIC_QL88          12


// Commands for configuration of Gen4 GTU cards.
// see https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md
#define GEN_4GTU_CMD    0xCF // Prefix for all commands, followed by pasword (4b)
#define GEN_4GTU_SHADOW 0x32 // Configure GTU shadow mode
#define GEN_4GTU_ATS    0x34 // Configure ATS
#define GEN_4GTU_ATQA   0x35 // Configure ATQA/SAK (swap ATQA bytes)
#define GEN_4GTU_UIDLEN 0x68 // Configure UID length
#define GEN_4GTU_ULEN   0x69 // (De)Activate Ultralight mode
#define GEN_4GTU_ULMODE 0x6A // Select Ultralight mode
#define GEN_4GTU_GETCNF 0xC6 // Dump configuration
#define GEN_4GTU_TEST   0xCC // Factory test, returns 6666
#define GEN_4GTU_WRITE  0xCD // Backdoor write 16b block
#define GEN_4GTU_READ   0xCE // Backdoor read 16b block
#define GEN_4GTU_SETCNF 0xF0 // Configure all params in one cmd
#define GEN_4GTU_FUSCNF 0xF1 // Configure all params in one cmd and fuse the configuration permanently
#define GEN_4GTU_CHPWD  0xFE // change password

/**
06 00 = INITIATE
0E xx = SELECT ID (xx = Chip-ID)
0B = Get UID
08 yy = Read Block (yy = block number)
09 yy dd dd dd dd = Write Block (yy = block number; dd dd dd dd = data to be written)
0C = Reset to Inventory
0F = Completion
0A 11 22 33 44 55 66 = Authenticate (11 22 33 44 55 66 = data to authenticate)
**/

#define ISO14443B_REQB         0x05
#define ISO14443B_ATTRIB       0x1D
#define ISO14443B_HALT         0x50
#define ISO14443B_INITIATE     0x06
#define ISO14443B_SELECT       0x0E
#define ISO14443B_GET_UID      0x0B
#define ISO14443B_READ_BLK     0x08
#define ISO14443B_WRITE_BLK    0x09
#define ISO14443B_RESET        0x0C
#define ISO14443B_COMPLETION   0x0F
#define ISO14443B_AUTHENTICATE 0x0A
#define ISO14443B_PING         0xBA
#define ISO14443B_PONG         0xAB

// ASK C-ticket
#define ASK_REQT               0x10
#define ASK_IDENTIFY           0x0F
#define ASK_SELECT             0x9F
#define ASK_MULTREAD           (0x1 << 4) // High nibble
#define ASK_UPDATE             (0x3 << 4) // High nibble
#define ASK_WRITE              (0x5 << 4) // High nibble
#define ASK_READ               (0x6 << 4) // High nibble
#define ASK_DESACTIVATE        0xF0


// defined crypto RF commands
// only interpreting channel 1 communication
#define CRYPTORF_SET_USER_ZONE      0x11
#define CRYPTORF_READ_USER_ZONE     0x12
#define CRYPTORF_WRITE_USER_ZONE    0x13
#define CRYPTORF_WRITE_SYSTEM_ZONE  0x14
#define CRYPTORF_READ_SYSTEM_ZONE   0x16
#define CRYPTORF_VERIFY_CRYPTO      0x18
#define CRYPTORF_SEND_CHECKSUM      0x19
#define CRYPTORF_DESELECT           0x1A
#define CRYPTORF_IDLE               0x1B
#define CRYPTORF_CHECK_PASSWORD     0x1C

// defined Crypto RF errors
#define CRYPTORF_ERR_ACCESS_DENIED_ZONE               0x99
#define CRYPTORF_ERR_PARAM_INVALID                    0xA1
#define CRYPTORF_ERR_ADDRES_INVALID                   0xA2
#define CRYPTORF_ERR_LENGTH_INVALID                   0xA3
#define CRYPTORF_ERR_AUTH_ENC_REQ                     0xA9
#define CRYPTORF_ERR_ACCESS_DENIED_WLOCK              0xB9
#define CRYPTORF_ERR_BYTE_ACCESS_DENIED_NOT_ALLOWED   0xBA
#define CRYPTORF_ERR_ACCESS_DENIED_NOT_ALLOWED        0xBA
#define CRYPTORF_ERR_BYTE_ACCESS_DENIED_PASSWD_REQ    0xBC
#define CRYPTORF_ERR_CHECKSUM_FAIL2                   0xC8
#define CRYPTORF_ERR_CHECKSUM_FAIL                    0xC9
#define CRYPTORF_ERR_PASSWD_REQ                       0xD9
#define CRYPTORF_ERR_FUSE_ACCESS_DENIED               0xDF
#define CRYPTORF_ERR_MODIFY_FORBIDDEN                 0xE9
#define CRYPTORF_ERR_ACCESS_DENIED_FUSE_ORDR          0xE9
#define CRYPTORF_ERR_MEMORY_WRITE_DATA_M              0xED
#define CRYPTORF_ERR_MEMORY_ACCESS                    0xEE
#define CRYPTORF_ERR_MEMORY_ACCESS_SEC                0xF9

//First byte is 26
#define ISO15693_INVENTORY     0x01
#define ISO15693_STAYQUIET     0x02
//First byte is 02
#define ISO15693_READBLOCK                   0x20
#define ISO15693_WRITEBLOCK                  0x21
#define ISO15693_LOCKBLOCK                   0x22
#define ISO15693_READ_MULTI_BLOCK            0x23
#define ISO15693_WRITE_MULTI_BLOCK           0x24
#define ISO15693_SELECT                      0x25
#define ISO15693_RESET_TO_READY              0x26
#define ISO15693_WRITE_AFI                   0x27
#define ISO15693_LOCK_AFI                    0x28
#define ISO15693_WRITE_DSFID                 0x29
#define ISO15693_LOCK_DSFID                  0x2A
#define ISO15693_GET_SYSTEM_INFO             0x2B
#define ISO15693_READ_MULTI_SECSTATUS        0x2C
// NXP/Philips custom commands
#define ISO15693_INVENTORY_READ              0xA0
#define ISO15693_FAST_INVENTORY_READ         0xA1
#define ISO15693_SET_EAS                     0xA2
#define ISO15693_RESET_EAS                   0xA3
#define ISO15693_LOCK_EAS                    0xA4
#define ISO15693_EAS_ALARM                   0xA5
#define ISO15693_PASSWORD_PROTECT_EAS        0xA6
#define ISO15693_WRITE_EAS_ID                0xA7
#define ISO15693_READ_EPC                    0xA8
#define ISO15693_GET_NXP_SYSTEM_INFO         0xAB
#define ISO15693_INVENTORY_PAGE_READ         0xB0
#define ISO15693_FAST_INVENTORY_PAGE_READ    0xB1
#define ISO15693_GET_RANDOM_NUMBER           0xB2
#define ISO15693_SET_PASSWORD                0xB3
#define ISO15693_WRITE_PASSWORD              0xB4
#define ISO15693_LOCK_PASSWORD               0xB5
#define ISO15693_PROTECT_PAGE                0xB6
#define ISO15693_LOCK_PAGE_PROTECTION        0xB7
#define ISO15693_GET_MULTI_BLOCK_PROTECTION  0xB8
#define ISO15693_DESTROY                     0xB9
#define ISO15693_ENABLE_PRIVACY              0xBA
#define ISO15693_64BIT_PASSWORD_PROTECTION   0xBB
#define ISO15693_STAYQUIET_PERSISTENT        0xBC
#define ISO15693_READ_SIGNATURE              0xBD

// Topaz command set:
#define TOPAZ_REQA                    0x26 // Request
#define TOPAZ_WUPA                    0x52 // WakeUp
#define TOPAZ_RID                     0x78 // Read ID
#define TOPAZ_RALL                    0x00 // Read All (all bytes)
#define TOPAZ_READ                    0x01 // Read (a single byte)
#define TOPAZ_WRITE_E                 0x53 // Write-with-erase (a single byte)
#define TOPAZ_WRITE_NE                0x1a // Write-no-erase (a single byte)
// additional commands for Dynamic Memory Model
#define TOPAZ_RSEG                    0x10 // Read segment
#define TOPAZ_READ8                   0x02 // Read (eight bytes)
#define TOPAZ_WRITE_E8                0x54 // Write-with-erase (eight bytes)
#define TOPAZ_WRITE_NE8               0x1B // Write-no-erase (eight bytes)

// Definitions of which protocol annotations there are available
#define ISO_14443A       0
#define ICLASS           1
#define ISO_14443B       2
#define TOPAZ            3
#define ISO_7816_4       4
#define MFDES            5
#define LEGIC            6
#define ISO_15693        7
#define FELICA           8
#define PROTO_MIFARE     9
#define PROTO_HITAG1    10
#define THINFILM        11
#define LTO             12
#define PROTO_HITAG2    13
#define PROTO_HITAGS    14
#define PROTO_CRYPTORF  15
#define SEOS            16
#define PROTO_MFPLUS    17

// Picopass fuses
#define FUSE_FPERS   0x80
#define FUSE_CODING1 0x40
#define FUSE_CODING0 0x20
#define FUSE_CRYPT1  0x10
#define FUSE_CRYPT0  0x08
#define FUSE_FPROD1  0x04
#define FUSE_FPROD0  0x02
#define FUSE_RA      0x01

// Picopass Pagemode fuses
#define PICOPASS_NON_SECURE_PAGEMODE 0x01
#define PICOPASS_SECURE_PAGEMODE     0x11


// ISO 7816-4 Basic interindustry commands. For command APDU's.
#define ISO7816_READ_BINARY             0xB0
#define ISO7816_WRITE_BINARY            0xD0
#define ISO7816_UPDATE_BINARY           0xD6
#define ISO7816_ERASE_BINARY            0x0E
#define ISO7816_READ_RECORDS            0xB2
#define ISO7816_WRITE_RECORDS           0xD2
#define ISO7816_APPEND_RECORD           0xE2
#define ISO7816_UPDATE_RECORD           0xDC
#define ISO7816_GET_DATA                0xCA
#define ISO7816_PUT_DATA                0xDA
#define ISO7816_SELECT_FILE             0xA4
#define ISO7816_VERIFY                  0x20
#define ISO7816_INTERNAL_AUTHENTICATION 0x88
#define ISO7816_EXTERNAL_AUTHENTICATION 0x82
#define ISO7816_GET_CHALLENGE           0x84
#define ISO7816_MANAGE_CHANNEL          0x70

#define ISO7816_GET_RESPONSE            0xC0

// ISO7816-4 For response APDU's
#define ISO7816_OK                              0x9000

// 6x xx = APDU ERROR CODES

// 61 xx
#define ISO7816_BYTES_REMAINING_00              0x6100 // Response bytes remaining

// 62 xx
#define ISO7816_WARNING_STATE_UNCHANGED         0x6200 // Warning, card state unchanged
#define ISO7816_DATA_CORRUPT                    0x6281 // Returned data may be corrupted
#define ISO7816_FILE_EOF                        0x6282 // The end of the file has been reached before the end of reading
#define ISO7816_INVALID_DF                      0x6283 // Invalid DF
#define ISO7816_INVALID_FILE                    0x6284 // Selected file is not valid
#define ISO7816_FILE_TERMINATED                 0x6285 // File is terminated

// 63 xx
#define ISO7816_AUTH_FAILED                     0x6300 // Authentification failed
#define ISO7816_FILE_FILLED                     0x6381 // File filled up by the last write

// 65 xx
#define ISO7816_MEMORY_FULL                     0x6501 // Memory failure
#define ISO7816_WRITE_MEMORY_ERR                0x6581 // Write problem / Memory failure / Unknown mode

// 67 xx
#define ISO7816_WRONG_LENGTH                    0x6700 // Wrong length

// 68 xx
#define ISO7816_LOGICAL_CHANNEL_NOT_SUPPORTED   0x6881 // Card does not support the operation on the specified logical channel
#define ISO7816_SECURE_MESSAGING_NOT_SUPPORTED  0x6882 // Card does not support secure messaging
#define ISO7816_LAST_COMMAND_EXPECTED           0x6883 // Last command in chain expected
#define ISO7816_COMMAND_CHAINING_NOT_SUPPORTED  0x6884 // Command chaining not supported

// 69 xx
#define ISO7816_TRANSACTION_FAIL                0x6900 // No successful transaction executed during session
#define ISO7816_SELECT_FILE_ERR                 0x6981 // Cannot select indicated file, command not compatible with file organization
#define ISO7816_SECURITY_STATUS_NOT_SATISFIED   0x6982 // Security condition not satisfied
#define ISO7816_FILE_INVALID                    0x6983 // File invalid
#define ISO7816_DATA_INVALID                    0x6984 // Data invalid
#define ISO7816_CONDITIONS_NOT_SATISFIED        0x6985 // Conditions of use not satisfied
#define ISO7816_COMMAND_NOT_ALLOWED             0x6986 // Command not allowed (no current EF)
#define ISO7816_SM_DATA_MISSING                 0x6987 // Expected SM data objects missing
#define ISO7816_SM_DATA_INCORRECT               0x6988 // SM data objects incorrect
#define ISO7816_APPLET_SELECT_FAILED            0x6999 // Applet selection failed

// 6A xx
#define ISO7816_INVALID_P1P2                    0x6A00 // Bytes P1 and/or P2 are invalid
#define ISO7816_WRONG_DATA                      0x6A80 // Wrong data
#define ISO7816_FUNC_NOT_SUPPORTED              0x6A81 // Function not supported
#define ISO7816_FILE_NOT_FOUND                  0x6A82 // File not found
#define ISO7816_RECORD_NOT_FOUND                0x6A83 // Record not found
#define ISO7816_FILE_FULL                       0x6A84 // Not enough memory space in the file
#define ISO7816_LC_TLV_CONFLICT                 0x6A85 // LC / TLV conlict
#define ISO7816_INCORRECT_P1P2                  0x6A86 // Incorrect parameters (P1,P2)
#define ISO7816_FILE_EXISTS                     0x6A89 // File exists
#define ISO7816_NOT_IMPLEMENTED                 0x6AFF //

// 6x 00
#define ISO7816_WRONG_P1P2                      0x6B00 // Incorrect parameters (P1,P2)
#define ISO7816_CORRECT_LENGTH_00               0x6C00 // Correct Expected Length (Le)
#define ISO7816_INS_NOT_SUPPORTED               0x6D00 // INS value not supported
#define ISO7816_CLA_NOT_SUPPORTED               0x6E00 // CLA value not supported
#define ISO7816_UNKNOWN                         0x6F00 // No precise diagnosis


// MIFARE DESFire command set:
#define MFDES_AUTHENTICATE               0x0A  // AUTHENTICATE_NATIVE
#define MFDES_AUTHENTICATE_ISO           0x1A  // AUTHENTICATE_STANDARD
#define MFDES_AUTHENTICATE_AES           0xAA

//  Leakage Resilient Primitive (LRP)
#define MFDES_AUTHENTICATE_EV2F          0x71  // LRP, AuthenticateLRPFirst
#define MFDES_AUTHENTICATE_EV2NF         0x77  // LRP, AuthenticateLRPNonFirst

#define MFDES_CREDIT                     0x0C
#define MFDES_LIMITED_CREDIT             0x1C
#define MFDES_WRITE_RECORD               0x3B
#define MFDES_READSIG                    0x3C
#define MFDES_WRITE_DATA                 0x3D
#define MFDES_GET_KEY_SETTINGS           0x45
#define MFDES_GET_UID                    0x51
#define MFDES_CHANGE_KEY_SETTINGS        0x54
#define MFDES_ROLL_KEY_SETTINGS          0x55
#define MFDES_INIT_KEY_SETTINGS          0x56
#define MFDES_FINALIZE_KEY_SETTINGS      0x57
#define MFDES_SELECT_APPLICATION         0x5A
#define MFDES_CHANGE_CONFIGURATION       0x5C
#define MFDES_CHANGE_FILE_SETTINGS       0x5F
#define MFDES_GET_VERSION                0x60
#define MFDES_GET_ISOFILE_IDS            0x61
#define MFDES_GET_KEY_VERSION            0x64
#define MFDES_GET_DELEGATE_INFO          0x69
#define MFDES_GET_APPLICATION_IDS        0x6A
#define MFDES_GET_VALUE                  0x6C
#define MFDES_GET_FREE_MEMORY            0x6E
#define MFDES_GET_DF_NAMES               0x6D
#define MFDES_GET_FILE_IDS               0x6F
#define MFDES_WRITE_RECORD2              0x8B
#define MFDES_WRITE_DATA2                0x8D
#define MFDES_ABORT_TRANSACTION          0xA7
#define MFDES_READ_RECORDS2              0xAB
#define MFDES_READ_DATA2                 0xAD
#define MFDES_ADDITIONAL_FRAME           0xAF
#define MFDES_UPDATE_RECORD2             0xBA
#define MFDES_READ_RECORDS               0xBB
#define MFDES_READ_DATA                  0xBD
#define MFDES_CREATE_CYCLIC_RECORD_FILE  0xC0
#define MFDES_CREATE_LINEAR_RECORD_FILE  0xC1
#define MFDES_CHANGE_KEY                 0xC4
#define MFDES_CHANGE_KEY_EV2             0xC6
#define MFDES_COMMIT_TRANSACTION         0xC7
#define MFDES_COMMIT_READER_ID           0xC8
#define MFDES_CREATE_DELEGATE_APP        0xC9
#define MFDES_CREATE_APPLICATION         0xCA
#define MFDES_CREATE_BACKUP_DATA_FILE    0xCB
#define MFDES_CREATE_VALUE_FILE          0xCC
#define MFDES_CREATE_STD_DATA_FILE       0xCD
#define MFDES_CREATE_TRANS_MAC_FILE      0xCE
#define MFDES_DELETE_APPLICATION         0xDA
#define MFDES_UPDATE_RECORD              0xDB
#define MFDES_DEBIT                      0xDC
#define MFDES_DELETE_FILE                0xDF
#define MFDES_CLEAR_RECORD_FILE          0xEB
#define MFDES_NOTIFY_TRANSACTION_SUCCESS 0xEE  // New command. Used by Apple-ECP-compliant DESFire readers to signify successful transaction
#define MFDES_PREPARE_PC                 0xF0
#define MFDES_PROXIMITY_CHECK            0xF2
#define MFDES_GET_FILE_SETTINGS          0xF5
#define MFDES_FORMAT_PICC                0xFC
#define MFDES_VERIFY_PC                  0xFD
#define MFDES_NATIVE_ISO7816_WRAP_CLA    0x90


// MIFARE DESFire status & error codes:
#define MFDES_S_OPERATION_OK             0x00
#define MFDES_S_NO_CHANGES               0x0C
#define MFDES_S_SIGNATURE                0x90
#define MFDES_S_ADDITIONAL_FRAME         0xAF

#define MFDES_E_OUT_OF_EEPROM            0x0E
#define MFDES_E_ILLEGAL_COMMAND_CODE     0x1C
#define MFDES_E_INTEGRITY_ERROR          0x1E
#define MFDES_E_NO_SUCH_KEY              0x40
#define MFDES_E_LENGTH                   0x7E
#define MFDES_E_PERMISSION_DENIED        0x9D
#define MFDES_E_PARAMETER_ERROR          0x9E
#define MFDES_E_APPLICATION_NOT_FOUND    0xA0
#define MFDES_E_APPL_INTEGRITY           0xA1
#define MFDES_E_AUTHENTICATION_ERROR     0xAE
#define MFDES_E_BOUNDARY                 0xBE
#define MFDES_E_PICC_INTEGRITY           0xC1
#define MFDES_E_COMMAND_ABORTED          0xCA
#define MFDES_E_PICC_DISABLED            0xCD
#define MFDES_E_COUNT                    0xCE
#define MFDES_E_DUPLICATE                0xDE
#define MFDES_E_EEPROM                   0xEE
#define MFDES_E_FILE_NOT_FOUND           0xF0
#define MFDES_E_FILE_INTEGRITY           0xF1


// MIFARE PLus EV2 Command set
// source: https://www.nxp.com/docs/en/data-sheet/MF1P(H)x2.pdf in Look-Up Tables

#define MFP_READ_SIG                    0x3C // same as DESFIRE
#define MFP_WRITEPERSO                  0xA8
#define MFP_COMMITPERSO                 0xAA

#define MFP_AUTHENTICATEFIRST           0x70
#define MFP_AUTHENTICATEFIRST_VARIANT   0x73
#define MFP_AUTHENTICATENONFIRST        0x76
#define MFP_AUTHENTICATECONTINUE        0x72
#define MFP_AUTHENTICATESECTORSWITCH    0x7A
#define MFP_RESETAUTH                   0x78

#define MFP_VCSUPPORTLASTISOL3          0x4B
#define MFP_ISOSELECT                   0xA4

#define MFP_GETVERSION                  0x60 // same as DESFIRE
#define MFP_ADDITIONALFRAME             0xAF
#define MFP_SETCONFIGSL1                0x44
#define MFP_MF_PERSONALIZEUIDUSAGE      0x40

// read commands
#define MFP_READENCRYPTEDNOMAC_MACED    0X30
#define MFP_READENCRYPTEDMAC_MACED      0x31
#define MFP_READPLAINNOMAC_MACED        0x32
#define MFP_READPLAINMAC_MACED          0x33
#define MFP_READENCRYPTEDNOMAC_UNMACED  0x34
#define MFP_READENCRYPTEDMAC_UNMACED    0X35
#define MFP_READPLAINNOMAC_UNMACED      0x36
#define MFP_READPLAINMAC_UNMACED        0x37

// write commands
#define MFP_WRITEENCRYPTEDNOMAC         0xA0
#define MFP_WRITEENCRYPTEDMAC           0xA1
#define MFP_WRITEPLAINNOMAC             0xA2
#define MFP_WRITEPLAINMAC               0xA3

// value commands
#define MFP_INCREMENTNOMAC              0xB0
#define MFP_INCREMENTMAC                0xB1
#define MFP_DECREMENTNOMAC              0xB2
#define MFP_DECREMENTMAC                0xB3
#define MFP_TRANSFERNOMAC               0xB4
#define MFP_TRANSFERMAC                 0xB5
#define MFP_INCREMENTTRANSFERNOMAC      0xB6
#define MFP_INCREMENTTRANSFERMAC        0xB7
#define MFP_DECREMENTTRANSFERNOMAC      0xB8
#define MFP_DECREMENTTRANSFERMAC        0xB9
#define MFP_RESTORENOMAC                0xC2
#define MFP_RESTOREMAC                  0xC3


// LEGIC Commands
#define LEGIC_MIM_22                    0x0D
#define LEGIC_MIM_256                   0x1D
#define LEGIC_MIM_1024                  0x3D
#define LEGIC_ACK_22                    0x19
#define LEGIC_ACK_256                   0x39
#define LEGIC_READ                      0x01
#define LEGIC_WRITE                     0x00

/* T55x7 configuration register definitions */
#define T55x7_POR_DELAY                 0x00000001
#define T55x7_ST_TERMINATOR             0x00000008
#define T55x7_PWD                       0x00000010
#define T55x7_MAXBLOCK_SHIFT            5
#define T55x7_AOR                       0x00000200
#define T55x7_PSKCF_RF_2                0
#define T55x7_PSKCF_RF_4                0x00000400
#define T55x7_PSKCF_RF_8                0x00000800
#define T55x7_MODULATION_DIRECT         0
#define T55x7_MODULATION_PSK1           0x00001000
#define T55x7_MODULATION_PSK2           0x00002000
#define T55x7_MODULATION_PSK3           0x00003000
#define T55x7_MODULATION_FSK1           0x00004000
#define T55x7_MODULATION_FSK2           0x00005000
#define T55x7_MODULATION_FSK1a          0x00006000
#define T55x7_MODULATION_FSK2a          0x00007000
#define T55x7_MODULATION_MANCHESTER     0x00008000
#define T55x7_MODULATION_BIPHASE        0x00010000
#define T55x7_MODULATION_DIPHASE        0x00018000
#define T55x7_X_MODE                    0x00020000
#define T55x7_BITRATE_RF_8              0
#define T55x7_BITRATE_RF_16             0x00040000
#define T55x7_BITRATE_RF_32             0x00080000
#define T55x7_BITRATE_RF_40             0x000C0000
#define T55x7_BITRATE_RF_50             0x00100000
#define T55x7_BITRATE_RF_64             0x00140000
#define T55x7_BITRATE_RF_100            0x00180000
#define T55x7_BITRATE_RF_128            0x001C0000
#define T55x7_TESTMODE_DISABLED         0x60000000

/* T5555 (Q5) configuration register definitions */
#define T5555_ST_TERMINATOR             0x00000001
#define T5555_MAXBLOCK_SHIFT            0x00000001
#define T5555_MODULATION_MANCHESTER     0
#define T5555_MODULATION_PSK1           0x00000010
#define T5555_MODULATION_PSK2           0x00000020
#define T5555_MODULATION_PSK3           0x00000030
#define T5555_MODULATION_FSK1           0x00000040
#define T5555_MODULATION_FSK2           0x00000050
#define T5555_MODULATION_BIPHASE        0x00000060
#define T5555_MODULATION_DIRECT         0x00000070
#define T5555_INVERT_OUTPUT             0x00000080
#define T5555_PSK_RF_2                  0
#define T5555_PSK_RF_4                  0x00000100
#define T5555_PSK_RF_8                  0x00000200
#define T5555_USE_PWD                   0x00000400
#define T5555_USE_AOR                   0x00000800
#define T5555_SET_BITRATE(x)            (((x-2)/2)<<12)
#define T5555_GET_BITRATE(x)            ((((x >> 12) & 0x3F)*2)+2)
#define T5555_BITRATE_SHIFT             12 //(RF=2n+2)   ie 64=2*0x1F+2   or n = (RF-2)/2
#define T5555_FAST_WRITE                0x00004000
#define T5555_PAGE_SELECT               0x00008000
#define T5555_FIXED                     0x60000000

#define T55XX_WRITE_TIMEOUT 1500

// em4x05 & em4x69 chip configuration register definitions
#define EM4x05_GET_BITRATE(x)           ((((x) & 0x3F) * 2) + 2)
// Note: only data rates 8, 16, 32, 40(*) and 64 are supported. (*) only with EM4305 330pF
#define EM4x05_SET_BITRATE(x)           (((x) - 2) / 2)
#define EM4x05_MODULATION_NRZ           0x00000000
#define EM4x05_MODULATION_MANCHESTER    0x00000040
#define EM4x05_MODULATION_BIPHASE       0x00000080
#define EM4x05_MODULATION_MILLER        0x000000C0 //not supported by all 4x05/4x69 chips
#define EM4x05_MODULATION_PSK1          0x00000100 //not supported by all 4x05/4x69 chips
#define EM4x05_MODULATION_PSK2          0x00000140 //not supported by all 4x05/4x69 chips
#define EM4x05_MODULATION_PSK3          0x00000180 //not supported by all 4x05/4x69 chips
#define EM4x05_MODULATION_FSK1          0x00000200 //not supported by all 4x05/4x69 chips
#define EM4x05_MODULATION_FSK2          0x00000240 //not supported by all 4x05/4x69 chips
#define EM4x05_PSK_RF_2                 0
#define EM4x05_PSK_RF_4                 0x00000400
#define EM4x05_PSK_RF_8                 0x00000800
#define EM4x05_MAXBLOCK_SHIFT           14
#define EM4x05_FIRST_USER_BLOCK         5
#define EM4x05_SET_NUM_BLOCKS(x)        (( (x) + 4) << 14) //# of blocks sent during default read mode
#define EM4x05_GET_NUM_BLOCKS(x)        ((( (x) >> 14) & 0xF) - 4)
#define EM4x05_READ_LOGIN_REQ           (1 << 18)
#define EM4x05_READ_HK_LOGIN_REQ        (1 << 19)
#define EM4x05_WRITE_LOGIN_REQ          (1 << 20)
#define EM4x05_WRITE_HK_LOGIN_REQ       (1 << 21)
#define EM4x05_READ_AFTER_WRITE         (1 << 22)
#define EM4x05_DISABLE_ALLOWED          (1 << 23)
#define EM4x05_READER_TALK_FIRST        (1 << 24)
#define EM4x05_INVERT                   (1 << 25)
#define EM4x05_PIGEON                   (1 << 26)


// FeliCa protocol
#define FELICA_POLL_REQ                 0x00
#define FELICA_POLL_ACK                 0x01

#define FELICA_REQSRV_REQ               0x02
#define FELICA_REQSRV_ACK               0x03

#define FELICA_REQRESP_REQ              0x04
#define FELICA_REQRESP_ACK              0x05

#define FELICA_RDBLK_REQ                0x06
#define FELICA_RDBLK_ACK                0x07

#define FELICA_WRTBLK_REQ               0x08
#define FELICA_WRTBLK_ACK               0x09

#define FELICA_SRCHSYSCODE_REQ          0x0a
#define FELICA_SRCHSYSCODE_ACK          0x0b

#define FELICA_REQSYSCODE_REQ           0x0c
#define FELICA_REQSYSCODE_ACK           0x0d

#define FELICA_AUTH1_REQ                0x10
#define FELICA_AUTH1_ACK                0x11

#define FELICA_AUTH2_REQ                0x12
#define FELICA_AUTH2_ACK                0x13

#define FELICA_RDSEC_REQ                0x14
#define FELICA_RDSEC_ACK                0x15

#define FELICA_WRTSEC_REQ               0x16
#define FELICA_WRTSEC_ACK               0x17

#define FELICA_REQSRV2_REQ              0x32
#define FELICA_REQSRV2_ACK              0x33

#define FELICA_GETSTATUS_REQ            0x38
#define FELICA_GETSTATUS_ACK            0x39

#define FELICA_OSVER_REQ                0x3c
#define FELICA_OSVER_ACK                0x3d

#define FELICA_RESET_MODE_REQ           0x3e
#define FELICA_RESET_MODE_ACK           0x3f

#define FELICA_AUTH1V2_REQ              0x40
#define FELICA_AUTH1V2_ACK              0x41

#define FELICA_AUTH2V2_REQ              0x42
#define FELICA_AUTH2V2_ACK              0x43

#define FELICA_RDSECV2_REQ              0x44
#define FELICA_RDSECV2_ACK              0x45
#define FELICA_WRTSECV2_REQ             0x46
#define FELICA_WRTSECV2_ACK             0x47

#define FELICA_UPDATE_RNDID_REQ         0x4C
#define FELICA_UPDATE_RNDID_ACK         0x4D

// FeliCa SYSTEM list
#define SYSTEMCODE_ANY                  0xffff // ANY
#define SYSTEMCODE_FELICA_LITE          0x88b4 // FeliCa Lite
#define SYSTEMCODE_COMMON               0xfe00 // Common
#define SYSTEMCODE_EDY                  0xfe00 // Edy
#define SYSTEMCODE_CYBERNE              0x0003 // Cyberne
#define SYSTEMCODE_SUICA                0x0003 // Suica
#define SYSTEMCODE_PASMO                0x0003 // Pasmo

//FeliCa Service list Suica/pasmo (little endian)
#define SERVICE_SUICA_INOUT             0x108f // SUICA/PASMO
#define SERVICE_SUICA_HISTORY           0x090f // SUICA/PASMO
#define SERVICE_FELICA_LITE_READONLY    0x0b00 // FeliCa Lite RO
#define SERVICE_FELICA_LITE_READWRITE   0x0900 // FeliCa Lite RW

// Calypso protocol
#define CALYPSO_GET_RESPONSE            0xC0
#define CALYPSO_SELECT                  0xA4
#define CALYPSO_INVALIDATE              0x04
#define CALYPSO_REHABILITATE            0x44
#define CALYPSO_APPEND_RECORD           0xE2
#define CALYPSO_DECREASE                0x30
#define CALYPSO_INCREASE                0x32
#define CALYPSO_READ_BINARY             0xB0
#define CALYPSO_READ_RECORD             0xB2
#define CALYPSO_UPDATE_BINARY           0xD6
#define CALYPSO_UPDATE_RECORD           0xDC
#define CALYPSO_WRITE_RECORD            0xD2
#define CALYPSO_OPEN_SESSION            0x8A
#define CALYPSO_CLOSE_SESSION           0x8E
#define CALYPSO_GET_CHALLENGE           0x84
#define CALYPSO_CHANGE_PIN              0xD8
#define CALYPSO_VERIFY_PIN              0x20
#define CALYPSO_SV_GET                  0x7C
#define CALYPSO_SV_DEBIT                0xBA
#define CALYPSO_SV_RELOAD               0xB8
#define CALYPSO_SV_UN_DEBIT             0xBC
#define CALYPSO_SAM_SV_DEBIT            0x54
#define CALYPSO_SAM_SV_RELOAD           0x56

// HITAG1 commands
#define HITAG1_SET_CCNEW                0xC2    // left 5 bits only
#define HITAG1_READ_ID                  0x00    // not a real command, consists of 5 bits length, <length> bits partial SN, 8 bits CRC
#define HITAG1_SELECT                   0x00    // left 5 bits only, followed by 32 bits SN and 8 bits CRC
#define HITAG1_WRPPAGE                  0x80    // left 4 bits only, followed by 8 bits page and 8 bits CRC
#define HITAG1_WRPBLK                   0x90    // left 4 bits only, followed by 8 bits block and 8 bits CRC
#define HITAG1_WRCPAGE                  0xA0    // left 4 bits only, followed by 8 bits page or key information and 8 bits CRC
#define HITAG1_WRCBLK                   0xB0    // left 4 bits only, followed by 8 bits block and 8 bits CRC
#define HITAG1_RDPPAGE                  0xC0    // left 4 bits only, followed by 8 bits page and 8 bits CRC
#define HITAG1_RDPBLK                   0xD0    // left 4 bits only, followed by 8 bits block and 8 bits CRC
#define HITAG1_RDCPAGE                  0xE0    // left 4 bits only, followed by 8 bits page and 8 bits CRC
#define HITAG1_RDCBLK                   0xF0    // left 4 bits only, followed by 8 bits block and 8 bits CRC
#define HITAG1_HALT                     0x70    // left 4 bits only, followed by 8 bits (dummy) page and 8 bits CRC

// HITAG2 commands
#define HITAG2_START_AUTH               0x3    // left 5 bits only
#define HITAG2_HALT                     0x0    // left 5 bits only

#define HITAG2_READ_PAGE                0x3    // page number in bits 5 to 3, page number inverted in bit 0 and following 2 bits
#define HITAG2_READ_PAGE_INVERTED       0x1    // page number in bits 5 to 3, page number inverted in bit 0 and following 2 bits
#define HITAG2_WRITE_PAGE               0x2   // page number in bits 5 to 3, page number


// HITAG S commands
#define HITAGS_QUIET                    0x70
//inverted in bit 0 and following 2 bits
#define HITAGS_WRITE_BLOCK              0x90

// LTO-CM commands
#define LTO_REQ_STANDARD                0x45
#define LTO_REQ_ALL                     0x4A
#define LTO_READWORD                    0x40   // read 2 bytes (word)
#define LTO_READBLOCK                   0x30
#define LTO_READBLOCK_CONT              0x80
#define LTO_SELECT                      0x93
#define LTO_WRITEWORD                   0xB0   // write 2 bytes (word)
#define LTO_WRITEBLOCK                  0xA0
#define LTO_HALT                        0x50
#define LTO_TEST_CMD_1                  0x0E
#define LTO_TEST_CMD_2                  0x6C

// 0x0A = ACK
// 0x05 = NACK

#endif
// PROTOCOLS_H
