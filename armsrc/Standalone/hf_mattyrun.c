//-----------------------------------------------------------------------------
// Copyright (C) Matías A. Ré Medina 2016
// Copyright (C) Michael Roland 2024
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
// main code for HF MIFARE Classic chk/ecfill/sim aka MattyRun
//-----------------------------------------------------------------------------

#include <inttypes.h>

#include "appmain.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "iso14443a.h"
#include "mifarecmd.h"
#include "mifaresim.h"  // mifare1ksim
#include "mifareutil.h"
#include "proxmark3_arm.h"
#include "standalone.h" // standalone definitions
#include "string.h"
#include "ticks.h"
#include "util.h"

/* 
 * `hf_mattyrun` tries to dump MIFARE Classic cards into emulator memory and emulates them.
 * 
 * This standalone mode uses a predefined dictionary (originally taken from
 * mfc_default_keys.dic) to authenticate to MIFARE Classic cards (cf. `hf mf chk`)
 * and to dump the card into emulator memory (cf. `hf mf ecfill`). Once a card has
 * been dumped, the card is emulated (cf. `hf mf sim`). Emulation will start even if
 * only a partial dump could be retrieved from the card (e.g. due to missing keys).
 * 
 * This standalone mode is specifically designed for devices without flash. However,
 * users can pass data to/from the standalone mode through emulator memory (assuming
 * continuous (battery) power supply):
 * 
 * - Keys can be added to the dictionary by loading them into the emulator before
 *   starting the standalone mode. You can use `hf mf eload -f dump_file` to load
 *   any existing card dump. All keys from the key slots in the sector trailers
 *   are added to the dictionary. Note that you can fill both keys in all sector
 *   trailers available for a 4K card to store your user dictionary. Sector and key
 *   type are ignored during chk; all user keys will be tested for all sectors and
 *   for both key types.
 * 
 * - Once a card has been cloned into emulator memory, you can extract the dump by
 *   ending the standalone mode and retrieving the emulator memory (`hf mf eview`
 *   or `hf mf esave [--mini|--1k|--2k|--4k] -f dump_file`).
 * 
 * This standalone mode will log status information via USB. In addition, the LEDs
 * display status information:
 * 
 * - Waiting for card: LED C is on, LED D blinks.
 * - Tying to authenticate: LED C and D are on; LED D will blink on errors.
 * - Nested attack (NOT IMPLEMENTED!): LED B is on.
 * - Loading card data into emulator memory: LED B and C are on.
 * - Starting emulation: LED A, B, and C are on. LED D is on if only a partial
 *   dump is available.
 * - Emulation started: All LEDS are off.
 * 
 * You can use the user button to interact with the standalone mode. During
 * emulation, (short) pressing the button ends emulation and returns to card
 * discovery. Long pressing the button ends the standalone mode.
 * 
 * Developers can configure the behavior of the standalone mode through the below
 * constants:
 * 
 * - MATTYRUN_PRINT_KEYS: Activate display of actually used key dictionary on startup.
 * - MATTYRUN_NO_ECFILL: Do not load and emulate card (only discovered keys are stored).
 * - MATTYRUN_MFC_DEFAULT_KEYS: Compiled-in default dictionary (originally taken from
 *   mfc_default_keys.dic). You can add your customized dictionaries here.
 * - MATTYRUN_MFC_ESSENTIAL_KEYS: Compiled-in dictionary of keys that should be tested
 *   before any user dictionary.
 * 
 * This is a major rewrite of the original `hf_mattyrun` by Matías A. Ré Medina.
 * The original version is described [here](http://bit.ly/2c9nZXR) (in Spanish).
 */

// Pseudo-configuration block
static bool const MATTYRUN_PRINT_KEYS = false; // Print assembled key dictionary on startup.
static bool const MATTYRUN_NO_ECFILL = false;  // Do not load and emulate card.

// Key flags
// TODO: Do we want to add flags to mark keys to be tested only as key A / key B?
static uint64_t const MATTYRUN_MFC_KEY_BITS = 0x00FFFFFFFFFFFF;
static uint64_t const MATTYRUN_MFC_KEY_FLAG_UNUSED = 0x10000000000000;

// Set of priority keys to be used
static uint64_t const MATTYRUN_MFC_ESSENTIAL_KEYS[] = {
    0xFFFFFFFFFFFF,  // Default key
    0x000000000000,  // Blank key
    0xA0A1A2A3A4A5,  // MAD key
    0x5C8FF9990DA2,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 A
    0x75CCB59C9BED,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 A
    0xD01AFEEB890A,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 B
    0x4B791BEA7BCC,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 B
    0xD3F7D3F7D3F7,  // AN1305 MIFARE Classic as NFC Type MIFARE Classic Tag Public Key A
};

// Set of standard keys to be used (originally taken from mfc_default_keys.dic)
// TODO: How to automate assembling these keys from mfc_default_keys.dic directly at compile-time?
static uint64_t const MATTYRUN_MFC_DEFAULT_KEYS[] = {
    // Default key
    0xFFFFFFFFFFFF,
    // Blank key
    0x000000000000,
    // MAD key
    0xA0A1A2A3A4A5,
    // MAD access key A (reversed)
    0xA5A4A3A2A1A0,
    // MAD access key B
    0x89ECA97F8C2A,
    // Mifare 1k EV1 (S50) hidden blocks, Signature data
    // 16 A
    0x5C8FF9990DA2,
    // 17 A
    0x75CCB59C9BED,
    // 16 B
    0xD01AFEEB890A,
    // 17 B
    0x4B791BEA7BCC,
    // QL88 keys 17 A/B
    0x2612C6DE84CA,
    0x707B11FC1481,
    // QL88 diversifed
    0x03F9067646AE,
    0x2352C5B56D85,
    // 
    0xB0B1B2B3B4B5,
    0xC0C1C2C3C4C5,
    0xD0D1D2D3D4D5,
    0xAABBCCDDEEFF,
    0x4D3A99C351DD,
    0x1A982C7E459A,
    // AN1305 MIFARE Classic as NFC Type MIFARE Classic Tag Public Key A
    0xD3F7D3F7D3F7,
    // key B Wien
    0x5A1B85FCE20A,
    // 
    0x714C5C886E97,
    0x587EE5F9350F,
    0xA0478CC39091,
    0x533CB6C723F6,
    0x8FD0A4F256E9,
    // iCopy-X
    0xE00000000000,
    // 
    0xE7D6064C5860,
    0xB27CCAB30DBD,
    // lib / Nat Bieb
    0xD2ECE8B9395E,
    // NSCP default key
    0x1494E81663D7,
    // NFC tools
    0x7c9fb8474242,
    // Kiev keys
    0x569369C5A0E5,
    0x632193BE1C3C,
    0x644672BD4AFE,
    0x8FE644038790,
    0x9DE89E070277,
    0xB5FF67CBA951,
    0xEFF603E1EFE9,
    0xF14EE7CAE863,
    // ICT S14 A/B
    0x9C28A60F7249,
    0xC9826AF02794,
    // RKF
    // Västtrafiken KeyA, RKF ÖstgötaTrafiken KeyA
    0xFC00018778F7,
    // Västtrafiken KeyA
    0x0297927C0F77,
    0x54726176656C,
    // Västtrafiken KeyB
    0x00000FFE2488,
    0x776974687573,
    0xEE0042F88840,
    // RKF SLKeyA
    0x26940B21FF5D,
    0xA64598A77478,
    // RKF SLKeyB
    0x5C598C9C58B5,
    0xE4D2770A89BE,
    // RKF Rejskort Danmark KeyA
    0x722BFCC5375F,
    // RKF Rejskort Danmark KeyB
    0xF1D83F964314,
    // RKF JOJOPRIVA KeyA
    0x505249564141,
    // RKF JOJOPRIVA KeyB
    0x505249564142,
    // RKF JOJOGROUP KeyA
    0x47524F555041,
    0x434F4D4D4F41,
    // RKF JOJOGROUP KeyB
    0x47524F555042,
    0x434F4D4D4F42,
    // TNP3xxx
    0x4B0B20107CCB,
    // Access control system
    0x605F5E5D5C5B,
    // NSP Global keys A and B (uk housing access control)
    0x199404281970,
    0x199404281998,
    // Data from http://www.proxmark.org/forum/viewtopic.php?pid=25925#p25925
    // Tengo Cards Key A
    0xFFF011223358,
    0xFF9F11223358,
    // Elevator system Kherson, Ukraine
    0xAC37E76385F5,
    0x576DCFFF2F25,
    // Car wash system
    0x1EE38419EF39,
    0x26578719DCD9,
    // more Keys from mfc_default_keys.lua
    0x000000000001,
    0x000000000002,
    0x00000000000A,
    0x00000000000B,
    0x010203040506,
    0x0123456789AB,
    0x100000000000,
    0x111111111111,
    0x123456789ABC,
    0x12F2EE3478C1,
    0x14D446E33363,
    0x1999A3554A55,
    0x200000000000,
    0x222222222222,
    0x27DD91F1FCF1,
    // Hotel system
    0x505209016A1F,
    // Directory and eventlog KeyB
    0x2BA9621E0A36,
    // Directory and eventlog KeyA
    0x4AF9D7ADEBE4,
    // 
    0x333333333333,
    0x33F974B42769,
    0x34D1DF9934C5,
    0x43AB19EF5C31,
    0x444444444444,
    0x505249565441,
    0x505249565442,
    0x555555555555,
    0x55F5A5DD38C9,
    0x666666666666,
    0x777777777777,
    0x888888888888,
    0x999999999999,
    0x99C636334433,
    0xA00000000000,
    0xA053A292A4AF,
    0xA94133013401,
    0xAAAAAAAAAAAA,
    // Key from ladyada.net
    0xABCDEF123456,
    // 
    0xB00000000000,
    0xB127C6F41436,
    0xBBBBBBBBBBBB,
    0xBD493A3962B6,
    0xC934FE34D934,
    0xCCCCCCCCCCCC,
    0xDDDDDDDDDDDD,
    0xEEEEEEEEEEEE,
    // elevator
    // data from forum
    0xFFFFFF545846,
    // 
    0xF1A97341A9FC,
    // hotel system
    0x44AB09010845,
    0x85FED980EA5A,
    // ARD (fr) key A
    0x43454952534E,
    // ARD (fr) key B
    0x4A2B29111213,
    // 
    0x4143414F5250,
    // Tehran Railway
    0xA9B43414F585,
    0x1FB235AC1388,
    // Data from http://irq5.io/2013/04/13/decoding-bcard-conference-badges/
    // BCARD KeyB
    0xF4A9EF2AFC6D,
    // S0 B
    0x89EAC97F8C2A,
    // S4 A
    0x43C7600DEE6B,
    // S6 A
    0x0120BF672A64,
    // S6 B
    0xFB0B20DF1F34,
    // 
    0xA9F953DEF0A3,
    // Data from forum
    0x74A386AD0A6D,
    0x3F7A5C2DBD81,
    0x21EDF95E7433,
    0xC121FF19F681,
    0x3D5D9996359A,
    // Here be BIP keys...
    0x3A42F33AF429,
    0x1FC235AC1309,
    0x6338A371C0ED,
    0x243F160918D1,
    0xF124C2578AD0,
    0x9AFC42372AF1,
    0x32AC3B90AC13,
    0x682D401ABB09,
    0x4AD1E273EAF1,
    0x067DB45454A9,
    0xE2C42591368A,
    0x15FC4C7613FE,
    0x2A3C347A1200,
    0x68D30288910A,
    0x16F3D5AB1139,
    0xF59A36A2546D,
    0x937A4FFF3011,
    0x64E3C10394C2,
    0x35C3D2CAEE88,
    0xB736412614AF,
    0x693143F10368,
    0x324F5DF65310,
    0xA3F97428DD01,
    0x643FB6DE2217,
    0x63F17A449AF0,
    0x82F435DEDF01,
    0xC4652C54261C,
    0x0263DE1278F3,
    0xD49E2826664F,
    0x51284C3686A6,
    0x3DF14C8000A1,
    0x6A470D54127C,
    // Data from http://pastebin.com/AK9Bftpw
    // Länstrafiken i Västerbotten
    0x48FFE71294A0,
    0xE3429281EFC1,
    0x16F21A82EC84,
    0x460722122510,
    // 3dprinter
    // EPI Envisionte
    0xAAFB06045877,
    // gym
    // Fysiken A
    0x3E65E4FB65B3,
    // Fysiken B
    0x25094DF6F148,
    // https://mattionline.de/fitnessstudio-armband-reverse-engineering/
    // https://mattionline.de/milazycracker/
    // gym wistband A, same as Fysiken A
    // gym wistband B
    0x81CC25EBBB6A,
    0x195DC63DB3A3,
    // CleverFit
    0xA05DBD98E0FC,
    // GoFit
    0xAA4DDA458EBB,
    0xEAB8066C7479,
    // Nordic Wellness A, same as Fysiken A
    // Nordic Wellness B
    0xE5519E1CC92B,
    // Hotel KeyCard
    0xD3B595E9DD63,
    0xAFBECD121004,
    // SimonsVoss
    0x6471A5EF2D1A,
    // ID06
    0x4E3552426B32,
    0x22BDACF5A33F,
    0x6E7747394E63,
    0x763958704B78,
    // Onity  S1 A/B
    0x8A19D40CF2B5,
    // 24-7
    0xD21762B2DE3B,
    0x0E83A374B513,
    0x1F1FFE000000,
    0xA10F303FC879,
    0x1322285230B8,
    0x0C71BCFB7E72,
    0xC3C88C6340B8,
    0xF101622750B7,
    0x1F107328DC8D,
    0x710732200D34,
    0x7C335FB121B5,
    0xB39AE17435DC,
    // key A
    0x454841585443,
    // Lift system
    0x190819842023,
    // Data from http://pastebin.com/gQ6nk38G
    0xD39BB83F5297,
    0x85675B200017,
    0x528C9DFFE28C,
    0xC82EC29E3235,
    0x3E3554AF0E12,
    0x491CDCFB7752,
    0x22C1BAE1AACD,
    0x5F146716E373,
    0x740E9A4F9AAF,
    0xAC0E24C75527,
    0x97184D136233,
    0xE444D53D359F,
    0x17758856B182,
    0xA8966C7CC54B,
    0xC6AD00254562,
    0xAE3FF4EEA0DB,
    0x5EB8F884C8D1,
    0xFEE470A4CB58,
    0x75D8690F21B6,
    0x871B8C085997,
    0x97D1101F18B0,
    0x75EDE6A84460,
    0xDF27A8F1CB8E,
    0xB0C9DD55DD4D,
    // Data from http://bit.ly/1bdSbJl
    0xA0B0C0D0E0F0,
    0xA1B1C1D1E1F1,
    // Data from msk social
    0x2735FC181807,
    0x2ABA9519F574,
    0x84FD7F7A12B6,
    0x186D8C4B93F9,
    0x3A4BBA8ADAF0,
    0x8765B17968A2,
    0x40EAD80721CE,
    0x0DB5E6523F7C,
    0x51119DAE5216,
    0x83E3549CE42D,
    0x136BDB246CAC,
    0x7DE02A7F6025,
    0xBF23A53C1F63,
    0xCB9A1F2D7368,
    0xC7C0ADB3284F,
    0x9F131D8C2057,
    0x67362D90F973,
    0x6202A38F69E2,
    0x100533B89331,
    0x653A87594079,
    0xD8A274B2E026,
    0xB20B83CB145C,
    0x9AFA6CB4FC3D,
    0xA229E68AD9E5,
    0x49C2B5296EF4,
    // Data from http://pastebin.com/RRJUEDCM
    0x0D258FE90296,
    0xE55A3CA71826,
    0xA4F204203F56,
    0xEEB420209D0C,
    0x911E52FD7CE4,
    0x752FBB5B7B45,
    0x66B03ACA6EE9,
    0x48734389EDC3,
    0x17193709ADF4,
    0x1ACC3189578C,
    0xC2B7EC7D4EB1,
    0x369A4663ACD2,
    // Data from https://github.com/zhangjingye03/zxcardumper
    // zxcard Key A/B
    0x668770666644,
    0x003003003003,
    // Data from http://phreakerclub.com/forum/showthread.php?p=41266
    0x26973EA74321,
    0x71F3A315AD26,
    0x51044EFB5AAB,
    0xAC70CA327A04,
    0xEB0A8FF88ADE,
    // Transport system Metromoney
    0x2803BCB0C7E1,
    0x9C616585E26D,
    0x4FA9EB49F75E,
    0x2DADE48942C5,
    0xA160FCD5EC4C,
    0x112233445566,
    0x361A62F35BC9,
    // Transport system Spain
    0x83F3CB98C258,
    0x070D486BC555,
    0xA9B018868CC1,
    0x9DCDB136110C,
    0x749934CC8ED3,
    0x506DB955F161,
    0xF088A85E71D7,
    0x72B458D60363,
    0x70C714869DC7,
    0xB32464412EE3,
    0xF253C30568C4,
    0x1C68315674AC,
    0xCFE63749080A,
    0xC1E6F8AFC9EC,
    0xDD0DE3BA08A6,
    0x3D923EB73534,
    0xFF94F86B09A6,
    0xD61707FFDFB1,
    0x8223205047B6,
    0x9951A273DEE7,
    0xC9449301AF93,
    0x66695A45C9FA,
    0x89AA9D743812,
    0xC41514DEFC07,
    0xC52876869800,
    0x5353B3AECB53,
    0x2E4169A5C79D,
    0x4BB747E48C2A,
    0x6285A1C8EB5C,
    0x5145C34DBA19,
    0x25352912CD8D,
    0x81B20C274C3F,
    0x00B70875AF1D,
    0x04B787B2F3A5,
    0x05412723F1B6,
    0x05C301C8795A,
    0x066F5AF3CCEE,
    0x0A1B6C50E04E,
    0x0AD0956DF6EE,
    0x0AD6B7E37183,
    0x0F3A4D48757B,
    0x1417E5671417,
    0x18AB07270506,
    0x18E887D625B4,
    0x1ABC15934F5A,
    0x1AF66F83F5BE,
    0x260480290483,
    0x2900AAC52BC3,
    0x2910AFE15C99,
    0x374521A38BCC,
    0x3A4C47757B07,
    0x3A524B7A7B37,
    0x3C4ABB877EAF,
    0x3F3A534B7B7B,
    0x4B787B273A50,
    0x4B92DF1BF25D,
    0x4F0E4AE8051A,
    0x514B797B2F3A,
    0x529CF51F05C5,
    0x52B26C199862,
    0x57A18BFEC381,
    0x5A7D87876EA8,
    0x64CBADC7A313,
    0x65B6C3200736,
    0x67B1B3A4E497,
    0x6B0454D5D3C3,
    0x6B3B7AF45777,
    0x6C273F431564,
    0x702C1BF025DD,
    0x738385948494,
    0x76E450094393,
    0x777B1F3A4F4A,
    0x7B173A4E4976,
    0x81504133B13C,
    0x826576A1AB68,
    0x8A55194F6587,
    0x8DFACF11E778,
    0x8FD6D76742DC,
    0x9AFEE1F65742,
    0x9D56D83658AC,
    0x9FAC23197904,
    0xA1AB3A08712C,
    0xA514B797B373,
    0xA58AB5619631,
    0xA5BB18152EF1,
    0xA777B233A4F4,
    0xAB19BC885A29,
    0xAB91BDA25F00,
    0xAE98BA1E6F2C,
    0xB133A4D48757,
    0xB3A4C47757B0,
    0xB6803136F5AF,
    0xB793ADA6DB0C,
    0xB95BFDEBA7E4,
    0xC0AA2BBD27CD,
    0xC27F5C1A9C2B,
    0xC9BE49675FE4,
    0xCCCE24102003,
    0xCDE668FDCDBA,
    0xD23A31A4AAB9,
    0xDEDD7688BC38,
    0xE9AE90885C39,
    0xF0A3C5182007,
    0xF3A524B7A7B3,
    // Data from mall
    // playland balikesir
    0xABBA1234FCB0,
    // A trio bowling bahcelievler
    0x314F495254FF,
    0x4152414B4E41,
    // karinca park nigde
    0x4E474434FFFF,
    // hotel system
    0x537930363139,
    // Data from https://github.com/RadioWar/NFCGUI
    0x44DD5A385AAF,
    0x21A600056CB0,
    0xB1ACA33180A5,
    0xDD61EB6BCE22,
    0x1565A172770F,
    0x3E84D2612E2A,
    0xF23442436765,
    0x79674F96C771,
    0x87DF99D496CB,
    0xC5132C8980BC,
    0xA21680C27773,
    0xF26E21EDCEE2,
    0x675557ECC92E,
    0xF4396E468114,
    0x6DB17C16B35B,
    0x4186562A5BB2,
    0x2FEAE851C199,
    0xDB1A3338B2EB,
    0x157B10D84C6B,
    0xA643F952EA57,
    0xDF37DCB6AFB3,
    0x4C32BAF326E0,
    0x91CE16C07AC5,
    0x3C5D1C2BCD18,
    0xC3F19EC592A2,
    0xF72A29005459,
    0x185FA3438949,
    0x321A695BD266,
    0xD327083A60A7,
    0x45635EF66EF3,
    0x5481986D2D62,
    0xCBA6AE869AD5,
    0x645A166B1EEB,
    0xA7ABBC77CC9E,
    0xF792C4C76A5C,
    0xBFB6796A11DB,
    // Data from Salto A/B
    0x6A1987C40A21,
    0x7F33625BC129,
    0x6BE9314930D8,
    // Data from forum
    0x2338B4913111,
    // Data from stoye
    0xCB779C50E1BD,
    0xA27D3804C259,
    0x003CC420001A,
    0xF9861526130F,
    0x381ECE050FBD,
    0xA57186BDD2B9,
    0x48C739E21A04,
    0x36ABF5874ED7,
    0x649D2ABBBD20,
    0xBBE8FFFCF363,
    0xAB4E7045E97D,
    0x340E40F81CD8,
    0xE4F65C0EF32C,
    0xD2A597D76936,
    0xA920F32FE93A,
    0x86AFD95200F7,
    0x9B832A9881FF,
    0x26643965B16E,
    0x0C669993C776,
    0xB468D1991AF9,
    0xD9A37831DCE5,
    0x2FC1F32F51B1,
    0x0FFBF65B5A14,
    0xC5CFE06D9EA3,
    0xC0DECE673829,
    //
    0xA56C2DF9A26D,
    // Data from https://pastebin.com/vbwast74
    0x68D3F7307C89,
    // Smart Rider. Western Australian Public Transport Cards
    0x568C9083F71C,
    0x117E5C165B10,
    0x24BB421C7973,
    0x3E3A546650EA,
    0x41F262D3AB66,
    0x514956AB3142,
    0x863933AE8388,
    // Bangkok metro key
    0x97F5DA640B18,
    // Metro Valencia key
    0xA8844B0BCA06,
    // HTC Eindhoven key
    0x857464D3AAD1,
    // Vigik Keys
    // Various sources :
    // * https://github.com/DumpDos/Vigik
    // * http://newffr.com/viewtopic.php?&forum=235&topic=11559
    // * Own dumps
    // French VIGIK
    // VIGIK1 A
    0x314B49474956,
    // VIGIK1 B
    0x564C505F4D41,
    0xBA5B895DA162,
    // BTCINO UNDETERMINED SPREAKD 0x01->0x13 key
    0x021209197591,
    // 
    0x2EF720F2AF76,
    0x414C41524F4E,
    0x424C41524F4E,
    0x4A6352684677,
    0xBF1F4424AF76,
    0x536653644C65,
    // Intratone Cogelec
    // Data from http://bouzdeck.com/rfid/32-cloning-a-mifare-classic-1k-tag.html
    0x484558414354,
    0xA22AE129C013,
    0x49FAE4E3849F,
    0x38FCF33072E0,
    0x8AD5517B4B18,
    0x509359F131B1,
    0x6C78928E1317,
    0xAA0720018738,
    0xA6CAC2886412,
    0x62D0C424ED8E,
    0xE64A986A5D94,
    0x8FA1D601D0A2,
    0x89347350BD36,
    0x66D2B7DC39EF,
    0x6BC1E1AE547D,
    0x22729A9BD40F,
    // Data from https://dfir.lu/blog/cloning-a-mifare-classic-1k-tag.html
    0x925B158F796F,
    0xFAD63ECB5891,
    0xBBA840BA1C57,
    0xCC6B3B3CD263,
    0x6245E47352E6,
    0x8ED41E8B8056,
    0x2DD39A54E1F3,
    0x6D4C5B3658D2,
    0x1877ED29435A,
    0x52264716EFDE,
    0x961C0DB4A7ED,
    0x703140FD6D86,
    0x157C9A513FA5,
    0xE2A5DC8E066F,
    // Data from forum,  schlage 9691T fob
    0xEF1232AB18A0,
    // Data from a oyster card
    0x374BF468607F,
    0xBFC8E353AF63,
    0x15CAFD6159F6,
    0x62EFD80AB715,
    0x987A7F7F1A35,
    0xC4104FA3C526,
    0x4C961F23E6BE,
    0x67546972BC69,
    0xF4CD5D4C13FF,
    0x94414C1A07DC,
    0x16551D52FD20,
    0x9CB290282F7D,
    0x77A84170B574,
    0xED646C83A4F3,
    0xE703589DB50B,
    0x513C85D06CDE,
    0x95093F0B2E22,
    0x543B01B27A95,
    0xC6D375B99972,
    0xEE4CC572B40E,
    0x5106CA7E4A69,
    0xC96BD1CE607F,
    0x167A1BE102E0,
    0xA8D0D850A606,
    0xA2ABB693CE34,
    0x7B296C40C486,
    0x91F93A5564C9,
    0xE10623E7A016,
    0xB725F9CBF183,
    // Data from FDi tag
    0x8829DA9DAF76,
    // Data from GitHub issue
    0x0A7932DC7E65,
    0x11428B5BCE06,
    0x11428B5BCE07,
    0x11428B5BCE08,
    0x11428B5BCE09,
    0x11428B5BCE0A,
    0x11428B5BCE0F,
    0x18971D893494,
    0x25D60050BF6E,
    0x44F0B5FBE344,
    0x7B296F353C6B,
    0x8553263F4FF0,
    0x8E5D33A6ED51,
    0x9F42971E8322,
    0xC620318EF179,
    0xD4FE03CE5B06,
    0xD4FE03CE5B07,
    0xD4FE03CE5B08,
    0xD4FE03CE5B09,
    0xD4FE03CE5B0A,
    0xD4FE03CE5B0F,
    0xE241E8AFCBAF,
    // Transport system Argentina - SUBE
    // Shared key - sec 3 blk 15
    0x3FA7217EC575,
    // Data from forum post
    0x123F8888F322,
    0x050908080008,
    // Data from hoist
    0x4F9F59C9C875,
    // Data from pastebin
    0x66F3ED00FED7,
    0xF7A39753D018,
    // Data from https://pastebin.com/Z7pEeZif
    0x386B4D634A65,
    0x666E564F4A44,
    0x564777315276,
    0x476242304C53,
    0x6A696B646631,
    0x4D3248735131,
    0x425A73484166,
    0x57784A533069,
    0x345547514B4D,
    0x4C6B69723461,
    0x4E4175623670,
    0x4D5076656D58,
    0x686A736A356E,
    0x484A57696F4A,
    0x6F4B6D644178,
    0x744E326B3441,
    0x70564650584F,
    0x584F66326877,
    0x6D4E334B6C48,
    0x6A676C315142,
    0x77494C526339,
    0x623055724556,
    0x356D46474348,
    0x4E32336C6E38,
    0x57734F6F6974,
    0x436A46587552,
    0x5544564E6E67,
    0x6F506F493353,
    0x31646241686C,
    0x77646B633657,
    // Data from TransPert
    0x2031D1E57A3B,
    0x53C11F90822A,
    0x9189449EA24E,
    // data from Github
    0x410B9B40B872,
    0x2CB1A90071C8,
    // 
    0x8697389ACA26,
    0x1AB23CD45EF6,
    0x013889343891,
    // 
    0x0000000018DE,
    0x16DDCB6B3F24,
    // Data from https://pastebin.com/vwDRZW7d
    // Vingcard Mifare 4k Staff card
    0xEC0A9B1A9E06,
    0x6C94E1CED026,
    0x0F230695923F,
    0x0000014B5C31,
    // 
    0xBEDB604CC9D1,
    0xB8A1F613CF3D,
    0xB578F38A5C61,
    0xB66AC040203A,
    0x6D0B6A2A0003,
    0x2E641D99AD5B,
    0xAD4FB33388BF,
    0x69FB7B7CD8EE,
    // Hotel
    0x2A6D9205E7CA,
    0x13B91C226E56,
    // KABA Hotel Locks
    0x2A2C13CC242A,
    // 
    0x27FBC86A00D0,
    0x01FA3FC68349,
    // Smart Rider. Western Australian Public Transport Cards
    0x6D44B5AAF464,
    0x1717E34A7A8A,
    // RFIDeas
    0x6B6579737472,
    // HID MIFARE Classic 1k Key
    0x484944204953,
    0x204752454154,
    // HID MIFARE SO
    0x3B7E4FD575AD,
    0x11496F97752A,
    // Luxeo/Aztek cashless vending
    0x415A54454B4D,
    // BQT
    0x321958042333,
    // Aperio KEY_A Sector 1, 12, 13, 14, 15 Data Start 0 Length 48
    0x160A91D29A9C,
    // Gallagher
    0xB7BF0C13066E,
    // PIK Comfort Moscow keys (ISBC Mifare Plus SE 1K)
    0x009FB42D98ED,
    0x002E626E2820,
    // Boston, MA, USA Transit - MBTA Charlie Card
    0x3060206F5B0A,
    0x5EC39B022F2B,
    0x3A09594C8587,
    0xF1B9F5669CC8,
    0xF662248E7E89,
    0x62387B8D250D,
    0xF238D78FF48F,
    0x9DC282D46217,
    0xAFD0BA94D624,
    0x92EE4DC87191,
    0xB35A0E4ACC09,
    0x756EF55E2507,
    0x447AB7FD5A6B,
    0x932B9CB730EF,
    0x1F1A0A111B5B,
    0xAD9E0A1CA2F7,
    0xD58023BA2BDC,
    0x62CED42A6D87,
    0x2548A443DF28,
    0x2ED3B15E7C0F,
    0xF66224EE1E89,
    // 
    0x60012E9BA3FA,
    // 
    0xDE1FCBEC764B,
    0x81BFBE8CACBA,
    0xBFF123126C9B,
    0x2F47741062A0,
    0xB4166B0A27EA,
    0xA170D9B59F95,
    0x400BC9BE8976,
    0xD80511FC2AB4,
    0x1FCEF3005BCF,
    0xBB467463ACD6,
    0xE67C8010502D,
    0xFF58BA1B4478,
    // Data from https://pastebin.com/Kz8xp4ev
    0xFBF225DC5D58,
    // Data  https://pastebin.com/BEm6bdAE
    // vingcard.txt
    // Note: most likely diversified
    0x96A301BCE267,
    0x4708111C8604,
    0x3D50D902EA48,
    0x6700F10FEC09,
    0x7A09CC1DB70A,
    0x560F7CFF2D81,
    0x66B31E64CA4B,
    0x9E53491F685B,
    0x3A09911D860C,
    0x8A036920AC0C,
    0x361F69D2C462,
    0xD9BCDE7FC489,
    0x0C03A720F208,
    0x6018522FAC02,
    // Data from https://pastebin.com/4t2yFMgt
    // Mifare technische Universität Graz TUG
    0xD58660D1ACDE,
    0x50A11381502C,
    0xC01FC822C6E5,
    0x0854BF31111E,
    // More keys - Found 8A at Sebel Hotel in Canberra, Australia
    0xAE8587108640,
    // SafLock standalone door locks
    0x135B88A94B8B,
    // Russian Troika card
    0xEC29806D9738,
    0x08B386463229,
    0x0E8F64340BA4,
    0x0F1C63013DBA,
    0x2AA05ED1856F,
    0x2B7F3253FAC5,
    0x69A32F1C2F19,
    0x73068F118C13,
    0x9BECDF3D9273,
    0xA73F5DC1D333,
    0xA82607B01C0D,
    0xAE3D65A3DAD4,
    0xCD4C61C26E3D,
    0xD3EAFB5DF46D,
    0xE35173494A81,
    0xFBC2793D540B,
    0x5125974CD391,
    0xECF751084A80,
    0x7545DF809202,
    0xAB16584C972A,
    0x7A38E3511A38,
    0xC8454C154CB5,
    0x04C297B91308,
    0xEFCB0E689DB3,
    0x07894FFEC1D6,
    0xFBA88F109B32,
    0x2FE3CB83EA43,
    0xB90DE525CEB6,
    0x1CC219E9FEC1,
    0xA74332F74994,
    0x764CD061F1E6,
    0x8F79C4FD8A01,
    0xCD64E567ABCD,
    0xCE26ECB95252,
    0xABA208516740,
    0x9868925175BA,
    0x16A27AF45407,
    0x372CC880F216,
    0x3EBCE0925B2F,
    0x73E5B9D9D3A4,
    0x0DB520C78C1C,
    0x70D901648CB9,
    0xC11F4597EFB5,
    0xB39D19A280DF,
    0x403D706BA880,
    0x7038CD25C408,
    0x6B02733BB6EC,
    0xEAAC88E5DC99,
    0x4ACEC1205D75,
    0x2910989B6880,
    0x31C7610DE3B0,
    0x5EFBAECEF46B,
    0xF8493407799D,
    0x6B8BD9860763,
    0xD3A297DC2698,
    // Data from reddit
    0x34635A313344,
    0x593367486137,
    // Keys from Mifare Classic Tool project
    0x044CE1872BC3,
    0x045CECA15535,
    0x0BE5FAC8B06A,
    0x0CE7CD2CC72B,
    0x0EB23CC8110B,
    0x0F01CEFF2742,
    0x0F318130ED18,
    0x114D6BE9440C,
    0x18E3A02B5EFF,
    0x19FC84A3784B,
    0x1B61B2E78C75,
    0x22052B480D11,
    0x3367BFAA91DB,
    0x3A8A139C20B4,
    0x42E9B54E51AB,
    0x46D78E850A7E,
    0x4B609876BBA3,
    0x518DC6EEA089,
    0x6B07877E2C5C,
    0x7259FA0197C6,
    0x72F96BDD3714,
    0x7413B599C4EA,
    0x77DABC9825E1,
    0x7A396F0D633D,
    0x7A86AA203788,
    0x8791B2CCB5C4,
    0x8A8D88151A00,
    0x8C97CD7A0E56,
    0x8E26E45E7D65,
    0x9D993C5D4EF4,
    0x9EA3387A63C1,
    0xA3FAA6DAFF67,
    0xA7141147D430,
    0xACFFFFFFFFFF,
    0xAFCEF64C9913,
    0xB27ADDFB64B0,
    0xB81F2B0C2F66,
    0xB9F8A7D83978,
    0xBAFF3053B496,
    0xBB52F8CCE07F,
    0xBC2D1791DEC1,
    0xBC4580B7F20B,
    0xC65D4EAA645B,
    0xC76BF71A2509,
    0xD5524F591EED,
    0xE328A1C7156D,
    0xE4821A377B75,
    0xE56AC127DD45,
    0xEA0FD73CB149,
    0xFC0001877BF7,
    0xFD8705E721B0,
    0x00ADA2CD516D,
    // 
    0x237A4D0D9119,
    0x0ED7846C2BC9,
    0xFFFFD06F83E3,
    0xFFFFAE82366C,
    0xF89C86B2A961,
    0xF83466888612,
    0xED3A7EFBFF56,
    0xE96246531342,
    0xE1DD284379D4,
    0xDFED39FFBB76,
    0xDB5181C92CBE,
    0xCFC738403AB0,
    0xBCFE01BCFE01,
    0xBA28CFD15EE8,
    0xB0699AD03D17,
    0xAABBCC660429,
    0xA4EF6C3BB692,
    0xA2B2C9D187FB,
    0x9B1DD7C030A1,
    0x9AEDF9931EC1,
    0x8F9B229047AC,
    0x872B71F9D15A,
    0x833FBD3CFE51,
    0x5D293AFC8D7E,
    0x5554AAA96321,
    0x474249437569,
    0x435330666666,
    0x1A2B3C4D5E6F,
    0x123456ABCDEF,
    0x83BAB5ACAD62,
    0x64E2283FCF5E,
    0x64A2EE93B12B,
    0x46868F6D5677,
    0x40E5EA1EFC00,
    0x37D4DCA92451,
    0x2012053082AD,
    0x2011092119F1,
    0x200306202033,
    0x1795902DBAF9,
    0x17505586EF02,
    0x022FE48B3072,
    0x013940233313,
    // Hotel Adina
    0x9EBC3EB37130,
    // Misc. keys from hotels & library cards in Germany
    0x914f57280ce3,
    0x324a82200018,
    0x370aee95cd69,
    0x2e032ad6850d,
    0x1feda39d38ec,
    0x288b7a34dbf8,
    0x0965e3193497,
    0x18c628493f7f,
    0x064d9423938a,
    0x995fd2a2351e,
    0x7c7d672bc62e,
    0x217250fb7014,
    0xae7478ccaee7,
    0xabbf6d116eaf,
    0x05862c58edfb,
    0xe43b7f185460,
    0x6a59aa9a959b,
    0xb79e5b175227,
    0x7bc9ebb8274b,
    0xb2afbf2331d4,
    0x223e5847dd79,
    0x640524d2a39b,
    0xaee297cb2fd6,
    0x3da5dfa54604,
    0x0cf1a2aa1f8d,
    // most likely diversifed individual keys.
    // data from https://github.com/korsehindi/proxmark3/commit/24fdbfa9a1d5c996aaa5c192bc07e4ab28db4c5c
    0x491CDC863104,
    0xA2F63A485632,
    0x98631ED2B229,
    0x19F1FFE02563,
    // Argentina
    0x563A22C01FC8,
    0x43CA22C13091,
    0x25094DF2C1BD,
    // OMNITEC.ES HOTEL TIMECARD / MAINTENANCECARD
    0xAFBECD120454,
    // OMNITEC.ES HOTEL EMERGENCYCARD
    0x842146108088,
    // TAPCARD PUBLIC TRANSPORT LA
    0xEA1B88DF0A76,
    0xD1991E71E2C5,
    0x05F89678CFCF,
    0xD31463A7AB6D,
    0xC38197C36420,
    0x772219470B38,
    0x1C1532A6F1BC,
    0xFA38F70215AD,
    0xE907470D31CC,
    0x160F4B7AB806,
    0x1D28C58BBE8A,
    0xB3830B95CA34,
    0x6A0E215D1EEB,
    0xE41E6199318F,
    0xC4F271F5F0B3,
    0x1E352F9E19E5,
    0x0E0E8C6D8EB6,
    0xC342F825B01B,
    0xCB911A1A1929,
    0xE65B66089AFC,
    0xB81846F06EDF,
    0x37FC71221B46,
    0x880C09CFA23C,
    0x6476FA0746E7,
    0x419A13811554,
    0x2C60E904539C,
    0x4ECCA6236400,
    0x10F2BBAA4D1C,
    0x4857DD68ECD9,
    0xC6A76CB2F3B5,
    0xE3AD9E9BA5D4,
    0x6C9EC046C1A4,
    // ROC HIGHSCHOOL ACCESSCARD
    0xB021669B44BB,
    0xB18CDCDE52B7,
    0xA22647F422AE,
    0xB268F7C9CA63,
    0xA37A30004AC9,
    0xB3630C9F11C8,
    0xA4CDFF3B1848,
    0xB42C4DFD7A90,
    0xA541538F1416,
    0xB5F454568271,
    0xA6C028A12FBB,
    0xB6323F550F54,
    0xA7D71AC06DC2,
    0xB7C344A36D88,
    0xA844F4F52385,
    0xB8457ACC5F5D,
    0xA9A4045DCE77,
    0xB9B8B7B6B5B3,
    0xAA4D051954AC,
    0xBA729428E808,
    0xAB28A44AD5F5,
    0xBB320A757099,
    0xAC45AD2D620D,
    0xBCF5A6B5E13F,
    0xAD5645062534,
    0xBDF837787A71,
    0xAE43F36C1A9A,
    0xBE7C4F6C7A9A,
    0x5EC7938F140A,
    0x82D58AA49CCB,
    // MELON CARD
    0x323334353637,
    // 
    0xCEE3632EEFF5,
    0x827ED62B31A7,
    0x03EA4053C6ED,
    0xC0BEEFEC850B,
    0xF57F410E18FF,
    0x0AF7DB99AEE4,
    0xA7FB4824ACBF,
    0x207FFED492FD,
    0x1CFA22DBDFC3,
    0x30FFB6B056F5,
    0x39CF885474DD,
    0x00F0BD116D70,
    0x4CFF128FA3EF,
    0x10F3BEBC01DF,
    // Transportes Insular La Palma
    0x0172066B2F03,
    0x0000085F0000,
    0x1A80B93F7107,
    0x70172066B2F0,
    0xB1A80C94F710,
    0x0B0172066B2F,
    0x0F1A81C95071,
    0xF0F0172066B2,
    0x1131A81D9507,
    0x2F130172066B,
    0x71171A82D951,
    0xB2F170172066,
    0x1711B1A82E96,
    0x6B2F1B017206,
    0x62711F1A83E9,
    0x66B2F1F01720,
    0x97271231A83F,
    0x066B2F230172,
    0xF97371271A84,
    0x2066B2F27017,
    0x50983712B1A8,
    0x72066B2F2B01,
    0x850984712F1A,
    0x172066B2F2F0,
    0xA85198481331,
    0x0172066B2F33,
    0x1A8619858137,
    0x70172066B2F3,
    0xB1A862985913,
    0x3B0172066B2F,
    0x3F1A87298691,
    0xF3F0172066B2,
    // Tehran ezpay
    0x38A88AEC1C43,
    0xCBD2568BC7C6,
    0x7BCB4774EC8F,
    0x22ECE9316461,
    0xAE4B497A2527,
    0xEEC0626B01A1,
    0x2C71E22A32FE,
    0x91142568B22F,
    0x7D56759A974A,
    0xD3B1C7EA5C53,
    0x41C82D231497,
    0x0B8B21C692C2,
    0x604AC8D87C7E,
    0x8E7B29460F12,
    0xBB3D7B11D224,
    // Chaco
    0xB210CFA436D2,
    0xB8B1CFA646A8,
    0xA9F95891F0A4,
    // Keys from APK application "Scan Badge"
    0x4A4C474F524D,
    0x444156494442,
    0x434143445649,
    0x434456495243,
    0xA00002000021,
    0xEF61A3D48E2A,
    0xA23456789123,
    0x010000000000,
    0x363119000001,
    0xA00003000084,
    0x675A32413770,
    0x395244733978,
    0xA0004A000036,
    0x2C9F3D45BA13,
    0x4243414F5250,
    0xDFE73BE48AC6,
    // 
    0xB069D0D03D17,
    0x000131B93F28,
    // From the DFW Area, TX, USA
    0xA506370E7C0F,
    0x26396F2042E7,
    0x70758FDD31E0,
    0x9F9D8EEDDCCE,
    0x06FF5F03AA1A,
    0x4098653289D3,
    0x904735F00F9E,
    0xB4C36C79DA8D,
    0x68F9A1F0B424,
    0x5A85536395B3,
    0x7DD399D4E897,
    0xEF4C5A7AC6FC,
    0xB47058139187,
    0x8268046CD154,
    0x67CC03B7D577,
    // From the HTL Mödling, NÖ, AT
    0xA5524645CD91,
    0xD964406E67B4,
    0x99858A49C119,
    0x7B7E752B6A2D,
    0xC27D999912EA,
    0x66A163BA82B4,
    0x4C60F4B15BA8,
    // CAFE + CO, AT
    0x35D850D10A24,
    0x4B511F4D28DD,
    0xE45230E7A9E8,
    0x535F47D35E39,
    0xFB6C88B7E279,
    // Metro Card, AT
    0x223C3427108A,
    // Unknown, AT
    0x23D4CDFF8DA3,
    0xE6849FCC324B,
    0x12FD3A94DF0E,
    // Unknown, AT
    0x0B83797A9C64,
    0x39AD2963D3D1,
    // Hotel Berlin Classic room A KEY
    0x34B16CD59FF8,
    // Hotel Berlin Classic room B KEY
    0xBB2C0007D022,
    // Coinmatic laundry Smart card
    // data from: https://pastebin.com/XZQiLtUf
    0x0734BFB93DAB,
    0x85A438F72A8A,
    // Data from forum, Chinese hotel
    0x58AC17BF3629,
    0xB62307B62307,
    // 
    0xA2A3CCA2A3CC,
    // Granada, ES Transport Card
    0x000000270000,
    0x0F385FFB6529,
    0x29173860FC76,
    0x2FCA8492F386,
    0x385EFA542907,
    0x3864FCBA5937,
    0x3F3865FCCB69,
    0x6291B3860FC8,
    0x63FCA9492F38,
    0x863FCB959373,
    0x87291F3861FC,
    0x913385FFB752,
    0xB385EFA64290,
    0xC9739233861F,
    0xF3864FCCA693,
    0xFC9839273862,
    // various hotel keys
    0x34D3C568B348,
    0x91FF18E63887,
    0x4D8B8B95FDEE,
    0x354A787087F1,
    0x4A306E62E9B6,
    0xB9C874AE63D0,
    // Data from official repo
    0xF00DFEEDD0D0,
    0x0BB31DC123E5,
    0x7578BF2C66A9,
    0xCD212889C3ED,
    0x6936C035AE1B,
    0xC6C866AA421E,
    0x590BD659CDD2,
    0xAA734D2F40E0,
    0x09800FF94AAF,
    0x5A12F83326E7,
    0xC554EF6A6015,
    0x0D8CA561BDF3,
    0xB8937130B6BA,
    0xD7744A1A0C44,
    0x82908B57EF4F,
    0xFE04ECFE5577,
    // comfort inn hotel
    0x4D57414C5648,
    0x4D48414C5648,
    // unknown hotel key
    0x6D9B485A4845,
    // Bosch Solution 6000
    0x5A7A52D5E20D,
    // Found in TagInfo app
    // RATB key
    0xC1E51C63B8F5,
    0x1DB710648A65,
    // E-GO card key
    0x18F34C92A56E,
    // Library Card MFP - SL1
    0x4A832584637D,
    0xCA679D6291B0,
    0x30D9690FC5BC,
    0x5296C26109D4,
    0xE77952748484,
    0x91C2376005A1,
    0x30B7680B2BC9,
    0xE2A9E88BFE16,
    0x43B04995D234,
    0xAADE86B1F9C1,
    0x5EA088C824C9,
    0xC67BEB41FFBF,
    0xB84D52971107,
    0x52B0D3F6116E,
    // Data from https://pastebin.com/cLSQQ9xN
    0xCA3A24669D45,
    0x4087C6A75A96,
    0x403F09848B87,
    0xD73438698EEA,
    0x5F31F6FCD3A0,
    0xA0974382C4C5,
    0xA82045A10949,
    // Data from https://pastebin.com/2iV8h93h
    // funnivarium
    // forum ankara
    0x2602FFFFFFFF,
    // macera adasi
    // ankara kentpark
    // INACTIVE
    0x0A4600FF00FF,
    0xDFF293979FA7,
    0x4D6F62692E45,
    0x4118D7EF0902,
    // petrol ofisi
    // positive card
    // ode-gec
    0x0406080A0C0E,
    // konya elkart
    0x988ACDECDFB0,
    0x120D00FFFFFF,
    // bowlingo
    // serdivan avym
    0x4AE23A562A80,
    //  kart 54
    0x2AFFD6F88B97,
    0xA9F3F289B70C,
    0xDB6819558A25,
    0x6130DFA578A0,
    0xB16B2E573235,
    0x42EF7BF572AB,
    0x274E6101FC5E,
    // crazy park
    // kizilay avm
    0x00DD300F4F10,
    // kartsistem B
    0xFEE2A3FBC5B6,
    // toru ent
    // taurus avm
    0x005078565703,
    // Ving?
    0x0602721E8F06,
    0xFC0B50AF8700,
    0xF7BA51A9434E,
    // eskart
    // eskisehir transport card
    0xE902395C1744,
    0x4051A85E7F2D,
    0x7357EBD483CC,
    0xD8BA1AA9ABA0,
    0x76939DDD9E97,
    0x3BF391815A8D,
    // muzekart
    // museum card for turkey
    0x7C87013A648A,
    0xE8794FB14C63,
    0x9F97C182585B,
    0xEC070A52E539,
    0xC229CE5123D5,
    0xE495D6E69D9C,
    0x26BF1A68B00F,
    0xB1D3BC5A7CCA,
    0x734EBE504CE8,
    0x974A36E2B1BA,
    0xC197AE6D6990,
    0x4D80A10649DF,
    0x037F64F470AD,
    0xC9CD8D7C65E5,
    0xB70B1957FE71,
    0xCE7712C5071D,
    0xC0AD1B72921A,
    0x45FEE09C1D06,
    0xE592ED478E59,
    0xF3C1F1DB1D83,
    0x704A81DDACED,
    0x89E00BC444EF,
    0xAFAAFCC40DEC,
    0xECC58C5D34CA,
    0x57D83754711D,
    0xD0DDDF2933EC,
    0x240F0BB84681,
    0x9E7168064993,
    0x2F8A867B06B4,
    // bursakart
    // bursa transport card
    0x755D49191A78,
    0xDAC7E0CBA8FD,
    0x68D3263A8CD6,
    0x865B6472B1C0,
    0x0860318A3A89,
    0x1927A45A83D3,
    0xB2FE3B2875A6,
    // playland
    // maltepe park
    0xABCC1276FCB0,
    0xAABAFFCC7612,
    // lunasan
    // kocaeli fair
    0x26107E7006A0,
    // gamefactory
    // ozdilek
    0x17D071403C20,
    // 
    0x534F4C415249,
    0x534F4C303232,
    // Nespresso, smart card
    // key-gen algo, these keys are for one card (keys diversified)
    0xFF9A84635BD2,
    0x6F30126EE7E4,
    0x6039ABB101BB,
    0xF1A1239A4487,
    // 
    0xB882FD4A9F78,
    0xCD7FFFF81C4A,
    0xAA0857C641A3,
    0xC8AACD7CF3D1,
    0x9FFDA233B496,
    0x26B85DCA4321,
    0xD4B2D140CB2D,
    0xA7395CCB42A0,
    0x541C417E57C0,
    0xD14E615E0545,
    0x69D92108C8B5,
    0x703265497350,
    0xD75971531042,
    0x10510049D725,
    0x35C649004000,
    0x5B0C7EC83645,
    0x05F5EC05133C,
    0x521B517352C7,
    0x94B6A644DFF6,
    0x2CA4A4D68B8E,
    0xA7765C952DDF,
    0xE2F14D0A0E28,
    0xDC018FC1D126,
    0x4927C97F1D57,
    0x046154274C11,
    0x155332417E00,
    0x6B13935CD550,
    0xC151D998C669,
    0xD973D917A4C7,
    0x130662240200,
    0x9386E2A48280,
    0x52750A0E592A,
    0x075D1A4DD323,
    0x32CA52054416,
    0x460661C93045,
    0x5429D67E1F57,
    0x0C734F230E13,
    0x1F0128447C00,
    0x411053C05273,
    0x42454C4C4147,
    0xC428C4550A75,
    0x730956C72BC2,
    0x28D70900734C,
    0x4F75030AD12B,
    0x6307417353C1,
    0xD65561530174,
    0xD1F71E05AD9D,
    0xF7FA2F629BB1,
    0x0E620691B9FE,
    0x43E69C28F08C,
    0x735175696421,
    0x424C0FFBF657,
    0x51E97FFF51E9,
    0xE7316853E731,
    0x00460740D722,
    0x35D152154017,
    0x5D0762D13401,
    0x0F35D5660653,
    0x1170553E4304,
    0x0C4233587119,
    0xF678905568C3,
    0x50240A68D1D8,
    0x2E71D3BD262A,
    0x540D5E6355CC,
    0xD1417E431949,
    0x4BF6DE347FB6,
    // 
    0x3A471B2192BF,
    0xA297CEB7D34B,
    0xAE76242931F1,
    // 
    0x124578ABFEDC,
    0xABFEDC124578,
    0x4578ABFEDC12,
    // Data from
    // premier inn hotel chain
    0x5E594208EF02,
    0xAF9E38D36582,
    // Norwegian building site identication card. (HMS KORT)
    // Key a
    0x10DF4D1859C8,
    // Key B
    0xB5244E79B0C8,
    // Ukraine hotel
    0xF5C1C4C5DE34,
    // Data from Mifare Classic Tool repo
    // Rotterdam University of applied sciences campus card
    0xBB7923232725,
    0xA95BD5BB4FC5,
    0xB099335628DF,
    0xA34DA4FAC6C8,
    0xAD7C2A07114B,
    0x53864975068A,
    0x549945110B6C,
    0xB6303CD5B2C6,
    0xAFE444C4BCAA,
    0xB80CC6DE9A03,
    0xA833FE5A4B55,
    0xB533CCD5F6BF,
    0xB7513BFF587C,
    0xB6DF25353654,
    0x9128A4EF4C05,
    0xA9D4B933B07A,
    0xA000D42D2445,
    0xAA5B6C7D88B4,
    0xB5ADEFCA46C4,
    0xBF3FE47637EC,
    0xB290401B0CAD,
    0xAD11006B0601,
    // Data from Mifare Classic Tool repo
    // Armenian Metro
    0xE4410EF8ED2D,
    0x6A68A7D83E11,
    0x0D6057E8133B,
    0xD3F3B958B8A3,
    0x3E120568A35C,
    0x2196FAD8115B,
    0x7C469FE86855,
    0xCE99FBC8BD26,
    // keys from Eurothermes group (Switzerland)
    0xD66D91829013,
    0x75B691829013,
    0x83E391829013,
    0xA23C91829013,
    0xE46A91829013,
    0xD9E091829013,
    0xFED791829013,
    0x155F91829013,
    0x06CC91829013,
    0x8DDC91829013,
    0x54AF91829013,
    0x29A791829013,
    0x668091829013,
    0x00008627C10A,
    // easycard
    0x310D51E539CA,
    0x2CCDA1358323,
    0x03E0094CEDFE,
    0x562E6EF73DB6,
    0xF53E9F4114A9,
    0xAD38C17DE7D2,
    // SUBE cards keys (new)
    0x2DEB57A3EA8F,
    0x32C1BB023F87,
    0x70E3AD3F2D29,
    0x202ECDCCC642,
    0x3686192D813F,
    0x24501C422387,
    0x2C7813A721C3,
    0xFFE04BE3D995,
    0xD28F090677A1,
    0xDE2D83E2DCCC,
    0xA66A478712EA,
    0x643232ADB2D5,
    0xC7F4A4478415,
    0x95C013B70D99,
    0x3C383889362A,
    0x3C6D9C4A90FA,
    0x51BEDBA005E5,
    0x74BF7363F354,
    0x53B09DB89111,
    0xE98075318085,
    0x2F904641D75F,
    0x7F60AEF68136,
    0xF5C1B3F62FDA,
    0x3E6E5713BA10,
    0x8B75A29D4AB2,
    0x7E6545076619,
    // SUBE cards keys (old)
    0x4C5A766DFE3A,
    0x32C6768847F5,
    0xF68930789631,
    0x8B42B6D64B02,
    0xB627A3CB13F8,
    0x562A4FB8260B,
    0x88DDC24E1671,
    0x91CB7802A559,
    0x7A3E0F5B63FC,
    0x8CA2C9DC8292,
    0x5CCC6D50EAAC,
    0xDE4F5AA9A7F3,
    0x52D0145E1AF5,
    0xC10F92A4E57E,
    0x7D6E7AF43C97,
    0xDE1E7D5F6DF1,
    0xF4CB751B031A,
    0xC54474936B59,
    0x2A1F900D4533,
    0x6303CDCBB233,
    0xF115E91357B3,
    0xBFE25035B0C8,
    0x62FF943EB069,
    0x7C82EF592001,
    0xD5C172325DD3,
    0x992B152E834A,
    0xCE75D7EADEAF,
    // Russian Podorozhnik card (Saint-Petersburg transport)
    // may be combined with Troika
    0x038B5F9B5A2A,
    0x04DC35277635,
    0x0C420A20E056,
    0x152FD0C420A7,
    0x296FC317A513,
    0x29C35FA068FB,
    0x31BEC3D9E510,
    0x462225CD34CF,
    0x4B7CB25354D3,
    0x5583698DF085,
    0x578A9ADA41E3,
    0x6F95887A4FD3,
    0x7600E889ADF9,
    0x86120E488ABF,
    0x8818A9C5D406,
    0x8C90C70CFF4A,
    0x8E65B3AF7D22,
    0x9764FEC3154A,
    0x9BA241DB3F56,
    0xAD2BDC097023,
    0xB0A2AAF3A1BA,
    0xB69D40D1A439,
    0xC956C3B80DA3,
    0xCA96A487DE0B,
    0xD0A4131FB290,
    0xD27058C6E2C7,
    0xE19504C39461,
    0xFA1FBB3F0F1F,
    0xFF16014FEFC7,
    // Food GEM
    0x6686FADE5566,
    // Samsung Data Systems (SDS) — Electronic Locks
    // Gen 1 S10 KA/KB is FFFFFFFFFFFF, incompatible with Gen 2 locks
    // SDS Gen 2 S10 KB
    0xC22E04247D9A,
    // Data from Discord, French pool
    // SDS Gen 2 S10 KA
    0x9B7C25052FC3,
    0x494446555455,
    // Data from Discord, seems to be related to ASSA
    0x427553754D47,
    // Keys found on Edith Cowan University Smart Riders
    0x9A677289564D,
    0x186C59E6AFC9,
    0xDDDAA35A9749,
    0x9D0D0A829F49,
    // Mercator Pika Card, Slovenia
    0x97D77FAE77D3,
    0x5AF445D2B87A,
    // Vilniečio/JUDU kortelė, Lithuania
    // A
    0x16901CB400BC,
    0xF0FE56621A42,
    0x8C187E78EE9C,
    0xFE2A42E85CA8,
    // B
    0x6A6C80423226,
    0xF4CE4AF888AE,
    0x307448829EBC,
    0xC2A0105EB028,
    // Keys from Flipper Zero Community
    // Last update: Aug 13, 2022
    // unknown if keys are diversified or static default
    // Strelka Extension
    0x5C83859F2224,
    0x66B504430416,
    0x70D1CF2C6843,
    0xC4B3BD0ED5F1,
    0xC4D3911AD1B3,
    0xCAD7D4A6A996,
    0xDA898ACBB854,
    0xFEA1295774F9,
    // Moscow Public Toilets Card
    0x807119F81418,
    0x22C8BCD10AAA,
    0x0AAABA420191,
    0xE51B4C22C8BC,
    0xDBF9F79AB7A2,
    0x34EDE51B4C22,
    0xC8BCD10AAABA,
    0xBCD10AAABA42,
    // Moscow Social Card
    0x2F87F74090D1,
    0xE53EAEFE478F,
    0xCE2797E73070,
    0x328A034B93DB,
    0x81E1529AE22B,
    0xFC55C50E579F,
    0x1A72E2337BC3,
    0x5DB52676BE07,
    0xF64FBF085098,
    0x8FE758A8F039,
    0xBB1484CC155D,
    0x41990A529AE2,
    0xCD2E9EE62F77,
    0x69C1327AC20B,
    0x3C9C0D559DE5,
    0x67BF3880C811,
    0x48A01159A1E9,
    0x2B83FB448CD4,
    0xF24BBB044C94,
    0x94F46DB5FD46,
    0xC31C8CD41D65,
    0xBB1684CC155D,
    0xCA2393DB246C,
    0x1D75E52E76BE,
    0x81D9529AE223,
    0x0159C9125AA2,
    0x52AA1B6BB3FB,
    0x97EF60A8F031,
    0x6FC73888D011,
    0x3A92FA438BD3,
    0x74CC3D85CD0E,
    0x025ACA1B63A3,
    0xAF0878C81151,
    0x9BFB6CB4FC45,
    0xF750C0095199,
    0x075FCF1860A8,
    0x2686EE3F87C7,
    0x277FEF3880C0,
    0x82DA4B93DB1C,
    0x9CF46DB5FD46,
    0x93EB64ACF43D,
    // Iron Logic RU
    0xA3A26EF4C6B0,
    0x2C3FEAAE99FC,
    0xE85B73382E1F,
    0xF4ED24C2B998,
    0xCB574C6D3B19,
    0xE092081D724B,
    0xB38D82CF7B6C,
    0x8228D2AA6EFA,
    0x2C7E983588A3,
    0xCF7A7B77E232,
    0x32A7F5EAF87D,
    0x7453A687B5F0,
    0x01A0C008A5B9,
    0xDEC0CEB0CE24,
    0x413BED2AE45B,
    0xD6261A9A4B3F,
    0xCB9D507CE56D,
    // Armenian Underground Ticket
    0xA0A1A2A8A4A5,
    // Badge Maker Leaked from https://github.com/UberGuidoZ
    0x1A1B1C1D1E1F,
    0x1665FE2AE945,
    0x158B51947A8E,
    0xE167EC67C7FF,
    0xD537320FF90E,
    0x5E56BFA9E2C9,
    0xF81CED821B63,
    0xC81584EF5EDF,
    0x9551F8F9259D,
    0x36E1765CE3E8,
    0x509052C8E42E,
    0x776C9B03BE71,
    0xC608E13ADD50,
    0xBEE8B345B949,
    0xED0EC56EEFDD,
    0x9716D5241E28,
    0x05D1FC14DC31,
    0x3321FB75A356,
    0xF22A78E29880,
    0xEC211D12C98D,
    0x8CCA8F62A551,
    0xB637E46AD674,
    0x39605B3C8917,
    0x3882719778A1,
    0x9F27D36C4230,
    0xDB32A6811327,
    0x8AA8544A2207,
    0x8C5819E780A4,
    0x7549E90353A2,
    0x2E52ABE0CE95,
    0xE46210ED98AB,
    0x61D030C0D7A8,
    0x18E20102821E,
    0xDA59354DFB88,
    0x040047C12B75,
    0xD10008074A6F,
    0x686E736F6E20,
    0x446176696453,
    0x6F6674776172,
    0x6520446F7665,
    // Apartment keyfobs (USA) (Corvette830)
    0xE60F8387F0B9,
    0xFFD46FF6C5EE,
    0x4F9661ED2E70,
    0x576A798C9904,
    0x1C5179C4A8A1,
    0x16CA203B811B,
    0x11AC8C8F3AF2,
    // The Westin Jakarta Indonesia (D4DB0D)
    // Peppers Hotel Unknown location (D4D0D)
    0x6E0DD4136B0A,
    0x141940E9B71B,
    0x3B1D3AAC866E,
    0x95E9EE4CCF8F,
    0xFEA6B332F04A,
    0xBE0EC5155806,
    0x0500D6BFCC4F,
    0xFC5AC7678BE3,
    0xF09BB8DD142D,
    0xB4B3FFEDBE0A,
    0x540E0D2D1D08,
    // Schlage 9691T Keyfob (seasnaill)
    0x7579B671051A,
    0x4F4553746B41,
    // Vigik ScanBadge App (fr.badgevigik.scanbadge)
    // Website https://badge-vigik.fr/  (Alex)
    0x0000A2B3C86F,
    0x021200C20307,
    0x021209197507,
    0x1E34B127AF9C,
    0x303041534956,
    0x4143532D494E,
    0x41454E521985,
    0x43412D627400,
    0x455249524345,
    0x456666456666,
    0x45B722C63319,
    0x484585414354,
    0x4D414C414741,
    0x536563644C65,
    0x57D27B730760,
    0x593DD8FE167A,
    0x6472616E7265,
    0x65626F726369,
    0x680E95F3C287,
    0x709BA7D4F920,
    0x8829DAD9AF76,
    0x92D0A0999CBA,
    0x948EE7CFC9DB,
    0x9EB7C8A6D4E3,
    0xA22AE12C9013,
    0xAFC984A3576E,
    // Vigik verified by quantum-x
    // https://github.com/RfidResearchGroup/proxmark3/pull/1742#issuecomment-1206113976
    0xA00027000099,
    0xA00016000028,
    0xA00003000028,
    0xA0000F000345,
    0xA00001000030,
    0xA00002000086,
    0xA00002000036,
    0xA00002000088,
    0xA00000000058,
    0xA00000000096,
    0xA00000000008,
    0xA00000043D79,
    0xA00000000064,
    0xA00025000030,
    0xA00003000057,
    // BH USA 2013 conference
    0x012279BAD3E5,
    // iGuard Simple (and reverse) keys
    0xAAAAAAFFFFFF,
    0xFFFFFFAAAAAA,
    // Random Hotel A Key Sec 0 Blk 3 - KABA Lock (VideoMan)
    0x3111A3A303EB,
    // Transport system Uruguay - STM
    // Shared key - sec 0 blk 3
    0xD144BD193063,
    // Data from http://www.proxmark.org/forum/viewtopic.php?pid=45659#p45659
    0x3515AE068CAD,
    // Keys Catering
    0x6A0D531DA1A7,
    0x4BB29463DC29,
    // Keys Swim
    0x8627C10A7014,
    0x453857395635,
    // Unknown hotel system Sec 0 / A
    0x353038383134,
    // Brazil transport Sec 8 / A
    0x50d4c54fcdf5,
    // Bandai Namco Passport [fka Banapassport] / Sega Aime Card
    // Dumped on the Flipper Devices Discord Server
    0x6090D00632F5,
    0x019761AA8082,
    0x574343467632,
    0xA99164400748,
    0x62742819AD7C,
    0xCC5075E42BA1,
    0xB9DF35A0814C,
    0x8AF9C718F23D,
    0x58CD5C3673CB,
    0xFC80E88EB88C,
    0x7A3CDAD7C023,
    0x30424C029001,
    0x024E4E44001F,
    0xECBBFA57C6AD,
    0x4757698143BD,
    0x1D30972E6485,
    0xF8526D1A8D6D,
    0x1300EC8C7E80,
    0xF80A65A87FFA,
    0xDEB06ED4AF8E,
    0x4AD96BF28190,
    0x000390014D41,
    0x0800F9917CB0,
    0x730050555253,
    0x4146D4A956C4,
    0x131157FBB126,
    0xE69DD9015A43,
    0x337237F254D5,
    0x9A8389F32FBF,
    0x7B8FB4A7100B,
    0xC8382A233993,
    0x7B304F2A12A6,
    0xFC9418BF788B,
    // Data from "the more the marriott" mifare project (colonelborkmundus)
    // aka The Horde
    // These keys seem to be from Vingcard / Saflok system which means they are diversified
    // and not static default keys.  To verify this, the UID from such a card is needed.
    // 20230125-01, Elite Member Marriott Rewards
    0x43012BD9EB87,
    // 20230125-02, Elite Member Marriott Rewards
    0x3119A70628EB,
    // 20230125-03, Elite Member Marriott Rewards
    0x23C9FDD9A366,
    // 20230125-04, Elite Member Marriott Rewards
    0x7B4DFC6D6525,
    // 20230125-05, Elite Member Marriott Rewards
    0x1330824CD356,
    // 20230125-06, Elite Member Marriott Rewards
    0x30AAD6A711EF,
    // 20230125-07, Fairfield Inn & Suites Marriott
    0x7B3B589A5525,
    // 20230125-08, Moxy Hotels
    0x20C166C00ADB,
    // 20230125-09, Westin Hotels & Resorts
    0x7D0A1C277C05,
    0x2058580A941F,
    0x8C29F8320617,
    // 20230125-10, Westin Hotels & Resorts
    0xC40964215509,
    0xD44CFC178460,
    0x5697519A8F02,
    // 20230125-12, AC Hotels Marriott
    0x7B56B2B38725,
    // 20230125-13, AC Hotels Marriott
    0x8EA8EC3F2320,
    // 20230125-14, Waldorf Astoria Chicago
    0x011C6CF459E8,
    // 20230125-24, Aria Resort & Casino
    0xA18D9F4E75AF,
    // 20230125-25, Aria Resort & Casino
    0x316B8FAA12EF,
    // 20230125-26, Residence Inn Mariott
    0x3122AE5341EB,
    // 20230125-27, Residence Inn Mariott
    0xF72CD208FDF9,
    // 20230125-28, Marriott
    0x035C70558D7B,
    // 20230125-29, Marriott
    0x12AB4C37BB8B,
    // 20230125-30, Marriott
    0x9966588CB9A0,
    // 20230125-31, Sheraton
    0x42FC522DE987,
    // 20230125-32, The Industrialist
    0x2158E314C3DF,
    // 20230125-39, The Ritz-Carlton Balharbour
    0x30FB20D0EFEF,
    // 20230125-40, The Ritz-Carlton Balharbour
    0x66A3B064CC4B,
    // 20230125-41, The Ritz-Carlton Balharbour
    0xD18296CD9E6E,
    // 20230125-42, The Ritz-Carlton Balharbour
    0xD20289CD9E6E,
    // 20230125-44, Graduate Hotels
    0x209A2B910545,
    0xC49DAE1C6049,
    // 20230125-46, AmericInn
    0x8AC04C1A4A25,
    // 20230129-53, Marriott Bonvoy
    0x6E029927600D,
    0x3E173F64C01C,
    0xC670A9AD6066,
    // 20230413-69, Westin
    0x487339FA02E0,
    // 20230413-70, Marriott Bonvoy
    0xDBD5CA4EE467,
    0xA0B1F234006C,
    0x180DE12B700E,
    // 20230413-71, Westin
    0x1352C68F7A56,
    // 20230413-76, Ritz Carlton
    0x318BD98C1CEF,
    // 20230413-77, Marriott
    0xD23C1CB1216E,
    // 20230413-78, Caesars
    0xA1D92F808CAF,
    // 20230413-79, The Cosmopolitan, Vegas
    // 20230413-80, Aria
    0x1153C319B4F8,
    // 20230413-81, Aria
    0x110C819BBEF8,
    // 20230413-82, Aria
    0x1332117E8756,
    // 20230413-83, Kimpton
    0x500AE915F50A,
    0x5032E362B484,
    0x8B63AB712753,
    // 20230413-85, Kimpton
    0x06106E187106,
    0x2E45C23DC541,
    0xD9FF8BEE7550,
    // 20230413-87, Marriott
    0x42F7A186BF87,
    // 20230413-88, Meritage Resort
    0xD213B093B79A,
    // 20230413-89, Meritage Resort
    0x216024C49EDF,
    // 20230413-90, Gaylord Palms
    0xD201DBB6AB6E,
    // 20230413-91, Residence Inn
    0x9F4AD875BB30,
    // 20230413-92, Marriott
    0x3352DB1E8777,
    // 20230413-94, Marriott
    0x09074A146605,
    0x151F3E85EC46,
    // Travelodge by Wyndham Berkeley
    0x0000FFFFFFFF,
    0x4663ACD2FFFF,
    0xEDC317193709,
    // Hotel Santa Cruz
    0x75FAB77E2E5B,
    // saflok brand HOTEL key
    0x32F093536677,
    // A WaterFront Hotel in  Oakland
    0x3351916B5A77,
    // Ballys (2018)
    0x336E34CC2177,
    // Random Hawaiian Hotel
    0xA1670589B2AF,
    // SF Hotel (SoMa area)
    0x2E0F00700000,
    // Unknown PACS from Western Australia
    0xCA80E51FA52B,
    0xA71E80EA35E1,
    0x05597810D63D,
    // Hotel Key from Las Vegas
    0xEA0CA627FD06,
    0x80BB8436024C,
    0x5044068C5183,
    // Key from Hotel M Montreal (probably diversified)
    0x7E5E05866ED6,
    0x661ABF99AFAD,
    // Key from evo Montreal (probably diversified)
    0x1064BA5D6DF8,
    // Hotel key
    0xCE0F4F15E909,
    0xD60DE9436219,
    // ATM Area de Girona, spanish transport card
    0xA01000000000,
    0xA02000000000,
    0xA03000000000,
    0xA04000000000,
    0xA05000000000,
    0xA06000000000,
    0xA07000000000,
    0xA08000000000,
    0xA09000000000,
    0xA10000000000,
    0xA11000000000,
    0xA12000000000,
    0xA13000000000,
    0xA14000000000,
    0xA15000000000,
    0xB01000000000,
    0xB02000000000,
    0xB03000000000,
    0xB04000000000,
    0xB05000000000,
    0xB06000000000,
    0xB07000000000,
    0xB08000000000,
    0xB09000000000,
    0xB10000000000,
    0xB11000000000,
    0xB12000000000,
    0xB13000000000,
    0xB14000000000,
    0xB15000000000,
    // Pittsburgh, PA, USA - Pittsburgh Regional Transit ConnectCard
    0xA7AE4A5A33DC,
    0x6B857B568C10,
    0xE2CE9A674CBE,
    0xA4896B2EBA4E,
    0x0724DF9AEDE8,
    0x0E368FB140C1,
    0x874EB25C8721,
    0x5C313F4539CD,
    0xC5498606E0A8,
    0x79C69F7EC7C0,
    0xDA7DD0044DA2,
    0x1B8189BD966B,
    0x765584147990,
    0x4B7C7C315E6E,
    0x46CAAD12C524,
    0x53BD03DEA5C9,
    0xD2D72CB60F59,
    0x14D258786538,
    0xE2E89A375B36,
    0xB3FA87DB0C45,
    0x44D3B1561B34,
    0x2817C6E02F97,
    0xA513FF1232E9,
    0xBD454BD52792,
    0x391771654DC8,
    0x5162797F8E1C,
    0xF700BD8E042D,
    0x3973ABFD8B66,
    0xCE8BFF3728EE,
    0x09938D05DA78,
    0xEACDA4DBE420,
    0xEC2B9FD483CA,
    // Hotel Intelier Orange - Benicasim, Spain
    // block 1 - key A
    0x04256CFE0425,
};

// Internal state
static uint8_t mattyrun_uid[10];
static uint32_t mattyrun_cuid;
static iso14a_card_select_t mattyrun_card;

// Discover ISO 14443A cards
static bool saMifareDiscover(void) {
    SpinDelay(500);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    if (iso14443a_select_card(mattyrun_uid, &mattyrun_card, &mattyrun_cuid, true, 0, true) == 0) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        SpinDelay(500);
        return false;
    }

    return true;
}

// Customized MifareChkKeys that operates on the already detected card in
// mattyrun_card and tests authentication with our dictionary
static int saMifareChkKeys(uint8_t const blockNo, uint8_t const keyType, bool const clearTrace,
                           uint16_t const keyCount, uint64_t const * const mfKeys, uint64_t * const key) {

    int retval = -1;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint8_t selectRetries = 16;
    uint8_t cascade_levels = 0;
    int authres = 0;

    if (clearTrace)
        clear_trace();

    int oldbg = g_dbglevel;
    g_dbglevel = DBG_NONE;

    set_tracing(false);

    for (uint16_t i = 0; i < keyCount; ++i) {

        uint64_t mfKey = mfKeys[i];
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) != 0) {
            // skip unused dictionary key slot
            continue;
        }
        mfKey &= MATTYRUN_MFC_KEY_BITS;

        if (mattyrun_card.uidlen == 0) {
            if (!saMifareDiscover()) {
                --i; // try same key once again
                --selectRetries;
                if (selectRetries > 0) {
                    continue;
                } else {
                    retval = -2;
                    break;
                }
            }
        } else {
            if (cascade_levels == 0) {
                switch (mattyrun_card.uidlen) {
                    case 4:  cascade_levels = 1; break;
                    case 7:  cascade_levels = 2; break;
                    case 10: cascade_levels = 3; break;
                    default: break;
                }
            }
            // No need for anticollision. Since we sucessfully selected the card before,
            // we can directly select the card again
            if (iso14443a_fast_select_card(mattyrun_uid, cascade_levels) == 0) {
                --i; // try same key once again
                --selectRetries;
                if (selectRetries > 0) {
                    continue;
                } else {
                    retval = -2;
                    break;
                }
            }
        }

        selectRetries = 16;

        authres = mifare_classic_auth(pcs, mattyrun_cuid, blockNo, keyType, mfKey, AUTH_FIRST);
        if (authres) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            if (authres == 1) {
                retval = -3;
                break;
            } else {
                continue;
            }
        }
        *key = mfKey;
        retval = i;
        break;
    }

    crypto1_deinit(pcs);

    set_tracing(false);
    g_dbglevel = oldbg;

    return retval;
}

void ModInfo(void) {
    DbpString("  HF MIFARE Classic chk/ecfill/sim - aka MattyRun");
}

void RunMod(void) {
    StandAloneMode();
    DbpString(">>  HF MIFARE Classic chk/ecfill/sim - aka MattyRun started  <<");

    // Comment this line below if you want to see debug messages.
    // usb_disable();

    // Allocate dictionary buffer
    uint64_t * const mfcKeys = (uint64_t *)BigBuf_malloc(
            sizeof(uint64_t) * (ARRAYLEN(MATTYRUN_MFC_ESSENTIAL_KEYS) +
                                ARRAYLEN(MATTYRUN_MFC_DEFAULT_KEYS) +
                                MIFARE_4K_MAXSECTOR * 2));
    uint16_t mfcKeyCount = 0;

    // Load essential keys to dictionary buffer
    for (uint16_t i = 0; i < ARRAYLEN(MATTYRUN_MFC_ESSENTIAL_KEYS); ++i) {
        uint64_t mfKey = MATTYRUN_MFC_ESSENTIAL_KEYS[i];
        for (uint16_t j = 0; j < mfcKeyCount; ++j) {
            if (mfKey == mfcKeys[j]) {
                // skip redundant dictionary key
                mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                break;
            }
        }
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
            mfcKeys[mfcKeyCount] = mfKey;
            ++mfcKeyCount;
        }
    }

    // Load user keys from emulator memory to dictionary buffer
    for (uint8_t sectorNo = 0; sectorNo < MIFARE_4K_MAXSECTOR; ++sectorNo) {
        for (uint8_t keyType = 0; keyType < 2; ++keyType) {
            uint64_t mfKey = emlGetKey(sectorNo, keyType);
            for (uint16_t j = 0; j < mfcKeyCount; ++j) {
                if (mfKey == mfcKeys[j]) {
                    // skip redundant dictionary key
                    mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                    break;
                }
            }
            if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
                mfcKeys[mfcKeyCount] = mfKey;
                ++mfcKeyCount;
            }
        }
    }

    // Load additional keys to dictionary buffer
    for (uint16_t i = 0; i < ARRAYLEN(MATTYRUN_MFC_DEFAULT_KEYS); ++i) {
        uint64_t mfKey = MATTYRUN_MFC_DEFAULT_KEYS[i];
        for (uint16_t j = 0; j < mfcKeyCount; ++j) {
            if (mfKey == mfcKeys[j]) {
                // skip redundant dictionary key
                mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                break;
            }
        }
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
            mfcKeys[mfcKeyCount] = mfKey;
            ++mfcKeyCount;
        }
    }

    // Call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) only after extracting keys from
    // emulator memory as it may destroy the contents of the emulator memory
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Pretty print keys to be checked
    if (MATTYRUN_PRINT_KEYS) {
        DbpString("[+] Printing mfc key dictionary");
        for (uint16_t i = 0; i < mfcKeyCount; ++i) {
            uint64_t mfKey = mfcKeys[i];
            if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) != 0) {
                // skip unused dictionary key slot
                continue;
            }
            Dbprintf("[-]     key[%5" PRIu16 "] = %012" PRIx64 "", i, mfKey);
        }
        DbpString("[+] --------------------------------------------------------");
    }

    uint8_t sectorsCnt = MIFARE_4K_MAXSECTOR;
    bool keyFound = false;
    bool allKeysFound = true;
    bool partialEmulation = false;
    bool validKey[2][MIFARE_4K_MAXSECTOR];
    uint8_t foundKey[2][MIFARE_4K_MAXSECTOR][6];

    enum {
        STATE_READ,
        STATE_ATTACK,
        STATE_LOAD,
        STATE_EMULATE,
    } state = STATE_READ;

    for (;;) {

        WDT_HIT();

        // Exit from MattyRun when usbcommand is received
        if (data_available()) break;

        // Exit from MattyRun on long-press of user button
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed == BUTTON_HOLD) {
            WAIT_BUTTON_RELEASED();
            break;
        }

        if (state == STATE_READ) {
            // Wait for card.
            // If detected, try to authenticate with dictionary keys.

            LED_A_OFF();
            LED_B_OFF();
            LED_C_ON();
            LED_D_OFF();

            if (!saMifareDiscover()) {
                SpinErr(LED_D, 50, 2);
                continue;
            }

            switch (mattyrun_card.uidlen) {
                case 4:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3]);
                    break;
                case 7:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3],
                             mattyrun_card.uid[4], mattyrun_card.uid[5], mattyrun_card.uid[6]);
                    break;
                default:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3],
                             mattyrun_card.uid[4], mattyrun_card.uid[5], mattyrun_card.uid[6],
                             mattyrun_card.uid[7], mattyrun_card.uid[8], mattyrun_card.uid[9]);
                    break;
            }

            sectorsCnt = MIFARE_4K_MAXSECTOR;

            // Initialization of validKeys and foundKeys:
            // - validKey will store whether the sector has a valid A/B key.
            // - foundKey will store the found A/B key for each sector.
            for (uint8_t keyType = 0; keyType < 2; ++keyType) {
                for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; ++sectorNo) {
                    validKey[keyType][sectorNo] = false;
                    memset(foundKey[keyType][sectorNo], 0xFF, 6);
                }
            }

            keyFound = false;
            allKeysFound = true;
            bool err = false;

            // Iterates through each sector, checking if there is a correct key
            for (uint8_t keyType = 0; keyType < 2 && !err; ++keyType) {
                for (uint8_t sec = 0; sec < sectorsCnt && !err; ++sec) {
                    uint64_t currentKey;
                    Dbprintf("[=] Testing sector %3" PRIu8 " (block %3" PRIu8 ") for key %c",
                             sec, FirstBlockOfSector(sec), (keyType == 0) ? 'A' : 'B');
                    int key = saMifareChkKeys(FirstBlockOfSector(sec), keyType, true,
                                              mfcKeyCount, &mfcKeys[0], &currentKey);
                    if (key == -2) {
                        DbpString("[" _RED_("!") "] " _RED_("Failed to select card!"));
                        SpinErr(LED_D, 50, 2);
                        err = true; // fall back into idle mode since we can't select card anymore
                        break;
                    } else if (key == -3) {
                        sectorsCnt = sec;
                        switch (sec) {
                            case MIFARE_MINI_MAXSECTOR:
                            case MIFARE_1K_MAXSECTOR:
                            case MIFARE_2K_MAXSECTOR:
                            case MIFARE_4K_MAXSECTOR:
                                break;
                            case (MIFARE_MINI_MAXSECTOR + 2):
                            case (MIFARE_1K_MAXSECTOR + 2):
                            case (MIFARE_2K_MAXSECTOR + 2):
                            case (MIFARE_4K_MAXSECTOR + 2):
                                break;
                            default:
                                Dbprintf("[" _RED_("!") "] " _RED_("Unexpected number of sectors (%" PRIu8 ")!"),
                                         sec);
                                SpinErr(LED_D, 250, 3);
                                allKeysFound = false;
                                break;
                        }
                        break;
                    } else if (key < 0) {
                        Dbprintf("[" _RED_("!") "] " _RED_("No key %c found for sector %" PRIu8 "!"),
                                 (keyType == 0) ? 'A' : 'B', sec);
                        SpinErr(LED_D, 50, 3);
                        LED_C_ON();
                        allKeysFound = false;
                        continue;
                    } else {
                        num_to_bytes(currentKey, 6, foundKey[keyType][sec]);
                        validKey[keyType][sec] = true;
                        keyFound = true;
                        Dbprintf("[=] Found valid key: %012" PRIx64 "", currentKey);
                    }
                }
            }

            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

            if (err) {
                SpinOff(500);
                continue;
            }

            if (allKeysFound) {
                DbpString("[" _GREEN_("+") "] " _GREEN_("All keys found"));
                state = STATE_LOAD;
                continue;
            } else if (keyFound) {
                DbpString("[" _RED_("!") "] " _RED_("Some keys could not be found!"));
                state = STATE_ATTACK;
                continue;
            } else {
                DbpString("[" _RED_("!") "] " _RED_("No keys found!"));
                DbpString("[" _RED_("!") "] " _RED_("There's nothing I can do without at least one valid key, sorry!"));
                SpinErr(LED_D, 250, 5);
                continue;
            }

        } else if (state == STATE_ATTACK) {
            // Do nested attack, set allKeysFound = true

            LED_A_OFF();
            LED_B_ON();
            LED_C_OFF();
            LED_D_OFF();

            // no room to run nested attack on device (iceman)
            DbpString("[" _RED_("!") "] " _RED_("There's currently no nested attack in MattyRun, sorry!"));
            // allKeysFound = true;

            state = STATE_LOAD;
            continue;

        } else if (state == STATE_LOAD) {
            // Transfer found keys to memory.
            // If enabled, load full card content into emulator memory.

            LED_A_OFF();
            LED_B_ON();
            LED_C_ON();
            LED_D_OFF();

            emlClearMem();

            uint8_t mblock[MIFARE_BLOCK_SIZE];
            for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; ++sectorNo) {
                if (validKey[0][sectorNo] || validKey[1][sectorNo]) {
                    emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
                    for (uint8_t keyType = 0; keyType < 2; ++keyType) {
                        if (validKey[keyType][sectorNo]) {
                            memcpy(mblock + keyType * 10, foundKey[keyType][sectorNo], 6);
                        }
                    }
                    emlSetMem_xt(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1, MIFARE_BLOCK_SIZE);
                }
            }

            DbpString("[=] Found keys have been transferred to the emulator memory.");

            if (MATTYRUN_NO_ECFILL) {
                state = STATE_READ;
                continue;
            }

            int filled;
            DbpString("[=] Filling emulator memory using key A");
            filled = MifareECardLoad(sectorsCnt, MF_KEY_A);
            if (filled != PM3_SUCCESS) {
                DbpString("[" _YELLOW_("-") "] " _YELLOW_("Only partially filled using key A, retry with key B!"));
                DbpString("[=] Filling emulator memory using key B");
                filled = MifareECardLoad(sectorsCnt, MF_KEY_B);
                if (filled != PM3_SUCCESS) {
                    DbpString("[" _YELLOW_("-") "] " _YELLOW_("Only partially filled using key B!"));
                }
            }
            if (filled != PM3_SUCCESS) {
                DbpString("[" _RED_("!") "] " _RED_("Emulator memory could not be completely filled due to errors!"));
                SpinErr(LED_D, 50, 8);
                partialEmulation = true;
            } else {
                DbpString("[" _GREEN_("+") "] " _GREEN_("Emulator memory filled completely."));
            }

            state = STATE_EMULATE;
            continue;

        } else if (state == STATE_EMULATE) {
            // Finally, emulate the cloned card.

            LED_A_ON();
            LED_B_ON();
            LED_C_ON();
            LED_D_OFF();

            DbpString("[=] Started emulation. Press button to abort at anytime.");
    
            if (partialEmulation) {
                LED_D_ON();
                DbpString("[=] Partial memory dump loaded. Trying best effort emulation approach.");
            }

            uint16_t simflags = 0;
            switch (mattyrun_card.uidlen) {
                case 4:  simflags |= FLAG_4B_UID_IN_DATA;  break;
                case 7:  simflags |= FLAG_7B_UID_IN_DATA;  break;
                case 10: simflags |= FLAG_10B_UID_IN_DATA; break;
                default: break;
            }
            uint16_t atqa = (uint16_t)bytes_to_num(mattyrun_card.atqa, 2);

            SpinDelay(1000);
            Mifare1ksim(simflags, 0, mattyrun_uid, atqa, mattyrun_card.sak);

            DbpString("[=] Emulation ended.");
            state = STATE_READ;
            continue;

        }
    }

    BigBuf_free_keep_EM();

    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5);
    DbpString("[=] Standalone mode MattyRun ended.");
    DbpString("");
    DbpString("[" _YELLOW_("-") "] " _YELLOW_("Download card clone with `hf mf esave [--mini|--1k|--2k|--4k] -f dump_file`."));
    DbpString("");
    DbpString("[=] You can take shell back :) ...");
    LEDsoff();
}
