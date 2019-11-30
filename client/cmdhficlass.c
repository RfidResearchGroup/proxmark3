//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
// Copyright (C) 2014 Midnitesnake & Andy Davies & Martin Holst Swende
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include "cmdhficlass.h"

#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
#include "cmdtrace.h"
#include "util_posix.h"

#include "comms.h"
#include "mbedtls/des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "fileutils.h"
#include "protocols.h"


#define NUM_CSNS 9
#define ICLASS_KEYS_MAX 8
#define ICLASS_AUTH_RETRY 10

static int CmdHelp(const char *Cmd);

static uint8_t iClass_Key_Table[ICLASS_KEYS_MAX][8] = {
    { 0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78 },
    { 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x00 },
    { 0x5B, 0x7C, 0x62, 0xC4, 0x91, 0xc1, 0x1b, 0x39 },
    { 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static int usage_hf_iclass_sim(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf iclass sim <option> [CSN]");
    PrintAndLogEx(NORMAL, "        options");
    PrintAndLogEx(NORMAL, "                0 <CSN> simulate the given CSN");
    PrintAndLogEx(NORMAL, "                1       simulate default CSN");
    PrintAndLogEx(NORMAL, "                2       Reader-attack, gather reader responses to extract elite key");
    PrintAndLogEx(NORMAL, "                3       Full simulation using emulator memory (see 'hf iclass eload')");
    PrintAndLogEx(NORMAL, "                4       Reader-attack, adapted for KeyRoll mode, gather reader responses to extract elite key");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass sim 0 031FEC8AF7FF12E0");
    PrintAndLogEx(NORMAL, "        hf iclass sim 2");
    PrintAndLogEx(NORMAL, "        hf iclass eload 'tagdump.bin'");
    PrintAndLogEx(NORMAL, "        hf iclass sim 3");
    PrintAndLogEx(NORMAL, "        hf iclass sim 4");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_eload(void) {
    PrintAndLogEx(NORMAL, "Loads iclass tag-dump into emulator memory on device");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass eload f <filename>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass eload f iclass_tagdump-aa162d30f8ff12f1.bin");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_decrypt(void) {
    PrintAndLogEx(NORMAL, "This is simple implementation, it tries to decrypt every block after block 6.");
    PrintAndLogEx(NORMAL, "Correct behaviour would be to decrypt only the application areas where the key is valid,");
    PrintAndLogEx(NORMAL, "which is defined by the configuration block.");
    PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
    PrintAndLogEx(NORMAL, "in the resources directory. The file should be 16 bytes binary data");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: hf iclass decrypt d <enc data> f <tagdump> k <transport key>");
    PrintAndLogEx(NORMAL, "        options");
    PrintAndLogEx(NORMAL, "              d <encrypted block>    16 bytes hex");
    PrintAndLogEx(NORMAL, "              f <filename>           filename of dump");
    PrintAndLogEx(NORMAL, "              k <transport key>      16 bytes hex");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "S       hf iclass decrypt f tagdump_1.bin");
    PrintAndLogEx(NORMAL, "S       hf iclass decrypt f tagdump_1.bin k 000102030405060708090a0b0c0d0e0f");
    PrintAndLogEx(NORMAL, "S       hf iclass decrypt d 1122334455667788 k 000102030405060708090a0b0c0d0e0f");

    return PM3_SUCCESS;
}
static int usage_hf_iclass_encrypt(void) {
    PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
    PrintAndLogEx(NORMAL, "in the resources directory. The file should be 16 bytes binary data");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: hf iclass encrypt d <blockdata> k <transport key>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass encrypt d 0102030405060708");
    PrintAndLogEx(NORMAL, "        hf iclass encrypt d 0102030405060708 k 00112233445566778899AABBCCDDEEFF");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf iclass dump f <fileName> k <key> c <creditkey> [e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to save dump to");
    PrintAndLogEx(NORMAL, "  k <key>      : <required> access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c <creditkey>: credit key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  e            : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r            : raw, the key is interpreted as raw block 3/4");
    PrintAndLogEx(NORMAL, "  v            : verbose output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass dump k 001122334455667B");
    PrintAndLogEx(NORMAL, "        hf iclass dump k AAAAAAAAAAAAAAAA c 001122334455667B");
    PrintAndLogEx(NORMAL, "        hf iclass dump k AAAAAAAAAAAAAAAA e");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_clone(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf iclass clone f <tagfile.bin> b <first block> l <last block> k <KEY> c e|r");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to clone from");
    PrintAndLogEx(NORMAL, "  b <Block>    : The first block to clone as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  l <Last Blk> : Set the Data to write as 16 hex symbols");
    PrintAndLogEx(NORMAL, "  k <Key>      : Access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c            : If 'c' is specified, the key set is assumed to be the credit key\n");
    PrintAndLogEx(NORMAL, "  e            : If 'e' is specified, elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r            : If 'r' is specified, no computations applied to key");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 06 l 1A k 1122334455667788 e");
    PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 05 l 19 k 0");
    PrintAndLogEx(NORMAL, "       hf iclass clone f iclass_tagdump-121345.bin b 06 l 19 k 0 e");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_writeblock(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf iclass writeblk b <block> d <data> k <key> [c|e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  b <Block> : The block number as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  d <data>  : set the Data to write as 16 hex symbols");
    PrintAndLogEx(NORMAL, "  k <Key>   : access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
    PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
    PrintAndLogEx(NORMAL, "  v         : verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass writeblk b 0A d AAAAAAAAAAAAAAAA k 001122334455667B");
    PrintAndLogEx(NORMAL, "        hf iclass writeblk b 1B d AAAAAAAAAAAAAAAA k 001122334455667B c");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_readblock(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf iclass rdbl b <block> k <key> [c|e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  b <block> : The block number as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  k <key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
    PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
    PrintAndLogEx(NORMAL, "  v         : verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass rdbl b 06 k 0011223344556677");
    PrintAndLogEx(NORMAL, "        hf iclass rdbl b 1B k 0011223344556677 c");
    PrintAndLogEx(NORMAL, "        hf iclass rdbl b 0A k 0");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_readtagfile() {
    PrintAndLogEx(NORMAL, "Usage: hf iclass readtagfile <filename> [startblock] [endblock]");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_calc_newkey(void) {
    PrintAndLogEx(NORMAL, "Calculate new key for updating\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass calc_newkey o <Old key> n <New key> s [csn] e");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  o <oldkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
    PrintAndLogEx(NORMAL, "  n <newkey> : *specify a key as 16 hex symbols or a key number as 1 symbol");
    PrintAndLogEx(NORMAL, "  s <csn>    : specify a card Serial number to diversify the key (if omitted will attempt to read a csn)");
    PrintAndLogEx(NORMAL, "  e          : specify new key as elite calc");
    PrintAndLogEx(NORMAL, "  ee         : specify old and new key as elite calc");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, " e key to e key given csn  : hf iclass calcnewkey o 1122334455667788 n 2233445566778899 s deadbeafdeadbeaf ee");
    PrintAndLogEx(NORMAL, " std key to e key read csn : hf iclass calcnewkey o 1122334455667788 n 2233445566778899 e");
    PrintAndLogEx(NORMAL, " std to std read csn       : hf iclass calcnewkey o 1122334455667788 n 2233445566778899");
    PrintAndLogEx(NORMAL, "\nNOTE: * = required\n");
    return PM3_SUCCESS;;
}
static int usage_hf_iclass_managekeys(void) {
    PrintAndLogEx(NORMAL, "HELP :  Manage iClass Keys in client memory:\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass managekeys n [keynbr] k [key] f [filename] s l p\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  n <keynbr>   : specify the keyNbr to set in memory");
    PrintAndLogEx(NORMAL, "  k <key>      : set a key in memory");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to use with load or save operations");
    PrintAndLogEx(NORMAL, "  s            : save keys in memory to file specified by filename");
    PrintAndLogEx(NORMAL, "  l            : load keys to memory from file specified by filename");
    PrintAndLogEx(NORMAL, "  p            : print keys loaded into memory\n");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, " set key       : hf iclass managekeys n 0 k 1122334455667788");
    PrintAndLogEx(NORMAL, " save key file : hf iclass managekeys f mykeys.bin s");
    PrintAndLogEx(NORMAL, " load key file : hf iclass managekeys f mykeys.bin l");
    PrintAndLogEx(NORMAL, " print keys    : hf iclass managekeys p\n");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_reader(void) {
    PrintAndLogEx(NORMAL, "Act as a Iclass reader.  Look for iClass tags until Enter or the pm3 button is pressed\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass reader [h] [1]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h   This help text");
    PrintAndLogEx(NORMAL, "    1   read only 1 tag");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass reader 1");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_replay(void) {
    PrintAndLogEx(NORMAL, "Replay a collected mac message");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass replay [h] <mac>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h       This help text");
    PrintAndLogEx(NORMAL, "    <mac>   Mac bytes to replay (8 hexsymbols)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass replay 00112233");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_sniff(void) {
    PrintAndLogEx(NORMAL, "Sniff the communication between reader and tag");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass sniff [h]");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf iclass sniff");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_loclass(void) {
    PrintAndLogEx(NORMAL, "Usage: hf iclass loclass [h] [t [l]] [f <filename>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             Show this help");
    PrintAndLogEx(NORMAL, "      t             Perform self-test");
    PrintAndLogEx(NORMAL, "      t l           Perform self-test, including long ones");
    PrintAndLogEx(NORMAL, "      f <filename>  Bruteforce iclass dumpfile");
    PrintAndLogEx(NORMAL, "                    An iclass dumpfile is assumed to consist of an arbitrary number of");
    PrintAndLogEx(NORMAL, "                    malicious CSNs, and their protocol responses");
    PrintAndLogEx(NORMAL, "                    The binary format of the file is expected to be as follows: ");
    PrintAndLogEx(NORMAL, "                    <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "                    <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "                    <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "                   ... totalling N*24 bytes");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_chk(void) {
    PrintAndLogEx(NORMAL, "Checkkeys loads a dictionary text file with 8byte hex keys to test authenticating against a iClass tag");
    PrintAndLogEx(NORMAL, "Usage: hf iclass chk [h|e|r] [f  (*.dic)]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             Show this help");
    PrintAndLogEx(NORMAL, "      f <filename>  Dictionary file with default iclass keys");
    PrintAndLogEx(NORMAL, "      r             raw");
    PrintAndLogEx(NORMAL, "      e             elite");
    PrintAndLogEx(NORMAL, "      c             credit key  (if not use, default is debit)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf iclass chk f dictionaries/iclass_default_keys.dic");
    PrintAndLogEx(NORMAL, "         hf iclass chk f dictionaries/iclass_default_keys.dic e");
    return PM3_SUCCESS;;
}
static int usage_hf_iclass_lookup(void) {
    PrintAndLogEx(NORMAL, "Lookup keys takes some sniffed trace data and tries to verify what key was used against a dictionary file");
    PrintAndLogEx(NORMAL, "Usage: hf iclass lookup [h|e|r] [f  (*.dic)] [u <csn>] [p <epurse>] [m <macs>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             Show this help");
    PrintAndLogEx(NORMAL, "      f <filename>  Dictionary file with default iclass keys");
    PrintAndLogEx(NORMAL, "      u             CSN");
    PrintAndLogEx(NORMAL, "      p             EPURSE");
    PrintAndLogEx(NORMAL, "      m             macs");
    PrintAndLogEx(NORMAL, "      r             raw");
    PrintAndLogEx(NORMAL, "      e             elite");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f dictionaries/iclass_default_keys.dic");
    PrintAndLogEx(NORMAL, "        hf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f dictionaries/iclass_default_keys.dic e");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_permutekey(void) {
    PrintAndLogEx(NORMAL, "Permute function from 'heart of darkness' paper.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass permute [h] <r|f> <bytes>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          This help");
    PrintAndLogEx(NORMAL, "           r          reverse permuted key");
    PrintAndLogEx(NORMAL, "           f          permute key");
    PrintAndLogEx(NORMAL, "           <bytes>    input bytes");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf iclass permute r 0123456789abcdef");
    return PM3_SUCCESS;
}

/*
static int xorbits_8(uint8_t val) {
    uint8_t res = val ^ (val >> 1); //1st pass
    res = res ^ (res >> 1);         // 2nd pass
    res = res ^ (res >> 2);         // 3rd pass
    res = res ^ (res >> 4);         // 4th pass
    return res & 1;
}
*/

// iclass / picopass chip config structures and shared routines
typedef struct {
    uint8_t app_limit;      //[8]
    uint8_t otp[2];         //[9-10]
    uint8_t block_writelock;//[11]
    uint8_t chip_config;    //[12]
    uint8_t mem_config;     //[13]
    uint8_t eas;            //[14]
    uint8_t fuses;          //[15]
} picopass_conf_block;


typedef struct {
    uint8_t csn[8];
    picopass_conf_block conf;
    uint8_t epurse[8];
    uint8_t key_d[8];
    uint8_t key_c[8];
    uint8_t app_issuer_area[8];
} picopass_hdr;

static uint8_t isset(uint8_t val, uint8_t mask) {
    return (val & mask);
}

static uint8_t notset(uint8_t val, uint8_t mask) {
    return !(val & mask);
}

static void fuse_config(const picopass_hdr *hdr) {
    uint8_t fuses = hdr->conf.fuses;

    if (isset(fuses, FUSE_FPERS))
        PrintAndLogEx(SUCCESS, "    Mode: Personalization [Programmable]");
    else
        PrintAndLogEx(SUCCESS, "    Mode: Application [Locked]");

    if (isset(fuses, FUSE_CODING1)) {
        PrintAndLogEx(SUCCESS, "    Coding: RFU");
    } else {
        if (isset(fuses, FUSE_CODING0))
            PrintAndLogEx(SUCCESS, "    Coding: ISO 14443-2 B/ISO 15693");
        else
            PrintAndLogEx(SUCCESS, "    Coding: ISO 14443B only");
    }
    // 1 1
    if (isset(fuses, FUSE_CRYPT1) && isset(fuses, FUSE_CRYPT0)) PrintAndLogEx(SUCCESS, "    Crypt: Secured page, keys not locked");
    // 1 0
    if (isset(fuses, FUSE_CRYPT1) && notset(fuses, FUSE_CRYPT0)) PrintAndLogEx(NORMAL, "    Crypt: Secured page, keys locked");
    // 0 1
    if (notset(fuses, FUSE_CRYPT1) && isset(fuses, FUSE_CRYPT0)) PrintAndLogEx(SUCCESS, "    Crypt: Non secured page");
    // 0 0
    if (notset(fuses, FUSE_CRYPT1) && notset(fuses, FUSE_CRYPT0)) PrintAndLogEx(NORMAL, "    Crypt: No auth possible. Read only if RA is enabled");

    if (isset(fuses, FUSE_RA))
        PrintAndLogEx(SUCCESS, "    RA: Read access enabled");
    else
        PrintAndLogEx(WARNING, "    RA: Read access not enabled");
}

static void getMemConfig(uint8_t mem_cfg, uint8_t chip_cfg, uint8_t *max_blk, uint8_t *app_areas, uint8_t *kb) {
    // mem-bit 5, mem-bit 7, chip-bit 4: defines chip type
    uint8_t k16 = isset(mem_cfg, 0x80);
    //uint8_t k2 = isset(mem_cfg, 0x08);
    uint8_t book = isset(mem_cfg, 0x20);

    if (isset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 2;
        *app_areas = 2;
        *max_blk = 31;
    } else if (isset(chip_cfg, 0x10) && k16 && !book) {
        *kb = 16;
        *app_areas = 2;
        *max_blk = 255; //16kb
    } else if (notset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 16;
        *app_areas = 16;
        *max_blk = 255; //16kb
    } else if (isset(chip_cfg, 0x10) && k16 && book) {
        *kb = 32;
        *app_areas = 3;
        *max_blk = 255; //16kb
    } else if (notset(chip_cfg, 0x10) && !k16 && book) {
        *kb = 32;
        *app_areas = 17;
        *max_blk = 255; //16kb
    } else {
        *kb = 32;
        *app_areas = 2;
        *max_blk = 255;
    }
}

static void mem_app_config(const picopass_hdr *hdr) {
    uint8_t mem = hdr->conf.mem_config;
    uint8_t chip = hdr->conf.chip_config;
    uint8_t applimit = hdr->conf.app_limit;
    uint8_t kb = 2;
    uint8_t app_areas = 2;
    uint8_t max_blk = 31;

    getMemConfig(mem, chip, &max_blk, &app_areas, &kb);

    if (applimit < 6) applimit = 26;
    if (kb == 2 && (applimit > 0x1f)) applimit = 26;

    PrintAndLogEx(NORMAL, " Mem: %u KBits/%u App Areas (%u * 8 bytes) [%02X]", kb, app_areas, max_blk, mem);
    PrintAndLogEx(NORMAL, "    AA1: blocks 06-%02X", applimit);
    PrintAndLogEx(NORMAL, "    AA2: blocks %02X-%02X", applimit + 1, max_blk);
    PrintAndLogEx(NORMAL, "    OTP: 0x%02X%02X", hdr->conf.otp[1],  hdr->conf.otp[0]);
    PrintAndLogEx(NORMAL, "    KeyAccess:");

    uint8_t book = isset(mem, 0x20);
    if (book) {
        PrintAndLogEx(NORMAL, "    Read A - Kd");
        PrintAndLogEx(NORMAL, "    Read B - Kc");
        PrintAndLogEx(NORMAL, "    Write A - Kd");
        PrintAndLogEx(NORMAL, "    Write B - Kc");
        PrintAndLogEx(NORMAL, "    Debit  - Kd or Kc");
        PrintAndLogEx(NORMAL, "    Credit - Kc");
    } else {
        PrintAndLogEx(NORMAL, "    Read A - Kd or Kc");
        PrintAndLogEx(NORMAL, "    Read B - Kd or Kc");
        PrintAndLogEx(NORMAL, "    Write A - Kc");
        PrintAndLogEx(NORMAL, "    Write B - Kc");
        PrintAndLogEx(NORMAL, "    Debit  - Kd or Kc");
        PrintAndLogEx(NORMAL, "    Credit - Kc");
    }
}
static void print_picopass_info(const picopass_hdr *hdr) {
    fuse_config(hdr);
    mem_app_config(hdr);
}
static void printIclassDumpInfo(uint8_t *iclass_dump) {
    print_picopass_info((picopass_hdr *) iclass_dump);
}


static int CmdHFiClassList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    //PrintAndLogEx(NORMAL, "Deprecated command, use 'hf list iclass' instead");
    CmdTraceList("iclass");
    return PM3_SUCCESS;
}

static int CmdHFiClassSniff(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_iclass_sniff();
    SendCommandNG(CMD_HF_ICLASS_SNIFF, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHFiClassSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_iclass_sim();

    uint8_t simType = 0;
    uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    simType = param_get8ex(Cmd, 0, 0, 10);

    if (simType == 0) {
        if (param_gethex(Cmd, 1, CSN, 16)) {
            PrintAndLogEx(ERR, "A CSN should consist of 16 HEX symbols");
            return usage_hf_iclass_sim();
        }
        PrintAndLogEx(NORMAL, " simtype: %02x csn: %s", simType, sprint_hex(CSN, 8));
    }

    if (simType > 4) {
        PrintAndLogEx(ERR, "Undefined simptype %d", simType);
        return usage_hf_iclass_sim();
    }

    /*
            // pre-defined 8 CSN by Holiman
            uint8_t csns[8*NUM_CSNS] = {
                0x00, 0x0B, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x13, 0x94, 0x7E, 0x76, 0xFF, 0x12, 0xE0,
                0x2A, 0x99, 0xAC, 0x79, 0xEC, 0xFF, 0x12, 0xE0,
                0x17, 0x12, 0x01, 0xFD, 0xF7, 0xFF, 0x12, 0xE0,
                0xCD, 0x56, 0x01, 0x7C, 0x6F, 0xFF, 0x12, 0xE0,
                0x4B, 0x5E, 0x0B, 0x72, 0xEF, 0xFF, 0x12, 0xE0,
                0x00, 0x73, 0xD8, 0x75, 0x58, 0xFF, 0x12, 0xE0,
                0x0C, 0x90, 0x32, 0xF3, 0x5D, 0xFF, 0x12, 0xE0
            };
    */
    /*
            pre-defined 9 CSN by iceman
            only one csn depend on several others.
            six depends only on the first csn,  (0,1, 0x45)
    */
    uint8_t csns[8 * NUM_CSNS] = {
        0x01, 0x0A, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
        0x0C, 0x06, 0x0C, 0xFE, 0xF7, 0xFF, 0x12, 0xE0,
        0x10, 0x97, 0x83, 0x7B, 0xF7, 0xFF, 0x12, 0xE0,
        0x13, 0x97, 0x82, 0x7A, 0xF7, 0xFF, 0x12, 0xE0,
        0x07, 0x0E, 0x0D, 0xF9, 0xF7, 0xFF, 0x12, 0xE0,
        0x14, 0x96, 0x84, 0x76, 0xF7, 0xFF, 0x12, 0xE0,
        0x17, 0x96, 0x85, 0x71, 0xF7, 0xFF, 0x12, 0xE0,
        0xCE, 0xC5, 0x0F, 0x77, 0xF7, 0xFF, 0x12, 0xE0,
        0xD2, 0x5A, 0x82, 0xF8, 0xF7, 0xFF, 0x12, 0xE0
        //0x04, 0x08, 0x9F, 0x78, 0x6E, 0xFF, 0x12, 0xE0
    };
    /*
            // pre-defined 15 CSN by Carl55
            // remember to change the define NUM_CSNS to match.
            uint8_t csns[8*NUM_CSNS] = {
                0x00, 0x0B, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x04, 0x0E, 0x08, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x09, 0x0D, 0x05, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x0A, 0x0C, 0x06, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x0F, 0x0B, 0x03, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x08, 0x0A, 0x0C, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x0D, 0x09, 0x09, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x0E, 0x08, 0x0A, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x03, 0x07, 0x17, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x3C, 0x06, 0xE0, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x01, 0x05, 0x1D, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x02, 0x04, 0x1E, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x07, 0x03, 0x1B, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x00, 0x02, 0x24, 0xF7, 0xFF, 0x12, 0xE0,
                0x00, 0x05, 0x01, 0x21, 0xF7, 0xFF, 0x12, 0xE0
            };
    */

    /* DUMPFILE FORMAT:
     *
     * <8-byte CSN><8-byte CC><4 byte NR><4 byte MAC>....
     * So, it should wind up as
     * 8 * 24 bytes.
     *
     * The returndata from the pm3 is on the following format
     * <4 byte NR><4 byte MAC>
     * CC are all zeroes, CSN is the same as was sent in
     **/
    uint8_t tries = 0;

    switch (simType) {

        case 2: {
            PrintAndLogEx(INFO, "Starting iCLASS sim 2 attack (elite mode)");
            PrintAndLogEx(INFO, "press Enter to cancel");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandOLD(CMD_HF_ICLASS_SIMULATE, simType, NUM_CSNS, 0, csns, 8 * NUM_CSNS);

            while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
                tries++;
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard.");
                    return PM3_EOPABORTED;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return PM3_ETIMEOUT;
                }
            }
            uint8_t num_mac  = resp.oldarg[1];
            bool success = (NUM_CSNS == num_mac);
            PrintAndLogEx(NORMAL, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS, (success) ? "OK" : "FAIL");

            if (num_mac == 0)
                break;

            size_t datalen = NUM_CSNS * 24;
            uint8_t *dump = calloc(datalen, sizeof(uint8_t));
            if (!dump) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return PM3_EMALLOC;
            }

            memset(dump, 0, datalen);//<-- Need zeroes for the EPURSE - field (offical)

            uint8_t i = 0;
            for (i = 0 ; i < NUM_CSNS ; i++) {
                //copy CSN
                memcpy(dump + i * 24, csns + i * 8, 8);
                //copy epurse
                memcpy(dump + i * 24 + 8, resp.data.asBytes + i * 16, 8);
                // NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
                memcpy(dump + i * 24 + 16, resp.data.asBytes + i * 16 + 8, 8);
            }
            /** Now, save to dumpfile **/
            saveFile("iclass_mac_attack", ".bin", dump, datalen);
            free(dump);
            break;
        }
        case 4: {
            // reader in key roll mode,  when it has two keys it alternates when trying to verify.
            PrintAndLogEx(INFO, "Starting iCLASS sim 4 attack (elite mode, reader in key roll mode)");
            PrintAndLogEx(INFO, "press Enter to cancel");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandOLD(CMD_HF_ICLASS_SIMULATE, simType, NUM_CSNS, 0, csns, 8 * NUM_CSNS);

            while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
                tries++;
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard.");
                    return PM3_EOPABORTED;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return PM3_ETIMEOUT;
                }
            }
            uint8_t num_mac = resp.oldarg[1];
            bool success = ((NUM_CSNS * 2) == num_mac);
            PrintAndLogEx(NORMAL, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS * 2, (success) ? "OK" : "FAIL");

            if (num_mac == 0)
                break;

            size_t datalen = NUM_CSNS * 24;
            uint8_t *dump = calloc(datalen, sizeof(uint8_t));
            if (!dump) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return PM3_EMALLOC;
            }

#define MAC_ITEM_SIZE 24

            //KEYROLL 1
            //Need zeroes for the CC-field
            memset(dump, 0, datalen);
            for (uint8_t i = 0; i < NUM_CSNS ; i++) {
                // copy CSN
                memcpy(dump + i * MAC_ITEM_SIZE, csns + i * 8, 8); //CSN
                // copy EPURSE
                memcpy(dump + i * MAC_ITEM_SIZE + 8, resp.data.asBytes + i * 16, 8);
                // copy NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
                memcpy(dump + i * MAC_ITEM_SIZE + 16, resp.data.asBytes + i * 16 + 8, 8);
            }
            saveFile("iclass_mac_attack_keyroll_A", ".bin", dump, datalen);

            //KEYROLL 2
            memset(dump, 0, datalen);
            for (uint8_t i = 0; i < NUM_CSNS; i++) {
                uint8_t resp_index = (i + NUM_CSNS) * 16;
                // Copy CSN
                memcpy(dump + i * MAC_ITEM_SIZE, csns + i * 8, 8);
                // copy EPURSE
                memcpy(dump + i * MAC_ITEM_SIZE + 8, resp.data.asBytes + resp_index, 8);
                // copy NR_MAC (eight bytes from the response)  ( 8b csn + 8 epurse == 16)
                memcpy(dump + i * MAC_ITEM_SIZE + 16, resp.data.asBytes + resp_index + 8, 8);
                resp_index++;
            }
            saveFile("iclass_mac_attack_keyroll_B", ".bin", dump, datalen);
            free(dump);
            break;
        }
        case 1:
        case 3:
        default: {
            uint8_t numberOfCSNs = 0;
            clearCommandBuffer();
            SendCommandOLD(CMD_HF_ICLASS_SIMULATE, simType, numberOfCSNs, 0, CSN, 8);
            break;
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassInfo(const char *Cmd) {
    return PM3_SUCCESS;
}

static int CmdHFiClassReader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_iclass_reader();
    bool findone = (cmdp == '1') ? false : true;
    return readIclass(findone, true);
}

static int CmdHFiClassReader_Replay(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_iclass_replay();

    uint8_t readerType = 0;
    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};

    if (param_gethex(Cmd, 0, MAC, 8)) {
        PrintAndLogEx(FAILED, "MAC must include 8 HEX symbols");
        return 1;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_REPLAY, readerType, 0, 0, MAC, 4);
    return PM3_SUCCESS;
}

static int CmdHFiClassELoad(const char *Cmd) {

    DumpFileType_t dftype = BIN;
    char filename[FILE_PATH_SIZE] = {0};
    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_eload();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 'j':
                dftype = JSON;
                cmdp++;
                break;
            case 'e':
                dftype = EML;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) {
        usage_hf_iclass_eload();
        return PM3_EINVARG;
    }


    uint8_t *dump = calloc(2048, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    size_t bytes_read = 2048;
    int res = 0;

    switch (dftype) {
        case BIN: {
            res = loadFile_safe(filename, ".bin", (void **)&dump, &bytes_read);
            break;
        }
        case EML: {
            res = loadFileEML(filename, dump, &bytes_read);
            break;
        }
        case JSON: {
            res = loadFileJSON(filename, dump, 2048, &bytes_read);
            break;
        }
        default:
            PrintAndLogEx(ERR, "No dictionary loaded");
            free(dump);
            return PM3_ESOFT;
    }

    if (res != PM3_SUCCESS) {
        free(dump);
        return PM3_EFILE;
    }

    uint8_t *newdump = realloc(dump, bytes_read);
    if (newdump == NULL) {
        free(dump);
        return PM3_EMALLOC;
    } else {
        dump = newdump;
    }

    printIclassDumpInfo(dump);

    // fast push mode
    conn.block_after_ACK = true;

    //Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining  = bytes_read;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_HF_ICLASS_EML_MEMSET, bytes_sent, bytes_in_packet, 0, dump + bytes_sent, bytes_in_packet);
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
    }
    free(dump);

    PrintAndLogEx(SUCCESS, "sent %d bytes of data to device emulator memory", bytes_sent);
    return PM3_SUCCESS;
}

#define ICLASS_DECRYPTION_BIN  "iclass_decryptionkey.bin"

static int CmdHFiClassDecrypt(const char *Cmd) {

    bool errors = false;
    bool have_key = false;
    bool have_data = false;
    bool have_file = false;
    uint8_t cmdp = 0;

    uint8_t enc_data[8] = {0};

    size_t keylen = 0;
    uint8_t key[32] = {0};
    uint8_t *keyptr = NULL;

    size_t decryptedlen = 0;
    uint8_t *decrypted = NULL;
    char filename[FILE_PATH_SIZE];

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_decrypt();
            case 'd':
                if (param_gethex(Cmd, cmdp + 1, enc_data, 16)) {
                    PrintAndLogEx(ERR, "data must be 16 HEX symbols");
                    errors = true;
                    break;
                }
                have_data = true;
                cmdp += 2;
                break;
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, sizeof(filename)) == 0) {
                    PrintAndLogEx(WARNING, "no filename found after f");
                    errors = true;
                    break;
                }

                if (loadFile_safe(filename, "", (void **)&decrypted, &decryptedlen) != PM3_SUCCESS) {
                    errors = true;
                    break;
                }
                have_file = true;
                cmdp += 2;
                break;
            case 'k':
                if (param_gethex(Cmd, cmdp + 1, key, 32)) {
                    PrintAndLogEx(ERR, "Transport key must include 32 HEX symbols");
                    errors = true;
                }
                have_key = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp < 1) return usage_hf_iclass_decrypt();

    if (have_key == false) {
        int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
        if (res != PM3_SUCCESS)
            return PM3_EINVARG;

        memcpy(key, keyptr, sizeof(key));
        free(keyptr);
    }

    // tripledes
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    uint8_t dec_data[8] = {0};

    if (have_data) {
        mbedtls_des3_crypt_ecb(&ctx, enc_data, dec_data);
        PrintAndLogEx(SUCCESS, "Data: %s", sprint_hex(dec_data, sizeof(dec_data)));
    }

    if (have_file) {
        picopass_hdr *hdr = (picopass_hdr *)decrypted;

        uint8_t mem = hdr->conf.mem_config;
        uint8_t chip = hdr->conf.chip_config;
        uint8_t applimit = hdr->conf.app_limit;
        uint8_t kb = 2;
        uint8_t app_areas = 2;
        uint8_t max_blk = 31;
        getMemConfig(mem, chip, &max_blk, &app_areas, &kb);

        uint8_t empty[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        for (uint16_t blocknum = 0; blocknum < applimit; ++blocknum) {

            uint8_t idx = blocknum * 8;
            memcpy(enc_data, decrypted + idx, 8);

            // block 7 or higher,  and not empty 0xFF
            if (blocknum > 6 &&  memcmp(enc_data, empty, 8) != 0) {
                mbedtls_des3_crypt_ecb(&ctx, enc_data, decrypted + idx);
            }
        }

        //Use the first block (CSN) for filename
        char *fptr = calloc(42, sizeof(uint8_t));
        strcat(fptr, "hf-iclass-");
        FillFileNameByUID(fptr, hdr->csn, "-data-decrypted", sizeof(hdr->csn));

        saveFile(fptr, ".bin", decrypted, decryptedlen);
        saveFileEML(fptr, decrypted, decryptedlen, 8);
        saveFileJSON(fptr, jsfIclass, decrypted, decryptedlen);

        printIclassDumpContents(decrypted, 1, (decryptedlen / 8), decryptedlen);
        free(decrypted);
        free(fptr);
    }

    mbedtls_des3_free(&ctx);
    return PM3_SUCCESS;
}

static void iClassEncryptBlkData(uint8_t *blk_data, uint8_t *key) {
    uint8_t encrypted_data[16];
    uint8_t *encrypted = encrypted_data;
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);
    mbedtls_des3_crypt_ecb(&ctx, blk_data, encrypted);
    memcpy(blk_data, encrypted, 8);
    mbedtls_des3_free(&ctx);
}

static int CmdHFiClassEncryptBlk(const char *Cmd) {
    bool errors = false;
    bool have_key = false;
    uint8_t blk_data[8] = {0};
    uint8_t key[16] = {0};
    uint8_t *keyptr = NULL;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_encrypt();
            case 'd':
                if (param_gethex(Cmd, cmdp + 1, blk_data, 16)) {
                    PrintAndLogEx(ERR, "Block data must include 16 HEX symbols");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'k':
                if (param_gethex(Cmd, cmdp + 1, key, 32)) {
                    PrintAndLogEx(ERR, "Transport key must include 32 HEX symbols");
                    errors = true;
                }
                have_key = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp < 1) return usage_hf_iclass_encrypt();

    if (have_key == false) {
        size_t keylen = 0;
        int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
        if (res != PM3_SUCCESS)
            return PM3_EINVARG;

        memcpy(key, keyptr, sizeof(key));
        free(keyptr);
    }

    iClassEncryptBlkData(blk_data, key);

    printvar("encrypted block", blk_data, 8);
    return PM3_SUCCESS;
}

static void Calc_wb_mac(uint8_t blockno, uint8_t *data, uint8_t *div_key, uint8_t MAC[4]) {
    uint8_t wb[9];
    wb[0] = blockno;
    memcpy(wb + 1, data, 8);
    doMAC_N(wb, sizeof(wb), div_key, MAC);
}

static bool select_only(uint8_t *CSN, uint8_t *CCNR, bool use_credit_key, bool verbose) {
    PacketResponseNG resp;
    uint8_t flags = FLAG_ICLASS_READER_ONLY_ONCE | FLAG_ICLASS_READER_CC | FLAG_ICLASS_READER_ONE_TRY;

    if (use_credit_key)
        flags |= FLAG_ICLASS_READER_CEDITKEY;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "command execute timeout");
        return false;
    }

    uint8_t isOK = resp.oldarg[0] & 0xff;
    uint8_t *data = resp.data.asBytes;

    memcpy(CSN, data, 8);

    if (CCNR != NULL)
        memcpy(CCNR, data + 16, 8);

    if (isOK > 0 && verbose) {
        PrintAndLogEx(SUCCESS, "CSN  | %s", sprint_hex(CSN, 8));
        PrintAndLogEx(SUCCESS, "CCNR | %s", sprint_hex(CCNR, 8));
    }

    if (isOK <= 1) {
        if (verbose)
            PrintAndLogEx(FAILED, "failed to obtain CC! Tag-select is aborting...  (%d)", isOK);

        return false;
    }
    return true;
}

static bool select_and_auth(uint8_t *KEY, uint8_t *MAC, uint8_t *div_key, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
    uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (!select_only(CSN, CCNR, use_credit_key, verbose)) {
        if (verbose) PrintAndLogEx(FAILED, "selecting tag failed");

//        DropField();
        return false;
    }
    //get div_key
    if (rawkey)
        memcpy(div_key, KEY, 8);
    else
        HFiClassCalcDivKey(CSN, KEY, div_key, elite);

    if (verbose) PrintAndLogEx(SUCCESS, "authing with %s: %s", rawkey ? "raw key" : "diversified key", sprint_hex(div_key, 8));

    doMAC(CCNR, div_key, MAC);

    PacketResponseNG resp;
    clearCommandBuffer();

    SendCommandNG(CMD_HF_ICLASS_AUTH, MAC, 4);
    if (WaitForResponseTimeout(CMD_HF_ICLASS_AUTH, &resp, 2000) == 0) {
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return false;
    }

    uint8_t isOK = resp.data.asBytes[0];
    if (isOK == 0) {
        if (verbose) PrintAndLogEx(FAILED, "authentication error");
        return false;
    }

    return true;
}

static int CmdHFiClassReader_Dump(const char *Cmd) {

    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t c_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t blockno = 0;
    uint8_t numblks = 0;
    uint8_t maxBlk = 31;
    uint8_t app_areas = 1;
    uint8_t kb = 2;
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CreditKEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char tempStr[50] = {0};
    bool have_debit_key = false;
    bool have_credit_key = false;
    bool use_credit_key = false;
    bool elite = false;
    bool rawkey = false;
    bool errors = false;
    bool verbose = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_dump();
            case 'c':
                have_credit_key = true;
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, CreditKEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(CreditKEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'e':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
                elite = true;
                cmdp++;
                break;
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                if (fileNameLen < 1) {
                    PrintAndLogEx(WARNING, "no filename found after f");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'k':
                have_debit_key = true;
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(KEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'r':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("raw mode"));
                rawkey = true;
                cmdp++;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || cmdp < 2) return usage_hf_iclass_dump();

    // if no debit key given try credit key on AA1 (not for iclass but for some picopass this will work)
    if (!have_debit_key && have_credit_key) use_credit_key = true;

    uint32_t flags = FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CC |
                     FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_ONLY_ONCE |
                     FLAG_ICLASS_READER_ONE_TRY;

    //get config and first 3 blocks
    PacketResponseNG resp;
    uint8_t tag_data[255 * 8];

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
        PrintAndLogEx(WARNING, "command execute timeout");
        DropField();
        return PM3_ESOFT;
    }
    DropField();

    uint8_t readStatus = resp.oldarg[0] & 0xff;
    uint8_t *data  = resp.data.asBytes;

    if (readStatus == 0) {
        PrintAndLogEx(FAILED, "no tag found");
        DropField();
        return PM3_ESOFT;
    }

    if (readStatus & (FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_CC)) {
        memcpy(tag_data, data, 8 * 3);
        blockno += 2; // 2 to force re-read of block 2 later. (seems to respond differently..)
        numblks = data[8];
        getMemConfig(data[13], data[12], &maxBlk, &app_areas, &kb);
        // large memory - not able to dump pages currently
        if (numblks > maxBlk) numblks = maxBlk;
    }

    // authenticate debit key and get div_key - later store in dump block 3
    int numberAuthRetries = ICLASS_AUTH_RETRY;
    do {
        if (select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
            break;
    } while (numberAuthRetries--);

    if (numberAuthRetries <= 0) {
        PrintAndLogEx(WARNING, "failed authenticating with debit key");
        DropField();
        return PM3_ESOFT;
    }

    // begin dump
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_DUMP, blockno, numblks - blockno + 1, 0, NULL, 0);
    while (true) {
        printf(".");
        fflush(stdout);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\n[!] aborted via keyboard!\n");
            DropField();
            return 0;
        }

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000))
            break;
    }
    // dump cmd switch off at device when finised.

    uint32_t blocksRead = resp.oldarg[1];
    uint8_t isOK = resp.oldarg[0] & 0xff;
    if (!isOK && !blocksRead) {
        PrintAndLogEx(WARNING, "read block failed");
        return PM3_ESOFT;
    }

    uint32_t startindex = resp.oldarg[2];
    if (blocksRead * 8 > sizeof(tag_data) - (blockno * 8)) {
        PrintAndLogEx(FAILED, "data exceeded buffer size!");
        blocksRead = (sizeof(tag_data) / 8) - blockno;
    }

    // response ok - now get bigbuf content of the dump
    if (!GetFromDevice(BIG_BUF, tag_data + (blockno * 8), blocksRead * 8, startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    size_t gotBytes = blocksRead * 8 + blockno * 8;

    // try AA2
    if (have_credit_key) {
        //turn off hf field before authenticating with different key
        DropField();

        memset(MAC, 0, 4);

        // AA2 authenticate credit key and git c_div_key - later store in dump block 4
        numberAuthRetries = ICLASS_AUTH_RETRY;
        do {
            if (select_and_auth(CreditKEY, MAC, c_div_key, true, elite, rawkey, verbose))
                break;
        } while (numberAuthRetries--);

        if (numberAuthRetries <= 0) {
            PrintAndLogEx(WARNING, "failed authenticating with credit key");
            DropField();
            return PM3_ESOFT;
        }

        // do we still need to read more block?  (aa2 enabled?)
        if (maxBlk > blockno + numblks + 1) {
            // setup dump and start
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_DUMP, blockno + blocksRead, maxBlk - (blockno + blocksRead), 0, NULL, 0);
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
                PrintAndLogEx(WARNING, "command execute timeout 2");
                return PM3_ETIMEOUT;
            }
            isOK = resp.oldarg[0] & 0xff;
            blocksRead = resp.oldarg[1];
            if (!isOK && !blocksRead) {
                PrintAndLogEx(WARNING, "read block failed 2");
                return PM3_ESOFT;
            }

            startindex = resp.oldarg[2];
            if (blocksRead * 8 > sizeof(tag_data) - gotBytes) {
                PrintAndLogEx(FAILED, "data exceeded buffer size!");
                blocksRead = (sizeof(tag_data) - gotBytes) / 8;
            }
            // get dumped data from bigbuf
            if (!GetFromDevice(BIG_BUF, tag_data + gotBytes, blocksRead * 8, startindex, NULL, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "command execution time out");
                return PM3_ETIMEOUT;
            }

            gotBytes += blocksRead * 8;
        }
    }

    DropField();

    // add diversified keys to dump
    if (have_debit_key)
        memcpy(tag_data + (3 * 8), div_key, 8);

    if (have_credit_key)
        memcpy(tag_data + (4 * 8), c_div_key, 8);


    // print the dump
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "------+--+-------------------------+");
    PrintAndLogEx(NORMAL, "CSN   |00| %s|", sprint_hex(tag_data, 8));
    printIclassDumpContents(tag_data, 1, (gotBytes / 8), gotBytes);

    if (filename[0] == 0) {
        //Use the first block (CSN) for filename
        strcat(filename, "hf-iclass-");
        FillFileNameByUID(filename, tag_data, "-data", 8);
    }

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %zu blocks read", gotBytes / 8);
    saveFile(filename, ".bin", tag_data, gotBytes);
    saveFileEML(filename, tag_data, gotBytes, 8);
    saveFileJSON(filename, jsfIclass, tag_data, gotBytes);
    return PM3_SUCCESS;
}

static int WriteBlock(uint8_t blockno, uint8_t *bldata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool verbose) {

    int numberAuthRetries = ICLASS_AUTH_RETRY;
    do {

        uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
        uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)) {
            numberAuthRetries--;
            DropField();
            continue;
        }

        Calc_wb_mac(blockno, bldata, div_key, MAC);

        struct p {
            uint8_t blockno;
            uint8_t data[12];
        } PACKED payload;
        payload.blockno = blockno;

        memcpy(payload.data, bldata, 8);
        memcpy(payload.data + 8, MAC, 4);

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_WRITEBL, (uint8_t *)&payload, sizeof(payload));
        PacketResponseNG resp;

        if (WaitForResponseTimeout(CMD_HF_ICLASS_WRITEBL, &resp, 4000) == 0) {
            if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
            DropField();
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
            DropField();
            return PM3_EWRONGANSVER;
        }

        if (resp.data.asBytes[0] == 1)
            break;

    } while (numberAuthRetries);

    DropField();

    if (numberAuthRetries > 0) {
        PrintAndLogEx(SUCCESS, "Write block %02X successful\n", blockno);
    } else {
        PrintAndLogEx(ERR, "failed to authenticate and write block");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int CmdHFiClass_WriteBlock(const char *Cmd) {
    uint8_t blockno = 0;
    uint8_t bldata[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    char tempStr[50] = {0};
    bool got_blockno = false;
    bool use_credit_key = false;
    bool elite = false;
    bool rawkey = false;
    bool errors = false;
    bool verbose = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_writeblock();
            case 'b':
                blockno = param_get8ex(Cmd, cmdp + 1, 07, 16);
                got_blockno = true;
                cmdp += 2;
                break;
            case 'c':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("CREDIT"));
                use_credit_key = true;
                cmdp++;
                break;
            case 'd':
                if (param_gethex(Cmd, cmdp + 1, bldata, 16)) {
                    PrintAndLogEx(WARNING, "Data must include 16 HEX symbols\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'e':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
                elite = true;
                cmdp++;
                break;
            case 'k':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        PrintAndLogEx(SUCCESS, "Using key[%d] %s", keyNbr, sprint_hex(iClass_Key_Table[keyNbr], 8));
                        memcpy(KEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'r':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("raw mode"));
                rawkey = true;
                cmdp++;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (got_blockno == false)
        errors = true;

    if (errors || cmdp < 6) return usage_hf_iclass_writeblock();

    return WriteBlock(blockno, bldata, KEY, use_credit_key, elite, rawkey, verbose);
}

static int CmdHFiClassCloneTag(const char *Cmd) {
    char filename[FILE_PATH_SIZE] = { 0x00 };
    char tempStr[50] = {0};
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t fileNameLen = 0;
    uint8_t startblock = 0;
    uint8_t endblock = 0;
    uint8_t dataLen = 0;
    bool got_startblk = false, got_endblk = false;
    bool use_credit_key = false;
    bool elite = false;
    bool rawkey = false;
    bool errors = false;
    bool verbose = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_clone();
            case 'b':
                startblock = param_get8ex(Cmd, cmdp + 1, 07, 16);
                got_startblk = true;
                cmdp += 2;
                break;
            case 'c':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("CREDIT"));
                use_credit_key = true;
                cmdp++;
                break;
            case 'e':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
                elite = true;
                cmdp++;
                break;
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                if (fileNameLen < 1) {
                    PrintAndLogEx(WARNING, "No filename found after f");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'k':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        PrintAndLogEx(SUCCESS, "Using key[%d] %s", keyNbr, sprint_hex(iClass_Key_Table[keyNbr], 8));
                        memcpy(KEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'l':
                endblock = param_get8ex(Cmd, cmdp + 1, 07, 16);
                got_endblk = true;
                cmdp += 2;
                break;
            case 'r':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("raw mode"));
                rawkey = true;
                cmdp++;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (got_endblk == false || got_startblk == false)
        errors = true;

    if (errors || cmdp < 8) return usage_hf_iclass_clone();

    if (startblock < 5) {
        PrintAndLogEx(WARNING, "you cannot write key blocks this way. yet... make your start block > 4");
        return PM3_EINVARG;
    }

    int total_bytes = (((endblock - startblock) + 1) * 12);

    if (total_bytes > PM3_CMD_DATA_SIZE - 2) {
        PrintAndLogEx(NORMAL, "Trying to write too many blocks at once.  Max: %d", PM3_CMD_DATA_SIZE / 8);
        return PM3_EINVARG;
    }

    // file handling and reading
    FILE *f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    iclass_block_t tag_data[PM3_CMD_DATA_SIZE / 12];

    // read data from file from block 6 --- 19
    // we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
    // then copy to usbcommand->asbytes;
    // max is 32 - 6 = 28 block.  28 x 12 bytes gives 336 bytes
    int i;
    fseek(f, startblock * 8, SEEK_SET);
    size_t bytes_read = fread(tag_data, sizeof(iclass_block_t), endblock - startblock + 1, f);
    fclose(f);

    if (bytes_read == 0) {
        PrintAndLogEx(ERR, "file reading error.");
        return PM3_EFILE;
    }

    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    int numberAuthRetries = ICLASS_AUTH_RETRY;
    do {
        if (select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
            break;
    } while (numberAuthRetries--);

    if (numberAuthRetries <= 0) {
        PrintAndLogEx(ERR, "failed to authenticate");
        DropField();
        return PM3_ESOFT;
    }

    uint8_t data[total_bytes];

    // calculate all mac for every the block we will write
    for (i = startblock; i <= endblock; i++) {

        Calc_wb_mac(i, tag_data[i - startblock].d, div_key, MAC);
        // usb command d start pointer = d + (i - 6) * 12
        // memcpy(pointer,tag_data[i - 6],8) 8 bytes
        // memcpy(pointer + 8,mac,sizoof(mac) 4 bytes;
        // next one
        uint8_t *ptr = data + (i - startblock) * 12;
        memcpy(ptr, &(tag_data[i - startblock].d[0]), 8);
        memcpy(ptr + 8, MAC, 4);
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "------+--------------------------+-------------");
        PrintAndLogEx(NORMAL, "block | data                     | mac");
        PrintAndLogEx(NORMAL, "------+--------------------------+-------------");
        uint8_t p[12];
        for (i = 0; i <= endblock - startblock; i++) {
            memcpy(p, data + (i * 12), 12);
            char *s = calloc(70, sizeof(uint8_t));
            sprintf(s, "| %s ", sprint_hex(p, 8));
            sprintf(s + strlen(s), "| %s", sprint_hex(p + 8, 4));
            PrintAndLogEx(NORMAL, "  %02X  %s", i + startblock, s);
            free(s);
        }
    }

    struct p {
        uint8_t startblock;
        uint8_t endblock;
        uint8_t data[PM3_CMD_DATA_SIZE - 2];
    } PACKED payload;

    payload.startblock = startblock;
    payload.endblock = endblock;
    memcpy(payload.data, data, total_bytes);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_CLONE, (uint8_t *)&payload, total_bytes + 2);

    if (WaitForResponseTimeout(CMD_HF_ICLASS_CLONE, &resp, 4500) == 0) {
        PrintAndLogEx(WARNING, "command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (resp.data.asBytes[0] == 1)
            PrintAndLogEx(SUCCESS, "Clone successful");
        else
            PrintAndLogEx(WARNING, "Clone failed");
    }
    return resp.status;
}

static int ReadBlock(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool verbose, bool auth) {

    int numberAuthRetries = ICLASS_AUTH_RETRY;
    // return data.
    struct p {
        bool isOK;
        uint8_t blockdata[8];
    } PACKED;

    struct p *result = NULL;

    do {
        // block 0,1 should always be able to read,  and block 5 on some cards.
        if (auth || blockno >= 2) {
            uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
            uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            if (!select_and_auth(KEY, MAC, div_key, (keyType == 0x18), elite, rawkey, verbose)) {
                numberAuthRetries--;
                DropField();
                continue;
            }
        } else {
            uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            if (!select_only(CSN, CCNR, (keyType == 0x18), verbose)) {
                numberAuthRetries--;
                DropField();
                continue;
            }
        }

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_READBL, (uint8_t *)&blockno, sizeof(uint8_t));

        if (WaitForResponseTimeout(CMD_HF_ICLASS_READBL, &resp, 2000) == 0) {
            if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
            DropField();
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
            DropField();
            return PM3_EWRONGANSVER;
        }

        result = (struct p *)resp.data.asBytes;
        if (result->isOK)
            break;

    } while (numberAuthRetries);

    DropField();

    if (numberAuthRetries == 0) {
        PrintAndLogEx(ERR, "failed to authenticate and read block");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "block %02X: %s\n", blockno, sprint_hex(result->blockdata, sizeof(result->blockdata)));
    return PM3_SUCCESS;
}

static int CmdHFiClass_ReadBlock(const char *Cmd) {
    uint8_t blockno = 0;
    uint8_t keyType = 0x88; //debit key
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    char tempStr[50] = {0};
    bool got_blockno = false;
    bool elite = false;
    bool rawkey = false;
    bool errors = false;
    bool auth = false;
    bool verbose = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_readblock();
            case 'b':
                blockno = param_get8ex(Cmd, cmdp + 1, 7, 16);
                got_blockno = true;
                cmdp += 2;
                break;
            case 'c':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("CREDIT"));
                keyType = 0x18;
                cmdp++;
                break;
            case 'e':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
                elite = true;
                cmdp++;
                break;
            case 'k':
                auth = true;
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        PrintAndLogEx(SUCCESS, "Using key[%d] %s", keyNbr, sprint_hex(iClass_Key_Table[keyNbr], 8));
                        memcpy(KEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'r':
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("raw mode"));
                rawkey = true;
                cmdp++;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (got_blockno == false)
        errors = true;

    if (errors || cmdp < 4) return usage_hf_iclass_readblock();

    if (!auth)
        PrintAndLogEx(FAILED, "warning: no authentication used with read, only a few specific blocks can be read accurately without authentication.");

    return ReadBlock(KEY, blockno, keyType, elite, rawkey, verbose, auth);
}

static int CmdHFiClass_loclass(const char *Cmd) {
    char opt = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 1 || opt == 'h')
        return usage_hf_iclass_loclass();

    if (opt == 'f') {
        char fileName[FILE_PATH_SIZE] = {0};
        if (param_getstr(Cmd, 1, fileName, sizeof(fileName)) > 0) {
            return bruteforceFileNoKeys(fileName);
        } else {
            PrintAndLogEx(WARNING, "You must specify a filename");
            return PM3_EFILE;
        }
    } else if (opt == 't') {
        char opt2 = tolower(param_getchar(Cmd, 1));
        int errors = testCipherUtils();
        errors += testMAC();
        errors += doKeyTests(0);
        errors += testElite(opt2 == 'l');
        if (errors) PrintAndLogEx(ERR, "There were errors!!!");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize) {
    uint8_t mem_config;
    memcpy(&mem_config, iclass_dump + 13, 1);
    uint8_t maxmemcount;

    uint8_t filemaxblock = filesize / 8;

    if (mem_config & 0x80)
        maxmemcount = 255;
    else
        maxmemcount = 31;

    if (startblock == 0)
        startblock = 6;

    if ((endblock > maxmemcount) || (endblock == 0))
        endblock = maxmemcount;

    // remember endblock needs to relate to zero-index arrays.
    if (endblock > filemaxblock - 1)
        endblock = filemaxblock - 1;

    //PrintAndLog ("startblock: %d, endblock: %d, filesize: %d, maxmemcount: %d, filemaxblock: %d",startblock, endblock,filesize, maxmemcount, filemaxblock);

    int i = startblock;
    PrintAndLogEx(NORMAL, "------+--+-------------------------+");
    while (i <= endblock) {
        uint8_t *blk = iclass_dump + (i * 8);
        PrintAndLogEx(NORMAL, "      |%02X| %s", i, sprint_hex_ascii(blk, 8));
        i++;
    }
    PrintAndLogEx(NORMAL, "------+--+-------------------------+");
}

static int CmdHFiClassReadTagFile(const char *Cmd) {
    int startblock = 0;
    int endblock = 0;
    char tempnum[5];
    FILE *f;
    char filename[FILE_PATH_SIZE];
    if (param_getstr(Cmd, 0, filename, sizeof(filename)) < 1)
        return usage_hf_iclass_readtagfile();

    if (param_getstr(Cmd, 1, tempnum, sizeof(tempnum)) < 1)
        startblock = 0;
    else
        sscanf(tempnum, "%d", &startblock);

    if (param_getstr(Cmd, 2, tempnum, sizeof(tempnum)) < 1)
        endblock = 0;
    else
        sscanf(tempnum, "%d", &endblock);

    // file handling and reading
    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(ERR, "Error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        return 1;
    }
    size_t bytes_read = fread(dump, 1, fsize, f);
    fclose(f);

    uint8_t *csn = dump;
    PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
    PrintAndLogEx(NORMAL, "CSN   |00| %s|\n", sprint_hex(csn, 8));
    printIclassDumpContents(dump, startblock, endblock, bytes_read);
    free(dump);
    return PM3_SUCCESS;
}

void HFiClassCalcDivKey(uint8_t *CSN, uint8_t *KEY, uint8_t *div_key, bool elite) {
    if (elite) {
        uint8_t keytable[128] = {0};
        uint8_t key_index[8] = {0};
        uint8_t key_sel[8] = { 0 };
        uint8_t key_sel_p[8] = { 0 };
        hash2(KEY, keytable);
        hash1(CSN, key_index);
        for (uint8_t i = 0; i < 8 ; i++)
            key_sel[i] = keytable[key_index[i]] & 0xFF;

        //Permute from iclass format to standard format
        permutekey_rev(key_sel, key_sel_p);
        diversifyKey(CSN, key_sel_p, div_key);
    } else {
        diversifyKey(CSN, KEY, div_key);
    }
}

//when told CSN, oldkey, newkey, if new key is elite (elite), and if old key was elite (oldElite)
//calculate and return xor_div_key (ready for a key write command)
//print all div_keys if verbose
static void HFiClassCalcNewKey(uint8_t *CSN, uint8_t *OLDKEY, uint8_t *NEWKEY, uint8_t *xor_div_key, bool elite, bool oldElite, bool verbose) {
    uint8_t old_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t new_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //get old div key
    HFiClassCalcDivKey(CSN, OLDKEY, old_div_key, oldElite);
    //get new div key
    HFiClassCalcDivKey(CSN, NEWKEY, new_div_key, elite);

    for (uint8_t i = 0; i < ARRAYLEN(old_div_key); i++) {
        xor_div_key[i] = old_div_key[i] ^ new_div_key[i];
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "Old div key : %s\n", sprint_hex(old_div_key, 8));
        PrintAndLogEx(SUCCESS, "New div key : %s\n", sprint_hex(new_div_key, 8));
        PrintAndLogEx(SUCCESS, "Xor div key : %s\n", sprint_hex(xor_div_key, 8));
    }
}

static int CmdHFiClassCalcNewKey(const char *Cmd) {
    uint8_t OLDKEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t NEWKEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t xor_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    char tempStr[50] = {0};
    bool givenCSN = false;
    bool oldElite = false;
    bool elite = false;
    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_calc_newkey();
            case 'e':
                dataLen = param_getstr(Cmd, cmdp, tempStr, sizeof(tempStr));
                if (dataLen == 2)
                    oldElite = true;
                elite = true;
                cmdp++;
                break;
            case 'n':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, NEWKEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(NEWKEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: NewKey Nbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: NewKey is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'o':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, OLDKEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(OLDKEY, iClass_Key_Table[keyNbr], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: Credit KeyNbr is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Credit Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 's':
                givenCSN = true;
                if (param_gethex(Cmd, cmdp + 1, CSN, 16))
                    return usage_hf_iclass_calc_newkey();
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || cmdp < 4) return usage_hf_iclass_calc_newkey();

    if (!givenCSN) {
        uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (!select_only(CSN, CCNR, false, true)) {
            DropField();
            return 0;
        }
    }

    HFiClassCalcNewKey(CSN, OLDKEY, NEWKEY, xor_div_key, elite, oldElite, true);
    return PM3_SUCCESS;
}

static int loadKeys(char *filename) {
    FILE *f;
    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(ERR, "Error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        return 1;
    }
    size_t bytes_read = fread(dump, 1, fsize, f);
    fclose(f);
    if (bytes_read > ICLASS_KEYS_MAX * 8) {
        PrintAndLogEx(WARNING, "File is too long to load - bytes: %zu", bytes_read);
        free(dump);
        return 0;
    }
    uint8_t i = 0;
    for (; i < bytes_read / 8; i++)
        memcpy(iClass_Key_Table[i], dump + (i * 8), 8);

    free(dump);
    PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2d") "keys from %s", i, filename);
    return PM3_SUCCESS;
}

static int saveKeys(char *filename) {
    FILE *f;
    f = fopen(filename, "wb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }
    for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
        if (fwrite(iClass_Key_Table[i], 8, 1, f) != 1) {
            PrintAndLogEx(WARNING, "save key failed to write to file:" _YELLOW_("%s"), filename);
            break;
        }
    }
    fclose(f);
    return PM3_SUCCESS;
}

static int printKeys(void) {
    PrintAndLogEx(NORMAL, "");
    for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
        if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0)
            PrintAndLogEx(NORMAL, "%u: %s", i, sprint_hex(iClass_Key_Table[i], 8));
        else
            PrintAndLogEx(NORMAL, "%u: "_YELLOW_("%s"), i, sprint_hex(iClass_Key_Table[i], 8));
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFiClassManageKeys(const char *Cmd) {
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    uint8_t KEY[8] = {0};
    char filename[FILE_PATH_SIZE];
    uint8_t fileNameLen = 0;
    bool errors = false;
    uint8_t operation = 0;
    char tempStr[20];
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_managekeys();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                if (fileNameLen < 1) {
                    PrintAndLogEx(ERR, "No filename found");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'n':
                keyNbr = param_get8(Cmd, cmdp + 1);
                if (keyNbr >= ICLASS_KEYS_MAX) {
                    PrintAndLogEx(ERR, "Invalid block number, MAX is " _YELLOW_("%d"), ICLASS_KEYS_MAX);
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'k':
                operation += 3; //set key
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) { //ul-c or ev1/ntag key length
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'p':
                operation += 4; //print keys in memory
                cmdp++;
                break;
            case 'l':
                operation += 5; //load keys from file
                cmdp++;
                break;
            case 's':
                operation += 6; //save keys to file
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_hf_iclass_managekeys();

    if (operation == 0) {
        PrintAndLogEx(WARNING, "no operation specified (load, save, or print)\n");
        return usage_hf_iclass_managekeys();
    }
    if (operation > 6) {
        PrintAndLogEx(WARNING, "Too many operations specified\n");
        return usage_hf_iclass_managekeys();
    }
    if (operation > 4 && fileNameLen == 0) {
        PrintAndLogEx(WARNING, "You must enter a filename when loading or saving\n");
        return usage_hf_iclass_managekeys();
    }

    switch (operation) {
        case 3:
            memcpy(iClass_Key_Table[keyNbr], KEY, 8);
            return PM3_SUCCESS;
        case 4:
            return printKeys();
        case 5:
            return loadKeys(filename);
        case 6:
            return saveKeys(filename);
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassCheckKeys(const char *Cmd) {

    // empty string
    if (strlen(Cmd) == 0) return usage_hf_iclass_chk();

    uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // elite key,  raw key, standard key
    bool use_elite = false;
    bool use_raw = false;
    bool use_credit_key = false;
    bool found_debit = false;
    //bool found_credit = false;
    bool got_csn = false;
    bool errors = false;
    uint8_t cmdp = 0x00;

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t fileNameLen = 0;
    iclass_premac_t *pre = NULL;

    // time
    uint64_t t1 = msclock();

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_chk();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                if (fileNameLen < 1) {
                    PrintAndLogEx(WARNING, _RED_("no filename found after f"));
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'e':
                use_elite = true;
                cmdp++;
                break;
            case 'c':
                use_credit_key = true;
                cmdp++;
                break;
            case 'r':
                use_raw = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_hf_iclass_chk();


    uint8_t *keyBlock = NULL;
    uint16_t keycount = 0;

    // load keys
    int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
    if (res != PM3_SUCCESS || keycount == 0) {
        free(keyBlock);
        return res;
    }

    // Get CSN / UID and CCNR
    PrintAndLogEx(SUCCESS, "Reading tag CSN");
    for (uint8_t i = 0; i < ICLASS_AUTH_RETRY && !got_csn; i++) {
        got_csn = select_only(CSN, CCNR, false, false);
        if (got_csn == false)
            PrintAndLogEx(WARNING, "one more try");
    }

    if (got_csn == false) {
        PrintAndLogEx(WARNING, "Tried 10 times. Can't select card, aborting...");
        DropField();
        return PM3_ESOFT;
    }

    pre = calloc(keycount, sizeof(iclass_premac_t));
    if (!pre) {
        DropField();
        free(keyBlock);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(SUCCESS, "Generating diversified keys");
    if (use_elite)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
    if (use_raw)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_(" raw mode"));

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") "key", (use_credit_key) ? "CREDIT" : "DEBIT");
    PrintAndLogEx(SUCCESS, "Tag info");
    PrintAndLogEx(SUCCESS, "CSN     | %s", sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, "CCNR    | %s", sprint_hex(CCNR, sizeof(CCNR)));

    GenerateMacFrom(CSN, CCNR, use_raw, use_elite, keyBlock, keycount, pre);

    //PrintPreCalcMac(keyBlock, keycnt, pre);

    // max 42 keys inside USB_COMMAND.  512/4 = 103 mac
    uint32_t chunksize = keycount > (PM3_CMD_DATA_SIZE / 4) ? (PM3_CMD_DATA_SIZE / 4) : keycount;
    bool lastChunk = false;

    // fast push mode
    conn.block_after_ACK = true;

    // keep track of position of found key
    uint8_t found_offset = 0;
    uint32_t key_offset = 0;
    // main keychunk loop
    for (key_offset = 0; key_offset < keycount; key_offset += chunksize) {

        uint64_t t2 = msclock();
        uint8_t timeout = 0;

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\n[!] Aborted via keyboard!\n");
            goto out;
        }

        uint32_t keys = ((keycount - key_offset)  > chunksize) ? chunksize : keycount - key_offset;

        // last chunk?
        if (keys == keycount - key_offset) {
            lastChunk = true;
            // Disable fast mode on last command
            conn.block_after_ACK = false;
        }
        uint32_t flags = lastChunk << 8;
        // bit 16
        //   - 1 indicates credit key
        //   - 0 indicates debit key (default)
        flags |= (use_credit_key << 16);

        clearCommandBuffer();
        SendCommandOLD(CMD_HF_ICLASS_CHKKEYS, flags, keys, 0, pre + key_offset, 4 * keys);
        PacketResponseNG resp;

        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            timeout++;
            printf(".");
            fflush(stdout);
            if (timeout > 120) {
                PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
                goto out;
            }
        }

        found_offset = resp.oldarg[1] & 0xFF;
        uint8_t isOK = resp.oldarg[0] & 0xFF;

        t2 = msclock() - t2;
        switch (isOK) {
            case 1: {
                found_debit = true;

                PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d]: %.1fs [%s] idx [%u] - found key "_YELLOW_("%s")
                              , key_offset
                              , keycount
                              , (float)(t2 / 1000.0)
                              , (use_credit_key) ? "credit" : "debit"
                              , found_offset
                              , sprint_hex(keyBlock + (key_offset + found_offset) * 8, 8)
                             );
                break;
            }
            case 0: {
                PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d] : %.1fs [%s]"
                              , key_offset
                              , keycount
                              , (float)(t2 / 1000.0)
                              , (use_credit_key) ? "credit" : "debit"
                             );
                break;
            }
            case 99: {
            }
            default:
                break;
        }

        // both keys found.
        if (found_debit) {
            PrintAndLogEx(SUCCESS, "All keys found, exiting");
            break;
        }

    } // end chunks of keys

out:
    t1 = msclock() - t1;

    PrintAndLogEx(SUCCESS, "\nTime in iclass checkkeys: %.0f seconds\n", (float)t1 / 1000.0);
    DropField();

    // add to managekeys
    if (found_debit) {
        for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
            // simple check for preexistences
            if (memcmp(iClass_Key_Table[i], keyBlock + (key_offset + found_offset) * 8, 8) == 0) break;

            if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) {
                memcpy(iClass_Key_Table[i], keyBlock + (key_offset + found_offset) * 8, 8);
                PrintAndLogEx(SUCCESS, "Added key to keyslot [%d] - "_YELLOW_("`hf iclass managekeys p`")" to view", i);
                break;
            }
        }
    }

    free(pre);
    free(keyBlock);
    return PM3_SUCCESS;
}

static int cmp_uint32(const void *a, const void *b) {

    const iclass_prekey_t *x = (const iclass_prekey_t *)a;
    const iclass_prekey_t *y = (const iclass_prekey_t *)b;

    uint32_t mx = bytes_to_num((uint8_t *)x->mac, 4);
    uint32_t my = bytes_to_num((uint8_t *)y->mac, 4);

    if (mx < my)
        return -1;
    else
        return mx > my;
}

// this method tries to identify in which configuration mode a iClass / iClass SE reader is in.
// Standard or Elite / HighSecurity mode.  It uses a default key dictionary list in order to work.
static int CmdHFiClassLookUp(const char *Cmd) {

    uint8_t CSN[8];
    uint8_t EPURSE[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t MACS[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t CCNR[12];
    uint8_t MAC_TAG[4] = { 0, 0, 0, 0 };

    // elite key,  raw key, standard key
    bool use_elite = false;
    bool use_raw = false;
    bool errors = false;
    uint8_t cmdp = 0x00;

    char filename[FILE_PATH_SIZE] = {0};

    iclass_prekey_t *prekey = NULL;
    int len = 0;
    // if empty string
    if (strlen(Cmd) == 0) errors = true;
    // time
    uint64_t t1 = msclock();

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_lookup();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, sizeof(filename)) < 1) {
                    PrintAndLogEx(WARNING, "No filename found after f");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'u':
                param_gethex_ex(Cmd, cmdp + 1, CSN, &len);
                if (len >> 1 != sizeof(CSN)) {
                    PrintAndLogEx(WARNING, "Wrong CSN length, expected %zu got [%d]", sizeof(CSN), len >> 1);
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'm':
                param_gethex_ex(Cmd, cmdp + 1, MACS, &len);
                if (len >> 1 != sizeof(MACS)) {
                    PrintAndLogEx(WARNING, "Wrong MACS length, expected %zu got [%d]  ", sizeof(MACS), len >> 1);
                    errors = true;
                } else {
                    memcpy(MAC_TAG, MACS + 4, 4);
                }
                cmdp += 2;
                break;
            case 'p':
                param_gethex_ex(Cmd, cmdp + 1, EPURSE, &len);
                if (len >> 1 != sizeof(EPURSE)) {
                    PrintAndLogEx(WARNING, "Wrong EPURSE length, expected %zu got [%d]  ", sizeof(EPURSE), len >> 1);
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'e':
                use_elite = true;
                cmdp++;
                break;
            case 'r':
                use_raw = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_hf_iclass_lookup();

    // stupid copy.. CCNR is a combo of epurse and reader nonce
    memcpy(CCNR, EPURSE, 8);
    memcpy(CCNR + 8, MACS, 4);

    PrintAndLogEx(SUCCESS, "CSN     | %s", sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, "Epurse  | %s", sprint_hex(EPURSE, sizeof(EPURSE)));
    PrintAndLogEx(SUCCESS, "MACS    | %s", sprint_hex(MACS, sizeof(MACS)));
    PrintAndLogEx(SUCCESS, "CCNR    | %s", sprint_hex(CCNR, sizeof(CCNR)));
    PrintAndLogEx(SUCCESS, "MAC_TAG | %s", sprint_hex(MAC_TAG, sizeof(MAC_TAG)));

    uint8_t *keyBlock = NULL;
    uint16_t keycount = 0;

    // load keys
    int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
    if (res != PM3_SUCCESS || keycount == 0) {
        free(keyBlock);
        return res;
    }

    //iclass_prekey_t
    prekey = calloc(keycount, sizeof(iclass_prekey_t));
    if (!prekey) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Generating diversified keys");
    GenerateMacKeyFrom(CSN, CCNR, use_raw, use_elite, keyBlock, keycount, prekey);

    PrintAndLogEx(INFO, "Sorting");

    // sort mac list.
    qsort(prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    //PrintPreCalc(prekey, keycnt);

    PrintAndLogEx(INFO, "Searching");
    iclass_prekey_t *item;
    iclass_prekey_t lookup;
    memcpy(lookup.mac, MAC_TAG, 4);

    // binsearch
    item = (iclass_prekey_t *) bsearch(&lookup, prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    t1 = msclock() - t1;
    PrintAndLogEx(NORMAL, "\nTime in iclass : %.0f seconds\n", (float)t1 / 1000.0);

    // foudn
    if (item != NULL) {
        PrintAndLogEx(SUCCESS, "[debit] found key " _YELLOW_("%s"), sprint_hex(item->key, 8));
        for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
            // simple check for preexistences
            if (memcmp(item->key, iClass_Key_Table[i], 8) == 0) break;

            if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) {
                memcpy(iClass_Key_Table[i], item->key, 8);
                PrintAndLogEx(SUCCESS, "Added key to keyslot [%d] - "_YELLOW_("`hf iclass managekeys p`")"to view", i);
                break;
            }
        }
    }

    free(prekey);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// precalc diversified keys and their MAC
void GenerateMacFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_premac_t *list) {
    uint8_t key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (int i = 0; i < keycnt; i++) {

        memcpy(key, keys + 8 * i, 8);

        if (use_raw)
            memcpy(div_key, key, 8);
        else
            HFiClassCalcDivKey(CSN, key, div_key, use_elite);

        doMAC(CCNR, div_key, list[i].mac);
    }
}

void GenerateMacKeyFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_prekey_t *list) {

    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (int i = 0; i < keycnt; i++) {

        memcpy(list[i].key, keys + 8 * i, 8);

        // generate diversifed key
        if (use_raw)
            memcpy(div_key, list[i].key, 8);
        else
            HFiClassCalcDivKey(CSN, list[i].key, div_key, use_elite);

        // generate MAC
        doMAC(CCNR, div_key, list[i].mac);
    }
}

// print diversified keys
void PrintPreCalcMac(uint8_t *keys, int keycnt, iclass_premac_t *pre_list) {

    iclass_prekey_t *b =  calloc(keycnt, sizeof(iclass_prekey_t));
    if (!b)
        return;

    for (int i = 0; i < keycnt; i++) {
        memcpy(b[i].key, keys + 8 * i, 8);
        memcpy(b[i].mac, pre_list[i].mac, 4);
    }
    PrintPreCalc(b, keycnt);
    free(b);
}

void PrintPreCalc(iclass_prekey_t *list, int itemcnt) {
    PrintAndLogEx(NORMAL, "-----+------------------+---------");
    PrintAndLogEx(NORMAL, "#key | key              | mac");
    PrintAndLogEx(NORMAL, "-----+------------------+---------");
    for (int i = 0; i < itemcnt; i++) {

        if (i < 10) {
            PrintAndLogEx(NORMAL, "[%2d] | %016" PRIx64 " | %08" PRIx64, i, bytes_to_num(list[i].key, 8), bytes_to_num(list[i].mac, 4));
        } else if (i == 10) {
            PrintAndLogEx(SUCCESS, "... skip printing the rest");
        }
    }
}

static void permute(uint8_t *data, uint8_t len, uint8_t *output) {
#define KEY_SIZE 8

    if (len > KEY_SIZE) {
        for (uint8_t m = 0; m < len; m += KEY_SIZE) {
            permute(data + m, KEY_SIZE, output + m);
        }
        return;
    }
    if (len != KEY_SIZE) {
        PrintAndLogEx(NORMAL, "[!] wrong key size\n");
        return;
    }
    for (uint8_t i = 0; i < KEY_SIZE; ++i) {
        uint8_t p = 0;
        uint8_t mask = 0x80 >> i;
        for (uint8_t j = 0; j < KEY_SIZE; ++j) {
            p >>= 1;
            if (data[j] & mask)
                p |= 0x80;
        }
        output[i] = p;
    }
}
static void permute_rev(uint8_t *data, uint8_t len, uint8_t *output) {
    permute(data, len, output);
    permute(output, len, data);
    permute(data, len, output);
}
static void simple_crc(uint8_t *data, uint8_t len, uint8_t *output) {
    uint8_t crc = 0;
    for (uint8_t i = 0; i < len; ++i) {
        // seventh byte contains the crc.
        if ((i & 0x7) == 0x7) {
            output[i] = crc ^ 0xFF;
            crc = 0;
        } else {
            output[i] = data[i];
            crc ^= data[i];
        }
    }
}
// DES doesn't use the MSB.
static void shave(uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; ++i)
        data[i] &= 0xFE;
}
static void generate_rev(uint8_t *data, uint8_t len) {
    uint8_t *key = calloc(len, sizeof(uint8_t));
    PrintAndLogEx(SUCCESS, "input permuted key | %s \n", sprint_hex(data, len));
    permute_rev(data, len, key);
    PrintAndLogEx(SUCCESS, "    unpermuted key | %s \n", sprint_hex(key, len));
    shave(key, len);
    PrintAndLogEx(SUCCESS, "               key | %s \n", sprint_hex(key, len));
    free(key);
}
static void generate(uint8_t *data, uint8_t len) {
    uint8_t *key = calloc(len, sizeof(uint8_t));
    uint8_t *pkey = calloc(len, sizeof(uint8_t));
    PrintAndLogEx(SUCCESS, "   input key | %s \n", sprint_hex(data, len));
    permute(data, len, pkey);
    PrintAndLogEx(SUCCESS, "permuted key | %s \n", sprint_hex(pkey, len));
    simple_crc(pkey, len, key);
    PrintAndLogEx(SUCCESS, "  CRC'ed key | %s \n", sprint_hex(key, len));
    free(key);
    free(pkey);
}

static int CmdHFiClassPermuteKey(const char *Cmd) {

    uint8_t key[8] = {0};
    uint8_t data[16] = {0};
    bool isReverse = false;
    int len = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_hf_iclass_permutekey();

    isReverse = (cmdp == 'r');

    param_gethex_ex(Cmd, 1, data, &len);
    if (len % 2) return usage_hf_iclass_permutekey();

    len >>= 1;

    memcpy(key, data, 8);

    if (isReverse) {
        generate_rev(data, len);
        uint8_t key_std_format[8] = {0};
        permutekey_rev(key, key_std_format);
        PrintAndLogEx(SUCCESS, "holiman iclass key | %s \n", sprint_hex(key_std_format, 8));
    } else {
        generate(data, len);
        uint8_t key_iclass_format[8] = {0};
        permutekey(key, key_iclass_format);
        PrintAndLogEx(SUCCESS, "holiman std key | %s \n", sprint_hex(key_iclass_format, 8));
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                    AlwaysAvailable, "This help"},
    {"calcnewkey",  CmdHFiClassCalcNewKey,      AlwaysAvailable, "[options..] Calc diversified keys (blocks 3 & 4) to write new keys"},
    {"chk",         CmdHFiClassCheckKeys,       AlwaysAvailable, "[options..] Check keys"},
    {"clone",       CmdHFiClassCloneTag,        IfPm3Iclass,     "[options..] Restore a dump file onto a iClass tag"},
    {"decrypt",     CmdHFiClassDecrypt,         AlwaysAvailable, "[options..] Decrypt given block data or tag dump file" },
    {"dump",        CmdHFiClassReader_Dump,     IfPm3Iclass,     "[options..] Dump iClass tag to file"},
    {"eload",       CmdHFiClassELoad,           IfPm3Iclass,     "[f <fname>] Load iClass dump file into emulator memory"},
    {"encrypt",     CmdHFiClassEncryptBlk,      AlwaysAvailable, "[options..] Encrypt given block data"},
    {"info",        CmdHFiClassInfo,            AlwaysAvailable, "            Tag information"},
    {"list",        CmdHFiClassList,            AlwaysAvailable, "            List iClass history"},
    {"loclass",     CmdHFiClass_loclass,        AlwaysAvailable, "[options..] Use loclass to perform bruteforce reader attack"},
    {"lookup",      CmdHFiClassLookUp,          AlwaysAvailable, "[options..] Uses authentication trace to check for key in dictionary file"},
    {"managekeys",  CmdHFiClassManageKeys,      AlwaysAvailable, "[options..] Manage keys to use with iClass"},
    {"permutekey",  CmdHFiClassPermuteKey,      IfPm3Iclass,     "            Permute function from 'heart of darkness' paper"},
    {"rdbl",        CmdHFiClass_ReadBlock,      IfPm3Iclass,     "[options..] Read iClass block"},
    {"reader",      CmdHFiClassReader,          IfPm3Iclass,     "            Act like an iClass reader"},
    {"readtagfile", CmdHFiClassReadTagFile,     AlwaysAvailable, "[options..] Display content from tag dump file"},
    {"replay",      CmdHFiClassReader_Replay,   IfPm3Iclass,     "<mac>       Read iClass tag via replay attack"},
    {"sim",         CmdHFiClassSim,             IfPm3Iclass,     "[options..] Simulate iClass tag"},
    {"sniff",       CmdHFiClassSniff,           IfPm3Iclass,     "            Eavesdrop iClass communication"},
    {"wrbl",        CmdHFiClass_WriteBlock,     IfPm3Iclass,     "[options..] Write iClass block"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFiClass(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readIclass(bool loop, bool verbose) {
    bool tagFound = false;

    uint32_t flags = FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CC |  FLAG_ICLASS_READER_AIA |
                     FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_ONLY_ONCE |
                     FLAG_ICLASS_READER_ONE_TRY;

    // loop in client not device - else on windows have a communication error
    while (!kbd_enter_pressed()) {

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
        PacketResponseNG resp;

        if (WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {

            uint8_t readStatus = resp.oldarg[0] & 0xff;
            uint8_t *data = resp.data.asBytes;

//            if (verbose) PrintAndLogEx(INFO, "Readstatus:%02x", readStatus);

            // no tag found or button pressed
            if ((readStatus == 0 && !loop) || readStatus == 0xFF) {
                // abort
                DropField();
                return PM3_EOPABORTED;
            }

            if (readStatus & FLAG_ICLASS_READER_CSN) {
                PrintAndLogEx(NORMAL, "\n");
                PrintAndLogEx(SUCCESS, "   CSN: %s", sprint_hex(data, 8));
                tagFound = true;
            }

            if (readStatus & FLAG_ICLASS_READER_CC) {
                PrintAndLogEx(SUCCESS, "    CC: %s", sprint_hex(data + 16, 8));
            }

            if (readStatus & FLAG_ICLASS_READER_CONF) {
                printIclassDumpInfo(data);
            }

            // if CSN ends with FF12E0, it's inside HID CSN range.
            bool isHidRange = (memcmp((uint8_t *)(data + 5), "\xFF\x12\xE0", 3) == 0);

            if (readStatus & FLAG_ICLASS_READER_AIA) {
                bool legacy = (memcmp((uint8_t *)(data + 8 * 5), "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0);

                bool se_enabled = (memcmp((uint8_t *)(data + 8 * 5), "\xff\xff\xff\x00\x06\xff\xff\xff", 8) == 0);

                PrintAndLogEx(SUCCESS, " App IA: %s", sprint_hex(data + 8 * 5, 8));

                if (isHidRange) {
                    if (legacy)
                        PrintAndLogEx(SUCCESS, "      : Possible iClass - legacy credential tag");

                    if (se_enabled)
                        PrintAndLogEx(SUCCESS, "      : Possible iClass - SE credential tag");
                }

                if (isHidRange) {
                    PrintAndLogEx(SUCCESS, "      : Tag is "_YELLOW_("iClass")", CSN is in HID range");
                } else {
                    PrintAndLogEx(SUCCESS, "      : Tag is "_YELLOW_("PicoPass")", CSN is not in HID range");
                }
            }

            if (tagFound && !loop) {
                DropField();
                return PM3_SUCCESS;
            }
        } else {
            if (verbose)
                PrintAndLogEx(WARNING, "command execute timeout");
        }
        if (!loop) break;
    }
    DropField();
    return PM3_SUCCESS;
}

