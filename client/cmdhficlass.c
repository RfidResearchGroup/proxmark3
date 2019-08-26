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

static int CmdHelp(const char *Cmd);

static uint8_t iClass_Key_Table[ICLASS_KEYS_MAX][8] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
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
    PrintAndLogEx(NORMAL, "in the working directory. The file should be 16 bytes binary data");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: hf iclass decrypt f <tagdump>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "S       hf iclass decrypt f tagdump_12312342343.bin");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_encrypt(void) {
    PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
    PrintAndLogEx(NORMAL, "in the working directory. The file should be 16 bytes binary data");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: hf iclass encrypt <BlockData>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass encrypt 0102030405060708");
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
    PrintAndLogEx(NORMAL, "Usage:  hf iclass readblk b <block> k <key> [c|e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  b <block> : The block number as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  k <key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
    PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
    PrintAndLogEx(NORMAL, "  v         : verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf iclass readblk b 06 k 0011223344556677");
    PrintAndLogEx(NORMAL, "        hf iclass readblk b 1B k 0011223344556677 c");
    PrintAndLogEx(NORMAL, "        hf iclass readblk b 0A k 0");
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
    PrintAndLogEx(NORMAL, "Usage: hf iclass loclass [options]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             Show this help");
    PrintAndLogEx(NORMAL, "      t             Perform self-test");
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
        PrintAndLogEx(NORMAL, "    Mode: Application [Locked]");

    if (isset(fuses, FUSE_CODING1)) {
        PrintAndLogEx(NORMAL, "    Coding: RFU");
    } else {
        if (isset(fuses, FUSE_CODING0))
            PrintAndLogEx(NORMAL, "    Coding: ISO 14443-2 B/ISO 15693");
        else
            PrintAndLogEx(NORMAL, "    Coding: ISO 14443B only");
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
        PrintAndLogEx(NORMAL, "    RA: Read access enabled");
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
                    return 0;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return 0;
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
                return 2;
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
                    return 0;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return 0;
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
                return 2;
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

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf_iclass_eload();

    if (ctmp != 'f') return usage_hf_iclass_eload();

    //File handling and reading
    char filename[FILE_PATH_SIZE];

    if (param_getstr(Cmd, 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
        PrintAndLogEx(FAILED, "Filename too long");
        return 1;
    }

    FILE *f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(ERR, "error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        fclose(f);
        return 1;
    }

    size_t bytes_read = fread(dump, 1, fsize, f);
    fclose(f);

    printIclassDumpInfo(dump);
    //Validate

    if (bytes_read < fsize) {
        PrintAndLogEx(ERR, "error, could only read %d bytes (should be %d)", bytes_read, fsize);
        free(dump);
        return 1;
    }

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

static int readKeyfile(const char *filename, size_t len, uint8_t *buffer) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, len, f);
    fclose(f);

    if (fsize != len) {
        PrintAndLogEx(WARNING, "Warning, file size is %d, expected %d", fsize, len);
        return 1;
    }

    if (bytes_read != len) {
        PrintAndLogEx(WARNING, "Warning, could only read %d bytes, expected %d", bytes_read, len);
        return 1;
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassDecrypt(const char *Cmd) {

    char opt = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || opt == 'h') return usage_hf_iclass_decrypt();

    uint8_t key[16] = { 0 };
    if (readKeyfile("iclass_decryptionkey.bin", 16, key)) return usage_hf_iclass_decrypt();

    PrintAndLogEx(SUCCESS, "decryption key loaded from file");

    //Open the tagdump-file
    FILE *f;
    char filename[FILE_PATH_SIZE];
    if (opt == 'f' && param_getstr(Cmd, 1, filename, sizeof(filename)) > 0) {
        f = fopen(filename, "rb");
        if (!f) {
            PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
            return PM3_EFILE;
        }
    } else {
        return usage_hf_iclass_decrypt();
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(ERR, "error, when getting filesize");
        fclose(f);
        return 2;
    }

    uint8_t *decrypted = calloc(fsize, sizeof(uint8_t));
    if (!decrypted) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        return 1;
    }

    size_t bytes_read = fread(decrypted, 1, fsize, f);
    fclose(f);
    if (bytes_read == 0) {
        PrintAndLogEx(ERR, "file reading error");
        free(decrypted);
        return 3;
    }

    picopass_hdr *hdr = (picopass_hdr *)decrypted;

    uint8_t mem = hdr->conf.mem_config;
    uint8_t chip = hdr->conf.chip_config;
    uint8_t applimit = hdr->conf.app_limit;
    uint8_t kb = 2;
    uint8_t app_areas = 2;
    uint8_t max_blk = 31;
    getMemConfig(mem, chip, &max_blk, &app_areas, &kb);

    //Use the first block (CSN) for filename
    char outfilename[FILE_PATH_SIZE] = {0};
    snprintf(outfilename, FILE_PATH_SIZE, "iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x-decrypted",
             hdr->csn[0], hdr->csn[1], hdr->csn[2], hdr->csn[3],
             hdr->csn[4], hdr->csn[5], hdr->csn[6], hdr->csn[7]);

    // tripledes
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    uint8_t enc_dump[8] = {0};
    uint8_t empty[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    for (uint16_t blocknum = 0; blocknum < applimit; ++blocknum) {

        uint8_t idx = blocknum * 8;
        memcpy(enc_dump, decrypted + idx, 8);

        // block 7 or higher,  and not empty 0xFF
        if (blocknum > 6 &&  memcmp(enc_dump, empty, 8) != 0) {
            mbedtls_des3_crypt_ecb(&ctx, enc_dump, decrypted + idx);
        }
    }

    saveFile(outfilename, ".bin", decrypted, fsize);
    saveFileEML(outfilename, decrypted, fsize, 8);
    printIclassDumpContents(decrypted, 1, (fsize / 8), fsize);
    free(decrypted);
    return PM3_SUCCESS;
}

static int iClassEncryptBlkData(uint8_t *blkData) {
    uint8_t key[16] = { 0 };
    if (readKeyfile("iclass_decryptionkey.bin", 16, key)) {
        usage_hf_iclass_encrypt();
        return 1;
    }
    PrintAndLogEx(SUCCESS, "decryption file found");
    uint8_t encryptedData[16];
    uint8_t *encrypted = encryptedData;
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);

    mbedtls_des3_crypt_ecb(&ctx, blkData, encrypted);
    memcpy(blkData, encrypted, 8);
    return 1;
}

static int CmdHFiClassEncryptBlk(const char *Cmd) {
    uint8_t blkData[8] = {0};
    char opt = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || opt == 'h') return usage_hf_iclass_encrypt();

    //get the bytes to encrypt
    if (param_gethex(Cmd, 0, blkData, 16)) {
        PrintAndLogEx(NORMAL, "BlockData must include 16 HEX symbols");
        return 0;
    }
    if (!iClassEncryptBlkData(blkData)) return 0;

    printvar("encrypted block", blkData, 8);
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
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
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
    SendCommandOLD(CMD_HF_ICLASS_AUTH, 0, 0, 0, MAC, 4);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4000)) {
        if (verbose) PrintAndLogEx(FAILED, "auth command execute timeout");
        return false;
    }
    uint8_t isOK = resp.oldarg[0] & 0xFF;
    if (!isOK) {
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
        return 0;
    }
    DropField();

    uint8_t readStatus = resp.oldarg[0] & 0xff;
    uint8_t *data  = resp.data.asBytes;

    if (readStatus == 0) {
        PrintAndLogEx(FAILED, "no tag found");
        return 0;
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
    if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)) {
        //try twice - for some reason it sometimes fails the first time...
        PrintAndLogEx(SUCCESS, "retry to select card");
        if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)) {
            PrintAndLogEx(WARNING, "failed authenticating with debit key");
            DropField();
            return 0;
        }
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
        return 0;
    }

    uint32_t startindex = resp.oldarg[2];
    if (blocksRead * 8 > sizeof(tag_data) - (blockno * 8)) {
        PrintAndLogEx(FAILED, "data exceeded buffer size!");
        blocksRead = (sizeof(tag_data) / 8) - blockno;
    }

    // response ok - now get bigbuf content of the dump
    if (!GetFromDevice(BIG_BUF, tag_data + (blockno * 8), blocksRead * 8, startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return 0;
    }

    size_t gotBytes = blocksRead * 8 + blockno * 8;

    // try AA2
    if (have_credit_key) {
        //turn off hf field before authenticating with different key
        DropField();
        memset(MAC, 0, 4);
        // AA2 authenticate credit key and git c_div_key - later store in dump block 4
        if (!select_and_auth(CreditKEY, MAC, c_div_key, true, elite, rawkey, verbose)) {
            //try twice - for some reason it sometimes fails the first time...
            if (!select_and_auth(CreditKEY, MAC, c_div_key, true, elite, rawkey, verbose)) {
                PrintAndLogEx(WARNING, "failed authenticating with credit key");
                DropField();
                return 0;
            }
        }
        // do we still need to read more block?  (aa2 enabled?)
        if (maxBlk > blockno + numblks + 1) {
            // setup dump and start
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_DUMP, blockno + blocksRead, maxBlk - (blockno + blocksRead), 0, NULL, 0);
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
                PrintAndLogEx(WARNING, "command execute timeout 2");
                return 0;
            }
            isOK = resp.oldarg[0] & 0xff;
            blocksRead = resp.oldarg[1];
            if (!isOK && !blocksRead) {
                PrintAndLogEx(WARNING, "read block failed 2");
                return 0;
            }

            startindex = resp.oldarg[2];
            if (blocksRead * 8 > sizeof(tag_data) - gotBytes) {
                PrintAndLogEx(FAILED, "data exceeded buffer size!");
                blocksRead = (sizeof(tag_data) - gotBytes) / 8;
            }
            // get dumped data from bigbuf
            if (!GetFromDevice(BIG_BUF, tag_data + gotBytes, blocksRead * 8, startindex, NULL, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "command execution time out");
                return 0;
            }

            gotBytes += blocksRead * 8;
        }
    }

    DropField();

    // add diversified keys to dump
    if (have_debit_key) memcpy(tag_data + (3 * 8), div_key, 8);
    if (have_credit_key) memcpy(tag_data + (4 * 8), c_div_key, 8);

    // print the dump
    PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
    PrintAndLogEx(NORMAL, "CSN   |00| %s|\n", sprint_hex(tag_data, 8));
    printIclassDumpContents(tag_data, 1, (gotBytes / 8), gotBytes);

    if (filename[0] == 0) {
        snprintf(filename, FILE_PATH_SIZE, "iclass_tagdump-%02x%02x%02x%02x%02x%02x%02x%02x",
                 tag_data[0], tag_data[1], tag_data[2], tag_data[3],
                 tag_data[4], tag_data[5], tag_data[6], tag_data[7]);
    }

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %d blocks read", gotBytes / 8);
    saveFile(filename, ".bin", tag_data, gotBytes);
    saveFileEML(filename, tag_data, gotBytes, 8);
    return 1;
}

static int WriteBlock(uint8_t blockno, uint8_t *bldata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose))
        return 0;

    PacketResponseNG resp;

    Calc_wb_mac(blockno, bldata, div_key, MAC);
    uint8_t data[12];
    memcpy(data, bldata, 8);
    memcpy(data + 8, MAC, 4);

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_ICLASS_WRITEBL, blockno, 0, 0, data, sizeof(data));
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
        if (verbose) PrintAndLogEx(WARNING, "Write Command execute timeout");
        return 0;
    }
    uint8_t isOK = resp.oldarg[0] & 0xff;
    if (isOK)
        PrintAndLogEx(SUCCESS, "Write block successful");
    else
        PrintAndLogEx(WARNING, "Write block failed");
    return isOK;
}

static int CmdHFiClass_WriteBlock(const char *Cmd) {
    uint8_t blockno = 0;
    uint8_t bldata[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    char tempStr[50] = {0};
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
                if (param_gethex(Cmd, cmdp + 1, &blockno, 2)) {
                    PrintAndLogEx(WARNING, "Block No must include 2 HEX symbols\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'c':
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
    if (errors || cmdp < 6) return usage_hf_iclass_writeblock();

    int ans = WriteBlock(blockno, bldata, KEY, use_credit_key, elite, rawkey, verbose);
    DropField();
    return ans;
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
                if (param_gethex(Cmd, cmdp + 1, &startblock, 2)) {
                    PrintAndLogEx(WARNING, "start block No must include 2 HEX symbols\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'c':
                use_credit_key = true;
                cmdp++;
                break;
            case 'e':
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
                if (param_gethex(Cmd, cmdp + 1, &endblock, 2)) {
                    PrintAndLogEx(WARNING, "start Block No must include 2 HEX symbols\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'r':
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

    if (errors || cmdp < 8) return usage_hf_iclass_clone();

    FILE *f;

    iclass_block_t tag_data[PM3_CMD_DATA_SIZE / 12];

    if ((endblock - startblock + 1) * 12 > PM3_CMD_DATA_SIZE) {
        PrintAndLogEx(NORMAL, "Trying to write too many blocks at once.  Max: %d", PM3_CMD_DATA_SIZE / 8);
    }
    // file handling and reading
    f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (startblock < 5) {
        PrintAndLogEx(WARNING, "you cannot write key blocks this way. yet... make your start block > 4");
        fclose(f);
        return 0;
    }
    // now read data from the file from block 6 --- 19
    // ok we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
    // then copy to usbcommand->asbytes; the max is 32 - 6 = 24 block 12 bytes each block 288 bytes then we can only accept to clone 21 blocks at the time,
    // else we have to create a share memory
    int i;
    fseek(f, startblock * 8, SEEK_SET);
    size_t bytes_read = fread(tag_data, sizeof(iclass_block_t), endblock - startblock + 1, f);
    if (bytes_read == 0) {
        PrintAndLogEx(ERR, "file reading error.");
        fclose(f);
        return 2;
    }

    fclose(f);

    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (!select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose)) {
        return 0;
    }

    uint8_t data[(endblock - startblock) * 12];
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
    uint8_t p[12];
    for (i = 0; i <= endblock - startblock; i++) {
        memcpy(p, data + (i * 12), 12);
        PrintAndLogEx(NORMAL, "Block |%02x|", i + startblock);
        PrintAndLogEx(NORMAL, " %02x%02x%02x%02x%02x%02x%02x%02x |", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        PrintAndLogEx(NORMAL, " MAC |%02x%02x%02x%02x|\n", p[8], p[9], p[10], p[11]);
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandOLD(CMD_HF_ICLASS_CLONE, startblock, endblock, 0, data, (endblock - startblock) * 12);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
        PrintAndLogEx(WARNING, "command execute timeout");
        return 0;
    }
    return PM3_SUCCESS;
}

static int ReadBlock(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool verbose, bool auth) {
    // block 0,1 should always be able to read,  and block 5 on some cards.
    if (auth || blockno >= 2) {
        uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
        uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (!select_and_auth(KEY, MAC, div_key, (keyType == 0x18), elite, rawkey, verbose))
            return 0;
    } else {
        uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (!select_only(CSN, CCNR, (keyType == 0x18), verbose))
            return 0;
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_READBL, blockno, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 0;
    }

    uint8_t isOK = resp.oldarg[0] & 0xff;
    if (!isOK) {
        PrintAndLogEx(WARNING, "read block failed");
        return 0;
    }
    //data read is stored in: resp.data.asBytes[0-15]
    PrintAndLogEx(NORMAL, "block %02X: %s\n", blockno, sprint_hex(resp.data.asBytes, 8));
   // should decrypt it if file is accessable.
    return 1;
}

static int CmdHFiClass_ReadBlock(const char *Cmd) {
    uint8_t blockno = 0;
    uint8_t keyType = 0x88; //debit key
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    char tempStr[50] = {0};
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
                if (param_gethex(Cmd, cmdp + 1, &blockno, 2)) {
                    PrintAndLogEx(WARNING, "Block No must include 2 HEX symbols\n");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'c':
                keyType = 0x18;
                cmdp++;
                break;
            case 'e':
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
    if (errors || cmdp < 4) return usage_hf_iclass_readblock();

    if (!auth)
        PrintAndLogEx(FAILED, "warning: no authentication used with read, only a few specific blocks can be read accurately without authentication.");

    return ReadBlock(KEY, blockno, keyType, elite, rawkey, verbose, auth);
}

static int CmdHFiClass_loclass(const char *Cmd) {
    char opt = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 1 || opt == 'h')
        usage_hf_iclass_loclass();

    if (opt == 'f') {
        char fileName[FILE_PATH_SIZE] = {0};
        if (param_getstr(Cmd, 1, fileName, sizeof(fileName)) > 0) {
            return bruteforceFileNoKeys(fileName);
        } else {
            PrintAndLogEx(WARNING, "You must specify a filename");
            return 0;
        }
    } else if (opt == 't') {
        int errors = testCipherUtils();
        errors += testMAC();
        errors += doKeyTests(0);
        errors += testElite();
        if (errors) PrintAndLogEx(ERR, "There were errors!!!");
        return errors;
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
    PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
    while (i <= endblock) {
        uint8_t *blk = iclass_dump + (i * 8);
        PrintAndLogEx(NORMAL, "      |%02X| %s\n", i, sprint_hex_ascii(blk, 8));
        i++;
    }
    PrintAndLogEx(NORMAL, "------+--+-------------------------+\n");
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
        if (!select_only(CSN, CCNR, false, true))
            return 0;
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
        PrintAndLogEx(WARNING, "File is too long to load - bytes: %u", bytes_read);
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
        if ( memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0)
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
                    PrintAndLogEx(ERR, "Invalid block number, MAX is "_YELLOW_("%d"), ICLASS_KEYS_MAX);
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

    uint8_t *keyBlock = NULL;
    iclass_premac_t *pre = NULL;
    int keycnt = 0;

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


    // Get CSN / UID and CCNR
    PrintAndLogEx(SUCCESS, "Reading tag CSN");
    for (uint8_t i = 0; i < 10 && !got_csn; i++) {
        if (select_only(CSN, CCNR, false, false)) {
            got_csn = true;
        } else {
            PrintAndLogEx(WARNING, "one more try\n");
        }
    }

    if (!got_csn) {
        PrintAndLogEx(WARNING, "can't select card, aborting...");
        return PM3_ESOFT;
    }

    // load keys into keyblock
    int res = LoadDictionaryKeyFile(filename, &keyBlock, &keycnt);
    if (res > 0) {
        free(keyBlock);
        return PM3_EFILE;
    }

    pre = calloc(keycnt, sizeof(iclass_premac_t));
    if (!pre) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(SUCCESS, "Generating diversified keys, MAC");
    if (use_elite)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
    if (use_raw)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_(" raw mode"));

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") "key", (use_credit_key) ? "CREDIT" : "DEBIT");
    PrintAndLogEx(SUCCESS, "Tag info");
    PrintAndLogEx(SUCCESS, "CSN     | %s", sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, "CCNR    | %s", sprint_hex(CCNR, sizeof(CCNR)));
    res = GenerateMacFromKeyFile(CSN, CCNR, use_raw, use_elite, keyBlock, keycnt, pre);
    if (res > 0) {
        free(keyBlock);
        free(pre);
        return PM3_ESOFT;
    }

    //PrintPreCalcMac(keyBlock, keycnt, pre);

    // max 42 keys inside USB_COMMAND.  512/4 = 103 mac
    uint32_t chunksize = keycnt > (PM3_CMD_DATA_SIZE / 4) ? (PM3_CMD_DATA_SIZE / 4) : keycnt;
    bool lastChunk = false;

    // fast push mode
    conn.block_after_ACK = true;

    // keep track of position of found key
    uint8_t found_offset = 0;
    uint32_t key_offset = 0;
    // main keychunk loop
    for (uint32_t key_offset = 0; key_offset < keycnt; key_offset += chunksize) {

        uint64_t t2 = msclock();
        uint8_t timeout = 0;

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\n[!] Aborted via keyboard!\n");
            goto out;
        }

        uint32_t keys = ((keycnt - key_offset)  > chunksize) ? chunksize : keycnt - key_offset;

        // last chunk?
        if (keys == keycnt - key_offset) {
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

                PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d]: %.1fs [%s]  found key  %s (index %u)"
                              , key_offset
                              , keycnt
                              , (float)(t2 / 1000.0)
                              , (use_credit_key) ? "credit" : "debit"
                              , sprint_hex(keyBlock + (key_offset + found_offset) * 8, 8)
                              , found_offset
                             );
                break;
            }
            case 0: {
                PrintAndLogEx(NORMAL, "\n[-] Chunk [%d/%d] : %.1fs [%s]"
                              , key_offset
                              , keycnt
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
    if ( found_debit ) {
        for (uint8_t i=0; i< ICLASS_KEYS_MAX; i++) { 
            // simple check for preexistences
            if ( memcmp(iClass_Key_Table[i], keyBlock + (key_offset + found_offset) * 8, 8) == 0 ) break;

            if ( memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0 ) {
                memcpy(iClass_Key_Table[i], keyBlock + (key_offset + found_offset) * 8, 8);
                PrintAndLogEx(SUCCESS, "Added found key to keyslot [%d] - "_YELLOW_("`hf iclass managekeys p`")" to view", i);
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
    uint8_t fileNameLen = 0;

    uint8_t *keyBlock = NULL;
    iclass_prekey_t *prekey = NULL;
    int keycnt = 0, len = 0;

    // if empty string
    if (strlen(Cmd) == 0) errors = true;
    // time
    uint64_t t1 = msclock();

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_lookup();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                if (fileNameLen < 1) {
                    PrintAndLogEx(WARNING, "No filename found after f");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'u':
                param_gethex_ex(Cmd, cmdp + 1, CSN, &len);
                if (len >> 1 != sizeof(CSN)) {
                    PrintAndLogEx(WARNING, "Wrong CSN length, expected %d got [%d]", sizeof(CSN), len >> 1);
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'm':
                param_gethex_ex(Cmd, cmdp + 1, MACS, &len);
                if (len >> 1 != sizeof(MACS)) {
                    PrintAndLogEx(WARNING, "Wrong MACS length, expected %d got [%d]  ", sizeof(MACS), len >> 1);
                    errors = true;
                } else {
                    memcpy(MAC_TAG, MACS + 4, 4);
                }
                cmdp += 2;
                break;
            case 'p':
                param_gethex_ex(Cmd, cmdp + 1, EPURSE, &len);
                if (len >> 1 != sizeof(EPURSE)) {
                    PrintAndLogEx(WARNING, "Wrong EPURSE length, expected %d got [%d]  ", sizeof(EPURSE), len >> 1);
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

    int res = LoadDictionaryKeyFile(filename, &keyBlock, &keycnt);
    if (res > 0) {
        free(keyBlock);
        return 1;
    }
    //iclass_prekey_t
    prekey = calloc(keycnt, sizeof(iclass_prekey_t));
    if (!prekey) {
        free(keyBlock);
        return 1;
    }

    PrintAndLogEx(FAILED, "Generating diversified keys and MAC");
    res = GenerateFromKeyFile(CSN, CCNR, use_raw, use_elite, keyBlock, keycnt, prekey);
    if (res > 0) {
        free(keyBlock);
        free(prekey);
        return 1;
    }

    PrintAndLogEx(FAILED, "Sorting");

    // sort mac list.
    qsort(prekey, keycnt, sizeof(iclass_prekey_t), cmp_uint32);

    //PrintPreCalc(prekey, keycnt);

    PrintAndLogEx(FAILED, "Searching");
    iclass_prekey_t *item;
    iclass_prekey_t lookup;
    memcpy(lookup.mac, MAC_TAG, 4);

    // binsearch
    item = (iclass_prekey_t *) bsearch(&lookup, prekey, keycnt, sizeof(iclass_prekey_t), cmp_uint32);

    t1 = msclock() - t1;
    PrintAndLogEx(NORMAL, "\nTime in iclass : %.0f seconds\n", (float)t1 / 1000.0);

    // foudn
    if (item != NULL) {
        PrintAndLogEx(SUCCESS, "\n[debit] found key %s", sprint_hex(item->key, 8));
        for (uint8_t i=0; i< ICLASS_KEYS_MAX; i++) {
            // simple check for preexistences
            if ( memcmp(item->key, iClass_Key_Table[i], 8) == 0 ) break;

            if ( memcmp(iClass_Key_Table[i] , "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0 ) {
                memcpy(iClass_Key_Table[i], item->key, 8);
                PrintAndLogEx(SUCCESS, "Added found key to keyslot [%d] - "_YELLOW_("`hf iclass managekeys p`")"to view", i);
                break;
            }
        }
    }
 
    free(prekey);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int LoadDictionaryKeyFile(char *filename, uint8_t **keys, int *keycnt) {

    char buf[17];
    FILE *f;
    uint8_t *p;
    int keyitems = 0;

    if (!(f = fopen(filename, "r"))) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return 1;
    }

    while (fgets(buf, sizeof(buf), f)) {
        if (strlen(buf) < 16 || buf[15] == '\n')
            continue;

        //goto next line
        while (fgetc(f) != '\n' && !feof(f)) {};

        //The line start with # is comment, skip
        if (buf[0] == '#')
            continue;

        // doesn't this only test first char only?
        if (!isxdigit(buf[0])) {
            PrintAndLogEx(ERR, "file content error. '%s' must include 16 HEX symbols", buf);
            continue;
        }

        // null terminator (skip the rest of the line)
        buf[16] = 0;

        p = realloc(*keys, 8 * (keyitems += 64));
        if (!p) {
            PrintAndLogEx(ERR, "cannot allocate memory for default keys");
            fclose(f);
            return 2;
        }
        *keys = p;

        memset(*keys + 8 * (*keycnt), 0, 8);
        num_to_bytes(strtoull(buf, NULL, 16), 8, *keys + 8 * (*keycnt));
        (*keycnt)++;
        memset(buf, 0, sizeof(buf));
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2d") "keys from %s", *keycnt, filename);
    return PM3_SUCCESS;
}

// precalc diversified keys and their MAC
int GenerateMacFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_premac_t *list) {
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
    return PM3_SUCCESS;
}

int GenerateFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_prekey_t *list) {

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
    return PM3_SUCCESS;
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
            PrintAndLogEx(NORMAL, "[%2d] | %016" PRIx64 " | %08" PRIx32, i, bytes_to_num(list[i].key, 8), bytes_to_num(list[i].mac, 4));
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
    {"calcnewkey",  CmdHFiClassCalcNewKey,      AlwaysAvailable, "[options..] Calc Diversified keys (blocks 3 & 4) to write new keys"},
    {"chk",         CmdHFiClassCheckKeys,       AlwaysAvailable, "            Check keys"},
    {"clone",       CmdHFiClassCloneTag,        IfPm3Iclass,     "[options..] Authenticate and Clone from iClass bin file"},
    {"decrypt",     CmdHFiClassDecrypt,         AlwaysAvailable, "[f <fname>] Decrypt tagdump" },
    {"dump",        CmdHFiClassReader_Dump,     IfPm3Iclass,     "[options..] Authenticate and Dump iClass tag's AA1"},
    {"eload",       CmdHFiClassELoad,           IfPm3Iclass,     "[f <fname>] (experimental) Load data into iClass emulator memory"},
    {"encryptblk",  CmdHFiClassEncryptBlk,      AlwaysAvailable, "<BlockData> Encrypt given block data"},
    {"list",        CmdHFiClassList,            AlwaysAvailable,     "            List iClass history"},
    {"loclass",     CmdHFiClass_loclass,        AlwaysAvailable, "[options..] Use loclass to perform bruteforce of reader attack dump"},
    {"lookup",      CmdHFiClassLookUp,          AlwaysAvailable, "[options..] Uses authentication trace to check for key in dictionary file"},
    {"managekeys",  CmdHFiClassManageKeys,      AlwaysAvailable, "[options..] Manage the keys to use with iClass"},
    {"permutekey",  CmdHFiClassPermuteKey,      IfPm3Iclass,     "            Permute function from 'heart of darkness' paper"},
    {"readblk",     CmdHFiClass_ReadBlock,      IfPm3Iclass,     "[options..] Authenticate and Read iClass block"},
    {"reader",      CmdHFiClassReader,          IfPm3Iclass,     "            Act like an iClass reader"},
    {"readtagfile", CmdHFiClassReadTagFile,     AlwaysAvailable, "[options..] Display Content from tagfile"},
    {"replay",      CmdHFiClassReader_Replay,   IfPm3Iclass,     "<mac>       Read an iClass tag via Replay Attack"},
    {"sim",         CmdHFiClassSim,             IfPm3Iclass,     "[options..] Simulate iClass tag"},
    {"sniff",       CmdHFiClassSniff,           IfPm3Iclass,     "            Eavesdrop iClass communication"},
    {"writeblk",    CmdHFiClass_WriteBlock,     IfPm3Iclass,     "[options..] Authenticate and Write iClass block"},
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
    PacketResponseNG resp;
    while (!kbd_enter_pressed()) {

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
        if (WaitForResponseTimeout(CMD_ACK, &resp, 4500)) {
            uint8_t readStatus = resp.oldarg[0] & 0xff;
            uint8_t *data = resp.data.asBytes;

            if (verbose) PrintAndLogEx(NORMAL, "Readstatus:%02x", readStatus);
            // no tag found or button pressed
            if ((readStatus == 0 && !loop) || readStatus == 0xFF) {
                // abort
                if (verbose) {
                    PrintAndLogEx(FAILED, "Quitting...");
                    DropField();
                    return 0;
                }
            }
            if (readStatus & FLAG_ICLASS_READER_CSN) {
                PrintAndLogEx(NORMAL, "   CSN: %s", sprint_hex(data, 8));
                tagFound = true;
            }
            if (readStatus & FLAG_ICLASS_READER_CC) {
                PrintAndLogEx(NORMAL, "    CC: %s", sprint_hex(data + 16, 8));
            }
            if (readStatus & FLAG_ICLASS_READER_CONF) {
                printIclassDumpInfo(data);
            }
            if (readStatus & FLAG_ICLASS_READER_AIA) {
                bool legacy = (memcmp((uint8_t *)(data + 8 * 5), "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0);

                bool se_enabled = (memcmp((uint8_t *)(data + 8 * 5), "\xff\xff\xff\x00\x06\xff\xff\xff", 8) == 0);

                PrintAndLogEx(NORMAL, " App IA: %s", sprint_hex(data + 8 * 5, 8));
                if (legacy)
                    PrintAndLogEx(SUCCESS, "      : Possible iClass (legacy credential tag)");
                else if (se_enabled)
                    PrintAndLogEx(SUCCESS, "      : Possible iClass (SE credential tag)");
                else
                    PrintAndLogEx(WARNING, "      : Possible iClass (NOT legacy tag)");
            }

            if (tagFound && !loop) {
                DropField();
                return 1;
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

