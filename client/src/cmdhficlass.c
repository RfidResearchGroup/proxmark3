//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>, Hagen Fritsch
// Copyright (C) 2011 Gerhard de Koning Gans
// Copyright (C) 2014 Midnitesnake & Andy Davies & Martin Holst Swende
// Copyright (C) 2019 piwi
// Copyright (C) 2020 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include "cmdhficlass.h"
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
#include "cmdtrace.h"
#include "util_posix.h"
#include "comms.h"
#include "des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "fileutils.h"
#include "protocols.h"
#include "cardhelper.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"

#define NUM_CSNS 9
#define ICLASS_KEYS_MAX 8
#define ICLASS_AUTH_RETRY 10
#define ICLASS_DECRYPTION_BIN  "iclass_decryptionkey.bin"
static uint8_t empty[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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
    PrintAndLogEx(NORMAL, "Simulate a iCLASS legacy/standard tag\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iCLASS sim [h] <option> [CSN]\n");
    PrintAndLogEx(NORMAL, "Options");
    PrintAndLogEx(NORMAL, "  h         : Show this help");
    PrintAndLogEx(NORMAL, "  0 <CSN>   : simulate the given CSN");
    PrintAndLogEx(NORMAL, "  1         : simulate default CSN");
    PrintAndLogEx(NORMAL, "  2         : Reader-attack, gather reader responses to extract elite key");
    PrintAndLogEx(NORMAL, "  3         : Full simulation using emulator memory (see 'hf iclass eload')");
    PrintAndLogEx(NORMAL, "  4         : Reader-attack, adapted for KeyRoll mode, gather reader responses to extract elite key");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass sim 0 031FEC8AF7FF12E0"));
    PrintAndLogEx(NORMAL, "   -- execute loclass attack online part");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass sim 2"));
    PrintAndLogEx(NORMAL, "   -- simulate full iCLASS 2k tag");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass eload f hf-iclass-AA162D30F8FF12F1-dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass sim 3"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_eload(void) {
    PrintAndLogEx(NORMAL, "Loads iCLASS tag dump into emulator memory on device\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass eload [h] f <filename>\n");
    PrintAndLogEx(NORMAL, "Options");
    PrintAndLogEx(NORMAL, "  h            : Show this help");
    PrintAndLogEx(NORMAL, "  f <filename> : filename of dump");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass eload f hf-iclass-AA162D30F8FF12F1-dump.bin"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_esave(void) {
    PrintAndLogEx(NORMAL, "Save emulator memory to file.");
    PrintAndLogEx(NORMAL, "if not filename is supplied, CSN will be used.");
    PrintAndLogEx(NORMAL, "Number of bytes to download defaults to 256. Other value is 2048\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass esave [h] [f <filename>] [s <num of bytes>]\n");
    PrintAndLogEx(NORMAL, "Options");
    PrintAndLogEx(NORMAL, "  h            : Show this help");
    PrintAndLogEx(NORMAL, "  f <filename> : filename of dump");
    PrintAndLogEx(NORMAL, "  s <bytes>    : (256|2048) number of bytes to save (default 256)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass esave"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass esave f hf-iclass-dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass esave s 2048 f hf-iclass-dump.bin"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_eview(void) {
    PrintAndLogEx(NORMAL, "It displays emulator memory");
    PrintAndLogEx(NORMAL, "Number of bytes to download defaults to 256. Other value is 2048\n");
    PrintAndLogEx(NORMAL, " Usage:  hf iclass eview [s <num of bytes>] <v>");
    PrintAndLogEx(NORMAL, "     s <bytes>    : (256|2048) number of bytes to save (default 256)");
    PrintAndLogEx(NORMAL, "     v            : verbose output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        hf iclass eview"));
    PrintAndLogEx(NORMAL, _YELLOW_("        hf iclass eview s 2048 v"));
    return PM3_SUCCESS;
}
static int usage_hf_iclass_decrypt(void) {
    PrintAndLogEx(NORMAL, "3DES decrypt data\n");
    PrintAndLogEx(NORMAL, "This is naive implementation, it tries to decrypt every block after block 6.");
    PrintAndLogEx(NORMAL, "Correct behaviour would be to decrypt only the application areas where the key is valid,");
    PrintAndLogEx(NORMAL, "which is defined by the configuration block.");
    PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside");
    PrintAndLogEx(NORMAL, "in the resources directory. The file should be 16 bytes binary data\n");
    PrintAndLogEx(NORMAL, "Usage: hf iclass decrypt d <enc data> f <tagdump> k <transport key>\n");
    PrintAndLogEx(NORMAL, "Options");
    PrintAndLogEx(NORMAL, "  h                 : Show this help");
    PrintAndLogEx(NORMAL, "  d <encrypted blk> : 16 bytes hex");
    PrintAndLogEx(NORMAL, "  f <filename>      : filename of dump");
    PrintAndLogEx(NORMAL, "  k <transport key> : 16 bytes hex");
    PrintAndLogEx(NORMAL, "  v                 : verbose output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass decrypt f hf-iclass-AA162D30F8FF12F1-dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass decrypt f hf-iclass-AA162D30F8FF12F1-dump.bin k 000102030405060708090a0b0c0d0e0f"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass decrypt d 1122334455667788 k 000102030405060708090a0b0c0d0e0f"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_encrypt(void) {
    PrintAndLogEx(NORMAL, "3DES encrypt data\n");
    PrintAndLogEx(NORMAL, "OBS! In order to use this function, the file " _YELLOW_("'iclass_decryptionkey.bin'") " must reside");
    PrintAndLogEx(NORMAL, "in the resources directory. The file should be 16 bytes binary data\n");
    PrintAndLogEx(NORMAL, "Usage: hf iclass encrypt d <blockdata> k <transport key>\n");
    PrintAndLogEx(NORMAL, "Options");
    PrintAndLogEx(NORMAL, "  h                 : Show this help");
    PrintAndLogEx(NORMAL, "  d <block data>    : 16 bytes hex");
    PrintAndLogEx(NORMAL, "  k <transport key> : 16 bytes hex");
    PrintAndLogEx(NORMAL, "  v                 : verbose output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass encrypt d 0102030405060708"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass encrypt d 0102030405060708 k 00112233445566778899AABBCCDDEEFF"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_dump(void) {
    PrintAndLogEx(NORMAL, "Dump all memory from a iCLASS tag\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass dump f <fileName> k <key> c <creditkey> [e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h            : Show this help");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to save dump to");
    PrintAndLogEx(NORMAL, "  k <key>      : <required> access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c <creditkey>: credit key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  e            : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r            : raw, the key is interpreted as raw block 3/4");
    PrintAndLogEx(NORMAL, "  v            : verbose output");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass dump k 001122334455667B"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass dump k AAAAAAAAAAAAAAAA c 001122334455667B"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass dump k AAAAAAAAAAAAAAAA e"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass dump k 0"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_restore(void) {
    PrintAndLogEx(NORMAL, "Restore data from dumpfile onto a iCLASS tag\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass restore f <tagfile.bin> b <first block> l <last block> k <KEY> c e|r\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h            : Show this help");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to restore");
    PrintAndLogEx(NORMAL, "  b <block>    : The first block to restore as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  l <last blk> : The last block to restore as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  k <key>      : Access key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c            : If 'c' is specified, the key set is assumed to be the credit key\n");
    PrintAndLogEx(NORMAL, "  e            : If 'e' is specified, elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r            : If 'r' is specified, no computations applied to key (raw)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass restore f hf-iclass-AA162D30F8FF12F1-dump.bin b 06 l 1A k 1122334455667788 e"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass restore f hf-iclass-AA162D30F8FF12F1-dump b 05 l 19 k 0"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass restore f hf-iclass-AA162D30F8FF12F1-dump b 06 l 19 k 0 e"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_writeblock(void) {
    PrintAndLogEx(NORMAL, "Write data to a iCLASS tag\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass wrbl b <block> d <data> k <key> [c|e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h         : Show this help");
    PrintAndLogEx(NORMAL, "  b <block> : The block number as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  d <data>  : set the Data to write as 16 hex symbols");
    PrintAndLogEx(NORMAL, "  k <key>   : access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
    PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key (raw)");
    PrintAndLogEx(NORMAL, "  v         : verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass wrbl b 0A d AAAAAAAAAAAAAAAA k 001122334455667B"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass wrbl b 1B d AAAAAAAAAAAAAAAA k 001122334455667B c"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass wrbl b 1B d AAAAAAAAAAAAAAAA k 0"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_readblock(void) {
    PrintAndLogEx(NORMAL, "Read a iCLASS block from tag\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass rdbl b <block> k <key> [c|e|r|v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h         : Show this help");
    PrintAndLogEx(NORMAL, "  b <block> : The block number as 2 hex symbols");
    PrintAndLogEx(NORMAL, "  k <key>   : Access Key as 16 hex symbols or 1 hex to select key from memory");
    PrintAndLogEx(NORMAL, "  c         : credit key assumed\n");
    PrintAndLogEx(NORMAL, "  e         : elite computations applied to key");
    PrintAndLogEx(NORMAL, "  r         : raw, no computations applied to key");
    PrintAndLogEx(NORMAL, "  v         : verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass rdbl b 06 k 0011223344556677"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass rdbl b 1B k 0011223344556677 c"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass rdbl b 0A k 0"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_view(void) {
    PrintAndLogEx(NORMAL, "Print a iCLASS tag dump file\n");
    PrintAndLogEx(NORMAL, "Usage: hf iClass view [f <filename>] [s <startblock>] [e <endblock>] [v]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h                Show this help");
    PrintAndLogEx(NORMAL, "  f <filename>     filename of dump");
    PrintAndLogEx(NORMAL, "  s <startblock>   print from this block (default block6)");
    PrintAndLogEx(NORMAL, "  e <endblock>     end printing at this block (default 0, ALL)");
    PrintAndLogEx(NORMAL, "  v                verbose output");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass view f hf-iclass-AA162D30F8FF12F1-dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass view s 1 f hf-iclass-AA162D30F8FF12F1-dump.bin"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_calc_newkey(void) {
    PrintAndLogEx(NORMAL, "Calculate new key for updating\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass calc_newkey o <old key> n <new key> s [csn] e\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h           : Show this help");
    PrintAndLogEx(NORMAL, "  o <old key> : *specify a key as 16 hex symbols or a key number as 1 symbol");
    PrintAndLogEx(NORMAL, "  n <new key> : *specify a key as 16 hex symbols or a key number as 1 symbol");
    PrintAndLogEx(NORMAL, "  s <csn>     : specify a card Serial number to diversify the key (if omitted will attempt to read a csn)");
    PrintAndLogEx(NORMAL, "  e           : specify new key as elite calc");
    PrintAndLogEx(NORMAL, "  ee          : specify old and new key as elite calc");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "   -- e key to e key given csn");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass calcnewkey o 1122334455667788 n 2233445566778899 s deadbeafdeadbeaf ee"));
    PrintAndLogEx(NORMAL, "   -- std key to e key read csn");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass calcnewkey o 1122334455667788 n 2233445566778899 e"));
    PrintAndLogEx(NORMAL, "   -- std to std read csn");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass calcnewkey o 1122334455667788 n 2233445566778899"));
    PrintAndLogEx(NORMAL, "\nNOTE: * = required");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_managekeys(void) {
    PrintAndLogEx(NORMAL, "Manage iCLASS Keys in client memory:\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass managekeys n [keynbr] k [key] f [filename] s l p\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h            : Show this help");
    PrintAndLogEx(NORMAL, "  n <keynbr>   : specify the keyNbr to set in memory");
    PrintAndLogEx(NORMAL, "  k <key>      : set a key in memory");
    PrintAndLogEx(NORMAL, "  f <filename> : specify a filename to use with load or save operations");
    PrintAndLogEx(NORMAL, "  s            : save keys in memory to file specified by filename");
    PrintAndLogEx(NORMAL, "  l            : load keys to memory from file specified by filename");
    PrintAndLogEx(NORMAL, "  p            : print keys loaded into memory\n");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "   -- set key");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass managekeys n 0 k 1122334455667788"));
    PrintAndLogEx(NORMAL, "   -- save key file");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass managekeys f mykeys.bin s"));
    PrintAndLogEx(NORMAL, "   -- load key file");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass managekeys f mykeys.bin l"));
    PrintAndLogEx(NORMAL, "   -- print keys");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass managekeys p"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_reader(void) {
    PrintAndLogEx(NORMAL, "Act as a iCLASS reader.  Look for iCLASS tags until Enter or the pm3 button is pressed\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass reader [h] [1]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h   Show this help");
    PrintAndLogEx(NORMAL, "  1   read only 1 tag");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass reader 1"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_replay(void) {
    PrintAndLogEx(NORMAL, "Replay a collected mac message\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass replay [h] [m <mac>]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             Show this help");
    PrintAndLogEx(NORMAL, "  r <nonce>     Reader nonce bytes to replay (8 hexsymbols)");
    PrintAndLogEx(NORMAL, "  m <mac>       Mac bytes to replay (8 hexsymbols)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass replay r 00000000 m 89cb984b"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_loclass(void) {
    PrintAndLogEx(NORMAL, "Execute the offline part of loclass attack");
    PrintAndLogEx(NORMAL, "  An iclass dumpfile is assumed to consist of an arbitrary number of");
    PrintAndLogEx(NORMAL, "  malicious CSNs, and their protocol responses");
    PrintAndLogEx(NORMAL, "  The binary format of the file is expected to be as follows: ");
    PrintAndLogEx(NORMAL, "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>");
    PrintAndLogEx(NORMAL, "   ... totalling N*24 bytes\n");
    PrintAndLogEx(NORMAL, "Usage: hf iclass loclass [h] [t [l]] [f <filename>]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             Show this help");
    PrintAndLogEx(NORMAL, "  t             Perform self-test");
    PrintAndLogEx(NORMAL, "  t l           Perform self-test, including long ones");
    PrintAndLogEx(NORMAL, "  f <filename>  Bruteforce iclass dumpfile");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass loclass f iclass-dump.bin"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass loclass t"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_chk(void) {
    PrintAndLogEx(NORMAL, "Checkkeys loads a dictionary text file with 8byte hex keys to test authenticating against a iClass tag\n");
    PrintAndLogEx(NORMAL, "Usage: hf iclass chk [h|e|r] [f  (*.dic)]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             Show this help");
    PrintAndLogEx(NORMAL, "  f <filename>  Dictionary file with default iclass keys");
    PrintAndLogEx(NORMAL, "  r             raw");
    PrintAndLogEx(NORMAL, "  e             elite");
    PrintAndLogEx(NORMAL, "  c             credit key  (if not use, default is debit)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass chk f dictionaries/iclass_default_keys.dic"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass chk f dictionaries/iclass_default_keys.dic e"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_lookup(void) {
    PrintAndLogEx(NORMAL, "Lookup keys takes some sniffed trace data and tries to verify what key was used against a dictionary file\n");
    PrintAndLogEx(NORMAL, "Usage: hf iclass lookup [h|e|r] [f  (*.dic)] [u <csn>] [p <epurse>] [m <macs>]\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             Show this help");
    PrintAndLogEx(NORMAL, "  f <filename>  Dictionary file with default iclass keys");
    PrintAndLogEx(NORMAL, "  u             CSN");
    PrintAndLogEx(NORMAL, "  p             EPURSE");
    PrintAndLogEx(NORMAL, "  m             macs");
    PrintAndLogEx(NORMAL, "  r             raw");
    PrintAndLogEx(NORMAL, "  e             elite");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f dictionaries/iclass_default_keys.dic"));
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass lookup u 9655a400f8ff12e0 p f0ffffffffffffff m 0000000089cb984b f dictionaries/iclass_default_keys.dic e"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_hf_iclass_permutekey(void) {
    PrintAndLogEx(NORMAL, "Permute function from 'heart of darkness' paper.\n");
    PrintAndLogEx(NORMAL, "Usage:  hf iclass permute [h] <r|f> <bytes>\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h          Show this help");
    PrintAndLogEx(NORMAL, "  r          reverse permuted key");
    PrintAndLogEx(NORMAL, "  f          permute key");
    PrintAndLogEx(NORMAL, "  <bytes>    input bytes");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("\thf iclass permute r 0123456789abcdef"));
    PrintAndLogEx(NORMAL, "");
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

bool check_known_default(uint8_t *csn, uint8_t *epurse, uint8_t *rmac, uint8_t *tmac, uint8_t *key) {

    iclass_prekey_t *prekey = calloc(ICLASS_KEYS_MAX, sizeof(iclass_prekey_t));
    if (prekey == false) {
        return PM3_EMALLOC;
    }

    uint8_t ccnr[12];
    memcpy(ccnr, epurse, 8);
    memcpy(ccnr + 8, rmac, 4);

    GenerateMacKeyFrom(csn, ccnr, false, false, (uint8_t *)iClass_Key_Table, ICLASS_KEYS_MAX, prekey);
    qsort(prekey, ICLASS_KEYS_MAX, sizeof(iclass_prekey_t), cmp_uint32);

    iclass_prekey_t lookup;
    memcpy(lookup.mac, tmac, 4);

    // binsearch
    iclass_prekey_t *item = (iclass_prekey_t *) bsearch(&lookup, prekey, ICLASS_KEYS_MAX, sizeof(iclass_prekey_t), cmp_uint32);
    if (item != NULL) {
        memcpy(key, item->key, 8);
        return true;
    }
    return false;
}

typedef enum {
    None = 0,
    DES,
    RFU,
    TRIPLEDES
} BLOCK79ENCRYPTION;

static inline uint32_t leadingzeros(uint64_t a) {
#if defined __GNUC__
    return __builtin_clzll(a);
#else
    return 0;
#endif
}
static inline uint32_t countones(uint64_t a) {
#if defined __GNUC__
    return __builtin_popcountll(a);
#else
    return 0;
#endif

}

const char *card_types[] = {
    "PicoPass 16K / 16",                       // 000
    "PicoPass 32K with current book 16K / 16", // 001
    "Unknown Card Type!",                      // 010
    "Unknown Card Type!",                      // 011
    "PicoPass 2K",                             // 100
    "Unknown Card Type!",                      // 101
    "PicoPass 16K / 2",                        // 110
    "PicoPass 32K with current book 16K / 2",  // 111
};

uint8_t card_app2_limit[] = {
    0xff,
    0xff,
    0xff,
    0xff,
    0x1f,
    0xff,
    0xff,
    0xff,
};

static uint8_t isset(uint8_t val, uint8_t mask) {
    return (val & mask);
}

static uint8_t notset(uint8_t val, uint8_t mask) {
    return !(val & mask);
}

uint8_t get_pagemap(const picopass_hdr *hdr) {
    return (hdr->conf.fuses & (FUSE_CRYPT0 | FUSE_CRYPT1)) >> 3;
}

static void fuse_config(const picopass_hdr *hdr) {
    uint8_t fuses = hdr->conf.fuses;

    if (isset(fuses, FUSE_FPERS))
        PrintAndLogEx(SUCCESS, "  Mode: " _GREEN_("Personalization (programmable)"));
    else
        PrintAndLogEx(SUCCESS, "  Mode: " _YELLOW_("Application (locked)"));

    if (isset(fuses, FUSE_CODING1)) {
        PrintAndLogEx(SUCCESS, "Coding: RFU");
    } else {
        if (isset(fuses, FUSE_CODING0))
            PrintAndLogEx(SUCCESS, "Coding: " _YELLOW_("ISO 14443-2 B / 15693"));
        else
            PrintAndLogEx(SUCCESS, "Coding: " _YELLOW_("ISO 14443-B only"));
    }

    uint8_t pagemap = get_pagemap(hdr);
    switch (pagemap) {
        case 0x0:
            PrintAndLogEx(INFO, " Crypt: No auth possible. Read only if RA is enabled");
            break;
        case 0x1:
            PrintAndLogEx(SUCCESS, " Crypt: Non secured page");
            break;
        case 0x2:
            PrintAndLogEx(INFO, " Crypt: Secured page, keys locked");
            break;
        case 0x03:
            PrintAndLogEx(SUCCESS, " Crypt: Secured page, " _GREEN_("keys not locked"));
            break;
    }

    if (isset(fuses, FUSE_RA))
        PrintAndLogEx(SUCCESS, "    RA: Read access enabled");
    else
        PrintAndLogEx(INFO, "    RA: Read access not enabled");

    PrintAndLogEx(INFO,
                  "App limit " _YELLOW_("0x%02X") ", OTP " _YELLOW_("0x%02X%02X") ", Block write lock " _YELLOW_("0x%02X")
                  , hdr->conf.app_limit
                  , hdr->conf.otp[1]
                  , hdr->conf.otp[0]
                  , hdr->conf.block_writelock
                 );
    PrintAndLogEx(INFO,
                  "     Chip " _YELLOW_("0x%02X") ", Mem " _YELLOW_("0x%02X") ", EAS " _YELLOW_("0x%02X") ", Fuses " _YELLOW_("0x%02X")
                  , hdr->conf.chip_config
                  , hdr->conf.mem_config
                  , hdr->conf.eas
                  , hdr->conf.fuses
                 );
}

static void getMemConfig(uint8_t mem_cfg, uint8_t chip_cfg, uint8_t *app_areas, uint8_t *kb) {
    // How to determine chip type

    // mem-bit 7 = 16K
    // mem-bit 5 = Book
    // mem-bit 4 = 2K
    // chip-bit 4 = Multi App

    uint8_t k16 = isset(mem_cfg, 0x80);
    //uint8_t k2 = isset(mem_cfg, 0x10);
    uint8_t book = isset(mem_cfg, 0x20);

    if (isset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 2;
        *app_areas = 2;
    } else if (isset(chip_cfg, 0x10) && k16 && !book) {
        *kb = 16;
        *app_areas = 2;
    } else if (notset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 16;
        *app_areas = 16;
    } else if (isset(chip_cfg, 0x10) && k16 && book) {
        *kb = 32;
        *app_areas = 3;
    } else if (notset(chip_cfg, 0x10) && !k16 && book) {
        *kb = 32;
        *app_areas = 17;
    } else {
        *kb = 32;
        *app_areas = 2;
    }
}

static uint8_t get_mem_config(const picopass_hdr *hdr) {
    // three configuration bits that decides sizes
    uint8_t type = (hdr->conf.chip_config & 0x10) >> 2;
    // 16K bit  0 ==  1==
    type |= (hdr->conf.mem_config & 0x80) >> 6;
    //  BOOK bit 0 ==  1==
    type |= (hdr->conf.mem_config & 0x20) >> 5;
    // 2K
    //type |= (hdr->conf.mem_config & 0x10) >> 5;
    return type;
}

static void mem_app_config(const picopass_hdr *hdr) {
    uint8_t mem = hdr->conf.mem_config;
    uint8_t chip = hdr->conf.chip_config;
    uint8_t kb = 2;
    uint8_t app_areas = 2;

    getMemConfig(mem, chip, &app_areas, &kb);

    uint8_t type = get_mem_config(hdr);
    uint8_t app1_limit = hdr->conf.app_limit - 5; // minus header blocks
    uint8_t app2_limit = card_app2_limit[type];
    uint8_t pagemap = get_pagemap(hdr);

    PrintAndLogEx(INFO, "------ " _CYAN_("Memory") " ------");

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        PrintAndLogEx(INFO, "    %u KBits (%u bytes)", kb, app2_limit * 8);
        PrintAndLogEx(INFO, "    Tag has not App Areas");
        return;
    }

    PrintAndLogEx(INFO, "    %u KBits/%u App Areas (%u bytes)", kb, app_areas, (app2_limit + 1) * 8);
    PrintAndLogEx(INFO, "    AA1 blocks %u { 0x06 - 0x%02X (06 - %02d) }", app1_limit, app1_limit + 5, app1_limit + 5);
    PrintAndLogEx(INFO, "    AA2 blocks %u { 0x%02X - 0x%02X (%02d - %02d) }", app2_limit - app1_limit, app1_limit + 5 + 1, app2_limit, app1_limit + 5 + 1, app2_limit);

    PrintAndLogEx(INFO, "------ " _CYAN_("KeyAccess") " ------");
    PrintAndLogEx(INFO, " Kd = Debit key (AA1),  Kc = Credit key (AA2)");
    uint8_t book = isset(mem, 0x20);
    if (book) {
        PrintAndLogEx(INFO, "     Read A - Kd");
        PrintAndLogEx(INFO, "     Read B - Kc");
        PrintAndLogEx(INFO, "    Write A - Kd");
        PrintAndLogEx(INFO, "    Write B - Kc");
        PrintAndLogEx(INFO, "      Debit - Kd or Kc");
        PrintAndLogEx(INFO, "     Credit - Kc");
    } else {
        PrintAndLogEx(INFO, "     Read A - Kd or Kc");
        PrintAndLogEx(INFO, "     Read B - Kd or Kc");
        PrintAndLogEx(INFO, "    Write A - Kc");
        PrintAndLogEx(INFO, "    Write B - Kc");
        PrintAndLogEx(INFO, "      Debit - Kd or Kc");
        PrintAndLogEx(INFO, "     Credit - Kc");
    }
}

static void print_picopass_info(const picopass_hdr *hdr) {
    PrintAndLogEx(INFO, "------ " _CYAN_("card configuration") " ------");
    fuse_config(hdr);
    mem_app_config(hdr);
}
static void print_picopass_header(const picopass_hdr *hdr) {
    PrintAndLogEx(INFO, "------------ " _CYAN_("card") " -------------");
    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s") "  (uid)", sprint_hex(hdr->csn, sizeof(hdr->csn)));
    PrintAndLogEx(SUCCESS, " Config: %s  (Card configuration)", sprint_hex((uint8_t *)&hdr->conf, sizeof(hdr->conf)));
    PrintAndLogEx(SUCCESS, "E-purse: %s  (Card challenge, CC)", sprint_hex(hdr->epurse, sizeof(hdr->epurse)));
    PrintAndLogEx(SUCCESS, "     Kd: %s  (Debit key, hidden)", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
    PrintAndLogEx(SUCCESS, "     Kc: %s  (Credit key, hidden)", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));
    PrintAndLogEx(SUCCESS, "    AIA: %s  (Application Issuer area)", sprint_hex(hdr->app_issuer_area, sizeof(hdr->app_issuer_area)));
}

static int CmdHFiClassList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("iclass");
    return PM3_SUCCESS;
}

static int CmdHFiClassSniff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass sniff",
                  "Sniff the communication reader and tag",
                  "Usage:\n"
                  _YELLOW_("\thf iclass sniff") "\n"
                  _YELLOW_("\thf iclass sniff -j") " -> jam e-purse updates\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("j",  "jam",    "Jam (prevent) e-purse updates"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool jam_epurse_update = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    const uint8_t update_epurse_sequence[2] = {0x87, 0x02};

    struct {
        uint8_t jam_search_len;
        uint8_t jam_search_string[2];
    } PACKED payload;

    if (jam_epurse_update) {
        payload.jam_search_len = sizeof(update_epurse_sequence);
        memcpy(payload.jam_search_string, update_epurse_sequence, sizeof(payload.jam_search_string));
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_SNIFF, (uint8_t *)&payload, sizeof(payload));

    WaitForResponse(CMD_HF_ICLASS_SNIFF, &resp);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static int CmdHFiClassSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_iclass_sim();

    uint8_t CSN[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t sim_type = param_get8ex(Cmd, 0, 0, 10);

    if (sim_type == 0) {
        if (param_gethex(Cmd, 1, CSN, 16)) {
            PrintAndLogEx(ERR, "A CSN should consist of 16 HEX symbols");
            return usage_hf_iclass_sim();
        }
        PrintAndLogEx(INFO, " simtype: %02x CSN: %s", sim_type, sprint_hex(CSN, 8));
    }

    if (sim_type > 4) {
        PrintAndLogEx(ERR, "Undefined simtype %d", sim_type);
        return usage_hf_iclass_sim();
    }

    // remember to change the define NUM_CSNS to match.

    // pre-defined 9 CSN by iceman
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

    switch (sim_type) {

        case ICLASS_SIM_MODE_READER_ATTACK: {
            PrintAndLogEx(INFO, "Starting iCLASS sim 2 attack (elite mode)");
            PrintAndLogEx(INFO, "press " _YELLOW_("`enter`") " to cancel");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, NUM_CSNS, 1, csns, 8 * NUM_CSNS);

            while (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
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
            PrintAndLogEx((success) ? SUCCESS : WARNING, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS, (success) ? "OK" : "FAIL");

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

            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass loclass h") "` to recover elite key");
            break;
        }
        case ICLASS_SIM_MODE_READER_ATTACK_KEYROLL: {
            // reader in key roll mode,  when it has two keys it alternates when trying to verify.
            PrintAndLogEx(INFO, "Starting iCLASS sim 4 attack (elite mode, reader in key roll mode)");
            PrintAndLogEx(INFO, "press Enter to cancel");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, NUM_CSNS, 1, csns, 8 * NUM_CSNS);

            while (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
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
            PrintAndLogEx((success) ? SUCCESS : WARNING, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS * 2, (success) ? "OK" : "FAIL");

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

            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass loclass h") "` to recover elite key");
            break;
        }
        case ICLASS_SIM_MODE_CSN:
        case ICLASS_SIM_MODE_CSN_DEFAULT:
        case ICLASS_SIM_MODE_FULL:
        default: {
            uint8_t numberOfCSNs = 0;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, numberOfCSNs, 1, CSN, 8);

            if (sim_type == ICLASS_SIM_MODE_FULL)
                PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass esave h") "` to save the emulator memory to file");
            break;
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassInfo(const char *Cmd) {
    return info_iclass();
}

int read_iclass_csn(bool loop, bool verbose) {

    uint32_t flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE);
    int res = PM3_SUCCESS;

    while (kbd_enter_pressed() == false) {

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t status = resp.oldarg[0] & 0xff;

            if (loop == false) {
                if (status == 0 || status == 0xFF) {
                    if (verbose) PrintAndLogEx(WARNING, "iCLASS / ISO15693 card select failed");
                    res = PM3_EOPABORTED;
                    break;
                }
            } else {
                if (status == 0xFF)
                    continue;
            }

            picopass_hdr *hdr = (picopass_hdr *)resp.data.asBytes;

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(hdr->csn, sizeof(hdr->csn)));
            PrintAndLogEx(SUCCESS, " Config: " _GREEN_("%s"), sprint_hex((uint8_t *)&hdr->conf, sizeof(hdr->conf)));

            if (loop == false)
                break;
        }
    }

    DropField();
    return res;
}

static int CmdHFiClassReader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_iclass_reader();
    bool loop_read = (cmdp == '1') ? false : true;

    return read_iclass_csn(loop_read, true);
}

static int CmdHFiClassReader_Replay(const char *Cmd) {

    struct {
        uint8_t reader[4];
        uint8_t mac[4];
    } PACKED payload;


    bool got_rnr, got_mac;
    got_rnr = got_mac = false;
    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h': {
                return usage_hf_iclass_replay();
            }
            case 'r': {
                if (param_gethex(Cmd, cmdp + 1, payload.reader, 8)) {
                    PrintAndLogEx(FAILED, "Reader Nr must include 8 HEX symbols");
                    errors = true;
                } else {
                    got_rnr = true;
                }
                cmdp += 2;
                break;
            }
            case 'm': {
                if (param_gethex(Cmd, cmdp + 1, payload.mac, 8)) {
                    PrintAndLogEx(FAILED, "Reader MAC must include 8 HEX symbols");
                    errors = true;
                } else {
                    got_mac = true;
                }
                cmdp += 2;
                break;
            }
            default: {
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
            }
        }
    }

    //Validations
    if (errors || cmdp == 0) {
        return usage_hf_iclass_replay();
    }

    if (got_rnr == false || got_mac == false) {
        PrintAndLogEx(FAILED, "Reader Nr and MAC is needed");
        return PM3_EINVARG;
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_REPLAY, (uint8_t *)&payload, sizeof(payload));

    while (true) {
        PrintAndLogEx(NORMAL, "." NOLF);

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_HF_ICLASS_REPLAY, &resp, 2000))
            break;
    }

    PrintAndLogEx(NORMAL, "");
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to communicate with card");
        return resp.status;
    }

    struct p_resp {
        bool isOK;
        uint16_t block_cnt;
        uint32_t bb_offset;
    } PACKED;
    struct p_resp *packet = (struct p_resp *)resp.data.asBytes;

    if (packet->isOK == false) {
        PrintAndLogEx(WARNING, "replay reading blocks failed");
        return PM3_ESOFT;
    }

    uint32_t startindex = packet->bb_offset;
    uint32_t bytes_got = (packet->block_cnt * 8);

    uint8_t tag_data[0x100 * 8];
    memset(tag_data, 0xFF, sizeof(tag_data));

    // response ok - now get bigbuf content of the dump
    if (!GetFromDevice(BIG_BUF, tag_data, sizeof(tag_data), startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    // print the dump
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
    PrintAndLogEx(INFO, " CSN  |0x00| " _GREEN_("%s") "|", sprint_hex(tag_data, 8));
    printIclassDumpContents(tag_data, 1, (bytes_got / 8), bytes_got);

    // use CSN as filename
    char filename[FILE_PATH_SIZE] = {0};
    strcat(filename, "hf-iclass-");
    FillFileNameByUID(filename, tag_data, "-dump", 8);

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %u blocks read", bytes_got / 8);
    saveFile(filename, ".bin", tag_data, bytes_got);
    saveFileEML(filename, tag_data, bytes_got, 8);
    saveFileJSON(filename, jsfIclass, tag_data, bytes_got, NULL);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass decrypt") "` to decrypt dump file");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass view") "` to view dump file");
    PrintAndLogEx(NORMAL, "");
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
        return usage_hf_iclass_eload();
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
            res = loadFileEML_safe(filename, (void **)&dump, &bytes_read);
            break;
        }
        case JSON: {
            res = loadFileJSON(filename, dump, 2048, &bytes_read, NULL);
            break;
        }
        case DICTIONARY:
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

    print_picopass_header((picopass_hdr *) dump);
    print_picopass_info((picopass_hdr *) dump);

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

static int CmdHFiClassESave(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    char *fnameptr = filename;
    int len = 0;
    uint16_t bytes = 256;
    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_esave();
            case 'f':
                len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (len >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 's':
                bytes = param_get32ex(Cmd, cmdp + 1, 256, 10);
                if (bytes > 4096) {
                    PrintAndLogEx(WARNING, "Emulator memory is max 4096bytes. Truncating %u to 4096", bytes);
                    bytes = 4096;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        return usage_hf_iclass_esave();
    }

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (len < 1) {
        fnameptr += snprintf(fnameptr, sizeof(filename), "hf-iclass-");
        FillFileNameByUID(fnameptr, dump, "-dump", 8);
    }

    saveFile(filename, ".bin", dump, bytes);
    saveFileEML(filename, dump, bytes, 8);
    saveFileJSON(filename, jsfIclass, dump, bytes, NULL);
    free(dump);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass readtagfile ") "` to view dump file");
    return PM3_SUCCESS;
}

static int CmdHFiClassEView(const char *Cmd) {

    uint16_t blocks = 32, bytes = 256;
    bool errors = false, verbose = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_eview();
            case 's':
                bytes = param_get32ex(Cmd, cmdp + 1, 256, 10);

                if (bytes > 4096) {
                    PrintAndLogEx(WARNING, "Emulator memory is max 4096bytes. Truncating %u to 4096", bytes);
                    bytes = 4096;
                }

                if (bytes % 8 != 0) {
                    bytes &= 0xFFF8;
                    PrintAndLogEx(WARNING, "Number not divided by 8, truncating to %u", bytes);
                }

                blocks = bytes / 8;
                cmdp += 2;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || bytes == 0) {
        return usage_hf_iclass_eview();
    }

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }
    memset(dump, 0, bytes);

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (verbose) {
        print_picopass_header((picopass_hdr *) dump);
        print_picopass_info((picopass_hdr *) dump);
    }

    PrintAndLogEx(NORMAL, "");
    uint8_t *csn = dump;
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
    PrintAndLogEx(INFO, " CSN  |0x00| " _GREEN_("%s") "|", sprint_hex(csn, 8));
    printIclassDumpContents(dump, 1, blocks, bytes);

    /*
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "----+-------------------------+---------");
        PrintAndLogEx(INFO, "blk | data                    | ascii");
        PrintAndLogEx(INFO, "----+-------------------------+---------");
        for (uint16_t i = 0; i < blocks; i++){
            PrintAndLogEx(INFO, "%03d | %s ", i, sprint_hex_ascii(dump + (i * 8) , 8) );
        }
        PrintAndLogEx(INFO, "----+-------------------------+---------");
        PrintAndLogEx(NORMAL, "");
    */
    free(dump);
    return PM3_SUCCESS;
}


static int CmdHFiClassDecrypt(const char *Cmd) {

    bool errors = false;
    bool have_key = false;
    bool have_data = false;
    bool have_file = false;
    bool verbose = false;
    uint8_t cmdp = 0;

    uint8_t enc_data[8] = {0};
    uint8_t dec_data[8] = {0};

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
                    PrintAndLogEx(ERR, "Data must be 16 HEX symbols");
                    errors = true;
                    break;
                }
                have_data = true;
                cmdp += 2;
                break;
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, sizeof(filename)) == 0) {
                    PrintAndLogEx(WARNING, "No filename found after f");
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

    if (errors || cmdp < 1) return usage_hf_iclass_decrypt();

    bool use_sc = IsCryptoHelperPresent(verbose);

    if (have_key == false && use_sc == false) {
        int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Couldn't find any decryption methods");
            return PM3_EINVARG;
        }
        memcpy(key, keyptr, sizeof(key));
        free(keyptr);
    }

    // tripledes
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    if (have_data) {

        if (use_sc) {
            Decrypt(enc_data, dec_data);
        } else {
            mbedtls_des3_crypt_ecb(&ctx, enc_data, dec_data);
        }
        PrintAndLogEx(SUCCESS, "Data: %s", sprint_hex(dec_data, sizeof(dec_data)));
    }

    if (have_file) {

        picopass_hdr *hdr = (picopass_hdr *)decrypted;

        uint8_t mem = hdr->conf.mem_config;
        uint8_t chip = hdr->conf.chip_config;
        uint8_t applimit = hdr->conf.app_limit;
        uint8_t kb = 2;
        uint8_t app_areas = 2;
        getMemConfig(mem, chip, &app_areas, &kb);

        BLOCK79ENCRYPTION aa1_encryption = (decrypted[(6 * 8) + 7] & 0x03);

        uint32_t limit = MIN(applimit, decryptedlen / 8);

        if (decryptedlen / 8 != applimit) {
            PrintAndLogEx(WARNING, "Actual file len " _YELLOW_("%zu") " vs HID app-limit len " _YELLOW_("%u"), decryptedlen, applimit * 8);
            PrintAndLogEx(INFO, "Setting limit to " _GREEN_("%u"), limit * 8);
        }

        //uint8_t numblocks4userid = GetNumberBlocksForUserId(decrypted + (6 * 8));

        for (uint16_t blocknum = 0; blocknum < limit; ++blocknum) {

            uint8_t idx = blocknum * 8;
            memcpy(enc_data, decrypted + idx, 8);

            if (aa1_encryption == RFU || aa1_encryption == None)
                continue;

            // Decrypted block 7,8,9 if configured.
            if (blocknum > 6 && blocknum <= 9 && memcmp(enc_data, empty, 8) != 0) {
                if (use_sc) {
                    Decrypt(enc_data, decrypted + idx);
                } else {
                    mbedtls_des3_crypt_ecb(&ctx, enc_data, decrypted + idx);
                }
            }
        }

        // use the first block (CSN) for filename
        char *fptr = calloc(50, sizeof(uint8_t));
        if (fptr == false) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            free(decrypted);
            return PM3_EMALLOC;
        }

        strcat(fptr, "hf-iclass-");
        FillFileNameByUID(fptr, hdr->csn, "-dump-decrypted", sizeof(hdr->csn));

        saveFile(fptr, ".bin", decrypted, decryptedlen);
        saveFileEML(fptr, decrypted, decryptedlen, 8);
        saveFileJSON(fptr, jsfIclass, decrypted, decryptedlen, NULL);

        PrintAndLogEx(INFO, "Following output skips CSN / block0");
        printIclassDumpContents(decrypted, 1, (decryptedlen / 8), decryptedlen);

        PrintAndLogEx(NORMAL, "");

        // decode block 6
        if (memcmp(decrypted + (8 * 6), empty, 8) != 0) {
            if (use_sc) {
                DecodeBlock6(decrypted + (8 * 6));
            }
        }

        // decode block 7-8-9
        if (memcmp(decrypted + (8 * 7), empty, 8) != 0) {

            //todo:  remove preamble/sentinal

            uint32_t top = 0, mid, bot;
            mid = bytes_to_num(decrypted + (8 * 7), 4);
            bot = bytes_to_num(decrypted + (8 * 7) + 4, 4);

            PrintAndLogEx(INFO, "Block 7 decoder");

            char hexstr[8 + 1] = {0};
            hex_to_buffer((uint8_t *)hexstr, decrypted + (8 * 7), 8, sizeof(hexstr) - 1, 0, 0, true);

            char binstr[8 * 8 + 1] = {0};
            hextobinstring(binstr, hexstr);
            uint8_t i = 0;
            while (i < strlen(binstr) && binstr[i++] == '0');

            PrintAndLogEx(SUCCESS, "Binary..................... " _GREEN_("%s"), binstr + i);

            PrintAndLogEx(INFO, "Wiegand decode");
            wiegand_message_t packed = initialize_message_object(top, mid, bot);
            HIDTryUnpack(&packed, true);

        } else {
            PrintAndLogEx(INFO, "No credential found.");
        }

        // decode block 9
        if (memcmp(decrypted + (8 * 9), empty, 8) != 0) {

            uint8_t usr_blk_len = GetNumberBlocksForUserId(decrypted + (8 * 6));
            if (usr_blk_len < 3) {

                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, "Block 9 decoder");
                uint8_t pinsize = 0;
                if (use_sc) {
                    pinsize = GetPinSize(decrypted + (8 * 6));

                    if (pinsize > 0) {

                        uint64_t pin = bytes_to_num(decrypted + (8 * 9), 5);
                        char tmp[17] = {0};
                        snprintf(tmp, sizeof(tmp), "%."PRIu64, BCD2DEC(pin));
                        PrintAndLogEx(INFO, "PIN........................ " _GREEN_("%.*s"), pinsize, tmp);
                    }
                }
            }
        }

        PrintAndLogEx(INFO, "-----------------------------------------------------------------");

        free(decrypted);
        free(fptr);
    }

    mbedtls_des3_free(&ctx);
    return PM3_SUCCESS;
}

static void iclass_encrypt_block_data(uint8_t *blk_data, uint8_t *key) {
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
    bool verbose = false;
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

    if (errors || cmdp < 1) return usage_hf_iclass_encrypt();

    bool use_sc = IsCryptoHelperPresent(verbose);

    if (have_key == false && use_sc == false) {
        size_t keylen = 0;
        int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
        if (res != PM3_SUCCESS)
            return PM3_EINVARG;

        memcpy(key, keyptr, sizeof(key));
        free(keyptr);
    }

    if (use_sc) {
        Encrypt(blk_data, blk_data);
    } else {
        iclass_encrypt_block_data(blk_data, key);
    }
    PrintAndLogEx(SUCCESS, "encrypted block %s", sprint_hex(blk_data, 8));
    return PM3_SUCCESS;
}

static void calc_wb_mac(uint8_t blockno, uint8_t *data, uint8_t *div_key, uint8_t *MAC) {
    uint8_t wb[9];
    wb[0] = blockno;
    memcpy(wb + 1, data, 8);
    doMAC_N(wb, sizeof(wb), div_key, MAC);
}

static bool select_only(uint8_t *CSN, uint8_t *CCNR, bool verbose) {

    uint8_t flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE);

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "command execute timeout");
        return false;
    }

    uint8_t isok = resp.oldarg[0] & 0xff;

    // no tag found or button pressed
    if ((isok == 0) || isok == 0xFF) {
        if (verbose) {
            PrintAndLogEx(FAILED, "failed tag-select, aborting...  (%d)", isok);
        }
        return false;
    }

    picopass_hdr *hdr = (picopass_hdr *)resp.data.asBytes;

    if (CSN != NULL)
        memcpy(CSN, hdr->csn, 8);

    if (CCNR != NULL)
        memcpy(CCNR, hdr->epurse, 8);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "CSN     %s", sprint_hex(CSN, 8));
        PrintAndLogEx(SUCCESS, "epurse  %s", sprint_hex(CCNR, 8));
    }
    return true;
}

static bool select_and_auth(uint8_t *KEY, uint8_t *MAC, uint8_t *div_key, bool use_credit_key, bool elite, bool rawkey, bool verbose) {

    iclass_auth_req_t payload = {
        .use_raw = rawkey,
        .use_elite = elite,
        .use_credit_key = use_credit_key
    };
    memcpy(payload.key, KEY, 8);

    SendCommandNG(CMD_HF_ICLASS_AUTH, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    clearCommandBuffer();
    if (WaitForResponseTimeout(CMD_HF_ICLASS_AUTH, &resp, 2000) == 0) {
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return false;
    }

    iclass_readblock_resp_t *packet = (iclass_readblock_resp_t *)resp.data.asBytes;

    if (packet->isOK == 0) {
        if (verbose) PrintAndLogEx(FAILED, "authentication error");
        return false;
    }

    if (div_key)
        memcpy(div_key, packet->div_key, sizeof(packet->div_key));

    if (MAC)
        memcpy(MAC, packet->mac, sizeof(packet->mac));

    if (verbose)
        PrintAndLogEx(SUCCESS, "authing with %s: %s", rawkey ? "raw key" : "diversified key", sprint_hex(div_key, 8));

    return true;
}

static int CmdHFiClassDump(const char *Cmd) {

    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CreditKEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t keyNbr = 0;
    uint8_t dataLen = 0;
    uint8_t app_limit1 = 0, app_limit2 = 0;
    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char tempStr[50] = {0};
    bool have_credit_key = false;
    bool elite = false;
    bool rawkey = false;
    bool errors = false;
    bool auth = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_dump();
            case 'c':
                auth = true;
                have_credit_key = true;
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, CreditKEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(CreditKEY, iClass_Key_Table[keyNbr], 8);
                        PrintAndLogEx(INFO, "AA2 (credit) index %u", keyNbr);
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
                auth = true;
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 16) {
                    errors = param_gethex(tempStr, 0, KEY, dataLen);
                } else if (dataLen == 1) {
                    keyNbr = param_get8(Cmd, cmdp + 1);
                    if (keyNbr < ICLASS_KEYS_MAX) {
                        memcpy(KEY, iClass_Key_Table[keyNbr], 8);
                        PrintAndLogEx(INFO, "AA1 (debit) index %u", keyNbr);
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
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_hf_iclass_dump();

    uint32_t flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE);

    //get CSN and config
    PacketResponseNG resp;
    uint8_t tag_data[0x100 * 8];
    memset(tag_data, 0xFF, sizeof(tag_data));

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "command execute timeout");
        DropField();
        return PM3_ESOFT;
    }
    DropField();

    uint8_t readStatus = resp.oldarg[0] & 0xff;
    picopass_hdr *hdr = (picopass_hdr *)resp.data.asBytes;

    if (readStatus == 0) {
        PrintAndLogEx(FAILED, "no tag found");
        DropField();
        return PM3_ESOFT;
    }

    uint8_t pagemap = get_pagemap(hdr);

    if (readStatus & (FLAG_ICLASS_CSN | FLAG_ICLASS_CONF | FLAG_ICLASS_CC)) {

        memcpy(tag_data, hdr, 24);

        uint8_t type = get_mem_config(hdr);

        // tags configured for NON SECURE PAGE,  acts different
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {

            PrintAndLogEx(INFO, "Card in non-secure page mode detected");

            app_limit1 = card_app2_limit[type];
            app_limit2 = 0;
        } else {
            app_limit1 = hdr->conf.app_limit;
            app_limit2 = card_app2_limit[type];
        }

    } else {
        PrintAndLogEx(FAILED, "failed to read block 0,1,2");
        DropField();
        return PM3_ESOFT;
    }

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        PrintAndLogEx(INFO, "Dumping all available memory, block 3 - %u (0x%02x)", app_limit1, app_limit1);
        if (auth) {
            PrintAndLogEx(INFO, "No keys needed, ignoring user supplied key");
        }
    } else {
        if (auth == false) {
            PrintAndLogEx(FAILED, "Run command with keys");
            return PM3_ESOFT;
        }
        PrintAndLogEx(INFO, "Card has atleast 2 application areas. AA1 limit %u (0x%02X) AA2 limit %u (0x%02X)", app_limit1, app_limit1, app_limit2, app_limit2);
    }

    iclass_dump_req_t payload = {
        .req.use_raw = rawkey,
        .req.use_elite = elite,
        .req.use_credit_key = false,
        .req.send_reply = true,
        .req.do_auth = auth,
        .end_block = app_limit1,
    };
    memcpy(payload.req.key, KEY, 8);

    // tags configured for NON SECURE PAGE,  acts different
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        payload.start_block = 3;
        payload.req.do_auth = false;
    } else {
        payload.start_block = 6;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_DUMP, (uint8_t *)&payload, sizeof(payload));

    while (true) {

        PrintAndLogEx(NORMAL, "." NOLF);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_HF_ICLASS_DUMP, &resp, 2000))
            break;
    }

    PrintAndLogEx(NORMAL, "");
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to communicate with card");
        return resp.status;
    }

    struct p_resp {
        bool isOK;
        uint16_t block_cnt;
        uint32_t bb_offset;
    } PACKED;
    struct p_resp *packet = (struct p_resp *)resp.data.asBytes;

    if (packet->isOK == false) {
        PrintAndLogEx(WARNING, "read AA1 blocks failed");
        return PM3_ESOFT;
    }

    uint32_t startindex = packet->bb_offset;
    uint32_t blocks_read = packet->block_cnt;

    uint8_t tempbuf[0x100 * 8];

    // response ok - now get bigbuf content of the dump
    if (!GetFromDevice(BIG_BUF, tempbuf, sizeof(tempbuf), startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        // all memory available
        memcpy(tag_data + (8 * 3), tempbuf + (8 * 3), (blocks_read * 8));
    } else {
        // div key KD
        memcpy(tag_data + (8 * 3), tempbuf + (8 * 3), 8);
        // AIA data
        memcpy(tag_data + (8 * 5), tempbuf + (8 * 5), 8);
        // AA1 data
        memcpy(tag_data + (8 * 6), tempbuf + (8 * 6), (blocks_read * 8));
    }

    uint16_t bytes_got = (app_limit1 + 1) * 8;

    // try AA2 Kc, Credit
    bool aa2_success = false;

    if (have_credit_key && pagemap != 0x01) {

        // AA2 authenticate credit key
        memcpy(payload.req.key, CreditKEY, 8);

        payload.req.use_credit_key = true;
        payload.start_block = app_limit1 + 1;
        payload.end_block = app_limit2;
        payload.req.do_auth = true;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_DUMP, (uint8_t *)&payload, sizeof(payload));

        while (true) {
            PrintAndLogEx(NORMAL, "." NOLF);
            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                DropField();
                return PM3_EOPABORTED;
            }

            if (WaitForResponseTimeout(CMD_HF_ICLASS_DUMP, &resp, 2000))
                break;
        }
        PrintAndLogEx(NORMAL, "");
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to communicate with card");
            goto write_dump;
        }

        packet = (struct p_resp *)resp.data.asBytes;
        if (packet->isOK == false) {
            PrintAndLogEx(WARNING, "failed read block using credit key");
            goto write_dump;
        }

        blocks_read = packet->block_cnt;
        startindex = packet->bb_offset;

        if (blocks_read * 8 > sizeof(tag_data) - bytes_got) {
            PrintAndLogEx(WARNING, "data exceeded buffer size! ");
            blocks_read = (sizeof(tag_data) - bytes_got) / 8;
        }

        // get dumped data from bigbuf
        if (!GetFromDevice(BIG_BUF, tempbuf, sizeof(tempbuf), startindex, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            goto write_dump;
        }

        // div key KC
        memcpy(tag_data + (8 * 4), tempbuf + (8 * 4), 8);

        // AA2 data
        memcpy(tag_data + (8 * (app_limit1 + 1)), tempbuf + (8 * (app_limit1 + 1)), (blocks_read * 8));

        bytes_got = (blocks_read * 8);

        aa2_success = true;
    }

write_dump:

    if (have_credit_key && pagemap != 0x01 && aa2_success == false)
        PrintAndLogEx(INFO, "Reading AA2 failed. dumping AA1 data to file");

    // print the dump
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
    PrintAndLogEx(INFO, " CSN  |0x00| " _GREEN_("%s") "|", sprint_hex(tag_data, 8));
    printIclassDumpContents(tag_data, 1, (bytes_got / 8), bytes_got);

    // use CSN as filename
    if (filename[0] == 0) {
        strcat(filename, "hf-iclass-");
        FillFileNameByUID(filename, tag_data, "-dump", 8);
    }

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %u blocks read", bytes_got / 8);
    saveFile(filename, ".bin", tag_data, bytes_got);
    saveFileEML(filename, tag_data, bytes_got, 8);
    saveFileJSON(filename, jsfIclass, tag_data, bytes_got, NULL);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass decrypt") "` to decrypt dump file");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass view") "` to view dump file");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int iclass_write_block(uint8_t blockno, uint8_t *bldata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool verbose) {
    /*
        uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
        uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (select_and_auth(KEY, MAC, div_key, use_credit_key, elite, rawkey, verbose) == false) {
            return PM3_ESOFT;
        }

        calc_wb_mac(blockno, bldata, div_key, MAC);

        struct p {
            uint8_t blockno;
            uint8_t data[12];
        } PACKED payload;
        payload.blockno = blockno;

        memcpy(payload.data, bldata, 8);
        memcpy(payload.data + 8, MAC, 4);


    //
    typedef struct {
        uint8_t key[8];
        bool use_raw;
        bool use_elite;
        bool use_credit_key;
        bool send_reply;
        bool do_auth;
        uint8_t blockno;
    } PACKED iclass_auth_req_t;

    // iCLASS write block request data structure
    typedef struct {
        iclass_auth_req_t req;
        uint8_t data[8];
    } PACKED iclass_writeblock_req_t;


    */
    iclass_writeblock_req_t payload = {
        .req.use_raw = rawkey,
        .req.use_elite = elite,
        .req.use_credit_key = use_credit_key,
        .req.blockno = blockno,
        .req.send_reply = true,
        .req.do_auth = true,
    };
    memcpy(payload.req.key, KEY, 8);
    memcpy(payload.data, bldata, sizeof(payload.data));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_WRITEBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_HF_ICLASS_WRITEBL, &resp, 2000) == 0) {
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return PM3_EWRONGANSWER;
    }

    return (resp.data.asBytes[0] == 1) ? PM3_SUCCESS : PM3_ESOFT;
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

    int isok = iclass_write_block(blockno, bldata, KEY, use_credit_key, elite, rawkey, verbose);
    if (isok == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Wrote block %02X successful", blockno);
    else
        PrintAndLogEx(FAILED, "Writing failed");
    return isok;
}

/*
static int CmdHFiClassClone(const char *Cmd) {
    return PM3_SUCCESS;
}
*/
static int CmdHFiClassRestore(const char *Cmd) {
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
                return usage_hf_iclass_restore();
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

    if (errors || cmdp < 8) return usage_hf_iclass_restore();

    if (startblock < 5) {
        PrintAndLogEx(WARNING, "you cannot write key blocks this way. yet... make your start block > 4");
        return PM3_EINVARG;
    }

    int total_bytes = (((endblock - startblock) + 1) * 12);

    if (total_bytes > PM3_CMD_DATA_SIZE - 2) {
        PrintAndLogEx(NORMAL, "Trying to write too many blocks at once.  Max: %d", PM3_CMD_DATA_SIZE / 8);
        return PM3_EINVARG;
    }

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (bytes_read == 0) {
        PrintAndLogEx(ERR, "file reading error");
        free(dump);
        return PM3_EFILE;
    }

    if (bytes_read < sizeof(iclass_block_t) * (endblock - startblock + 1)) {
        PrintAndLogEx(ERR, "file wrong size");
        free(dump);
        return PM3_EFILE;
    }

    // read data from file from block 6 --- 19
    // we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
    // then copy to usbcommand->asbytes;
    // max is 32 - 6 = 28 block.  28 x 12 bytes gives 336 bytes
    iclass_block_t tag_data[PM3_CMD_DATA_SIZE / 12];

    memcpy(tag_data, dump + startblock * 8, sizeof(iclass_block_t) * (endblock - startblock + 1));

    free(dump);

    uint8_t MAC[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    int i;
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

        calc_wb_mac(i, tag_data[i - startblock].d, div_key, MAC);
        // usb command d start pointer = d + (i - 6) * 12
        // memcpy(pointer,tag_data[i - 6],8) 8 bytes
        // memcpy(pointer + 8,mac,sizoof(mac) 4 bytes;
        // next one
        uint8_t *ptr = data + (i - startblock) * 12;
        memcpy(ptr, &(tag_data[i - startblock].d[0]), 8);
        memcpy(ptr + 8, MAC, 4);
    }

    if (verbose) {
        PrintAndLogEx(INFO, "------+--------------------------+-------------");
        PrintAndLogEx(INFO, "block | data                     | mac");
        PrintAndLogEx(INFO, "------+--------------------------+-------------");
        uint8_t p[12];
        for (i = 0; i <= endblock - startblock; i++) {
            memcpy(p, data + (i * 12), 12);
            char *s = calloc(70, sizeof(uint8_t));
            snprintf(s, 70, "| %s ", sprint_hex(p, 8));
            snprintf(s + strlen(s), 70 - strlen(s), "| %s", sprint_hex(p + 8, 4));
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

    if (WaitForResponseTimeout(CMD_HF_ICLASS_CLONE, &resp, 2000) == 0) {
        PrintAndLogEx(WARNING, "command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (resp.data.asBytes[0] == 1)
            PrintAndLogEx(SUCCESS, "Restore successful");
        else
            PrintAndLogEx(WARNING, "Restore failed");
    }
    return resp.status;
}

static int iclass_read_block(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool verbose, bool auth, uint8_t *out) {

    iclass_auth_req_t payload = {
        .use_raw = rawkey,
        .use_elite = elite,
        .use_credit_key = (keyType == 0x18),
        .blockno = blockno,
        .send_reply = true,
        .do_auth = auth,
    };
    memcpy(payload.key, KEY, 8);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_READBL, (uint8_t *)&payload, sizeof(payload));

    if (WaitForResponseTimeout(CMD_HF_ICLASS_READBL, &resp, 2000) == false) {
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return PM3_EWRONGANSWER;
    }

    // return data.
    iclass_readblock_resp_t *packet = (iclass_readblock_resp_t *)resp.data.asBytes;

    if (packet->isOK == false) {
        if (verbose) PrintAndLogEx(FAILED, "authentication error");
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " block %02X : " _GREEN_("%s"), blockno, sprint_hex(packet->data, sizeof(packet->data)));
    PrintAndLogEx(NORMAL, "");

    if (out)
        memcpy(out, packet->data, sizeof(packet->data));

    return PM3_SUCCESS;
}

static int CmdHFiClass_ReadBlock(const char *Cmd) {
    uint8_t blockno = 0;
    uint8_t keyType = 0x88; //debit key
    uint8_t KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t key_idx = 0;
    uint8_t key_len = 0;
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
                PrintAndLogEx(SUCCESS, "Using " _YELLOW_("KC credit"));
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
                key_len = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (key_len == 16) {
                    errors = param_gethex(tempStr, 0, KEY, key_len);
                } else if (key_len == 1) {
                    key_idx = param_get8(Cmd, cmdp + 1);
                    if (key_idx < ICLASS_KEYS_MAX) {
                        memcpy(KEY, iClass_Key_Table[key_idx], 8);
                    } else {
                        PrintAndLogEx(WARNING, "\nERROR: key index is invalid\n");
                        errors = true;
                    }
                } else {
                    PrintAndLogEx(WARNING, "\nERROR: incorrect key length\n");
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

    if (errors) return usage_hf_iclass_readblock();

    if (verbose) {
        if (key_len == 1)
            PrintAndLogEx(SUCCESS, "Using key[%d] %s", key_idx, sprint_hex(KEY, 8));
        else
            PrintAndLogEx(SUCCESS, "Using key %s", sprint_hex(KEY, 8));
    }

    if (auth == false && verbose) {
        PrintAndLogEx(WARNING, "warning: no authentication used with read. Typical for cards configured toin `non-secure page`");

    }

    uint8_t data[8] = {0};
    int res = iclass_read_block(KEY, blockno, keyType, elite, rawkey, verbose, auth, data);
    if (res != PM3_SUCCESS)
        return res;

    if (blockno < 6 || blockno > 7)
        return PM3_SUCCESS;

    if (memcmp(data, empty, 8) == 0)
        return PM3_SUCCESS;

    bool use_sc = IsCryptoHelperPresent(verbose);
    if (use_sc == false)
        return PM3_SUCCESS;

    // crypto helper available.
    PrintAndLogEx(INFO, "----------------------------- " _CYAN_("cardhelper") " -----------------------------");

    switch (blockno) {
        case 6: {
            DecodeBlock6(data);
            break;
        }
        case 7: {

            uint8_t dec_data[8];

            uint64_t a = bytes_to_num(data, 8);
            bool starts = (leadingzeros(a) < 12);
            bool ones = (countones(a) > 16 && countones(a) < 48);

            if (starts && ones) {
                PrintAndLogEx(INFO, "data looks encrypted, False Positives " _YELLOW_("ARE") " possible");
                Decrypt(data, dec_data);
                PrintAndLogEx(SUCCESS, "decrypted : " _GREEN_("%s"), sprint_hex(dec_data, sizeof(dec_data)));
            } else {
                memcpy(dec_data, data, sizeof(dec_data));
                PrintAndLogEx(INFO, "data looks unencrypted, trying to decode");
            }

            if (memcmp(dec_data, empty, 8) != 0) {

                //todo:  remove preamble/sentinal

                uint32_t top = 0, mid, bot;
                mid = bytes_to_num(dec_data, 4);
                bot = bytes_to_num(dec_data + 4, 4);

                char hexstr[16 + 1] = {0};
                hex_to_buffer((uint8_t *)hexstr, dec_data, 8, sizeof(hexstr) - 1, 0, 0, true);
                char binstr[64 + 1] = {0};
                hextobinstring(binstr, hexstr);
                uint8_t i = 0;
                while (i < strlen(binstr) && binstr[i++] == '0');

                i &= 0x3C;
                PrintAndLogEx(SUCCESS, "      bin : %s", binstr + i);
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "------------------------------ " _CYAN_("wiegand") " -------------------------------");
                wiegand_message_t packed = initialize_message_object(top, mid, bot);
                HIDTryUnpack(&packed, true);
            } else {
                PrintAndLogEx(INFO, "no credential found");
            }
            break;
        }
    }
    PrintAndLogEx(INFO, "----------------------------------------------------------------------");
    return PM3_SUCCESS;
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
        errors += doKeyTests();
        errors += testElite(opt2 == 'l');

        if (errors != PM3_SUCCESS)
            PrintAndLogEx(ERR, "There were errors!!!");

        return PM3_ESOFT;
    }

    return usage_hf_iclass_loclass();
}

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize) {

    picopass_hdr *hdr = (picopass_hdr *)iclass_dump;
//    picopass_ns_hdr *ns_hdr = (picopass_ns_hdr *)iclass_dump;
//    uint8_t pagemap = get_pagemap(hdr);
//    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) { }

    uint8_t lock = hdr->conf.block_writelock;

    // is chip in ReadOnly (RO)
    bool ro = ((lock & 0x80) == 0);

    uint8_t maxmemcount;
    uint8_t filemaxblock = filesize / 8;
    uint8_t mem_config = iclass_dump[13];

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

    /*
    PrintAndLogEx(INFO, "startblock: %u, endblock: %u, filesize: %zu, maxmemcount: %u, filemaxblock: %u"
        , startblock
        , endblock
        , filesize
        , maxmemcount
        , filemaxblock
    );
    */

    int i = startblock;
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
    while (i <= endblock) {
        uint8_t *blk = iclass_dump + (i * 8);

        bool bl_lock = false;
        if (ro == false) {
            switch (i) {
                case 12: {
                    bl_lock = ((lock & 0x40) == 0);
                    break;
                }
                case 11: {
                    bl_lock = ((lock & 0x20) == 0);
                    break;
                }
                case 10: {
                    bl_lock = ((lock & 0x10) == 0);
                    break;
                }
                case 9: {
                    bl_lock = ((lock & 0x08) == 0);
                    break;
                }
                case 8: {
                    bl_lock = ((lock & 0x04) == 0);
                    break;
                }
                case 7: {
                    bl_lock = ((lock & 0x02) == 0);
                    break;
                }
                case 6: {
                    bl_lock = ((lock & 0x01) == 0);
                    break;
                }
            }
        } else {
            bl_lock = true;
        }

        PrintAndLogEx(INFO, "  %c   |0x%02X| %s", (bl_lock) ? 'x' : ' ', i, sprint_hex_ascii(blk, 8));
        i++;
    }
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
}

static int CmdHFiClassView(const char *Cmd) {
    int startblock = 0;
    int endblock = 0;
    char filename[FILE_PATH_SIZE];
    bool errors = false, verbose = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_iclass_view();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 's':
                startblock = param_get8ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'e':
                endblock = param_get8ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
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

    if (errors || (strlen(Cmd) == 0)) return usage_hf_iclass_view();

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, (uint16_t)(bytes_read >> 3), (uint16_t)(bytes_read >> 3));
        PrintAndLogEx(INFO, "Printing blocks from");
        PrintAndLogEx(INFO, "start " _YELLOW_("0x%02x") " end " _YELLOW_("0x%02x"), (startblock == 0) ? 6 : startblock, endblock);
    }

    print_picopass_header((picopass_hdr *) dump);
    print_picopass_info((picopass_hdr *) dump);

    PrintAndLogEx(NORMAL, "");
    uint8_t *csn = dump;
    PrintAndLogEx(INFO, "------+----+-------------------------+----------");
    PrintAndLogEx(INFO, " CSN  |0x00| " _GREEN_("%s") "|", sprint_hex(csn, 8));
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
            key_sel[i] = keytable[key_index[i]];

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
        PrintAndLogEx(SUCCESS, "Old div key : %s", sprint_hex(old_div_key, 8));
        PrintAndLogEx(SUCCESS, "New div key : %s", sprint_hex(new_div_key, 8));
        PrintAndLogEx(SUCCESS, "Xor div key : " _YELLOW_("%s") "\n", sprint_hex(xor_div_key, 8));
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
    bool old_elite = false;
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
                    old_elite = true;
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

    if (givenCSN == false) {
        uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (select_only(CSN, CCNR, true) == false) {
            DropField();
            return PM3_ESOFT;
        }
    }

    HFiClassCalcNewKey(CSN, OLDKEY, NEWKEY, xor_div_key, elite, old_elite, true);

    return PM3_SUCCESS;
}

static int loadKeys(char *filename) {

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (bytes_read > ICLASS_KEYS_MAX * 8) {
        PrintAndLogEx(WARNING, "File is too long to load - bytes: %zu", bytes_read);
        free(dump);
        return PM3_EFILE;
    }
    uint8_t i = 0;
    for (; i < bytes_read / 8; i++)
        memcpy(iClass_Key_Table[i], dump + (i * 8), 8);

    free(dump);
    PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2d") " keys from %s", i, filename);
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
            PrintAndLogEx(INFO, "%u: %s", i, sprint_hex(iClass_Key_Table[i], 8));
        else
            PrintAndLogEx(INFO, "%u: "_YELLOW_("%s"), i, sprint_hex(iClass_Key_Table[i], 8));
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

static void add_key(uint8_t *key) {

    uint8_t i;
    for (i = 0; i < ICLASS_KEYS_MAX; i++) {

        if (memcmp(iClass_Key_Table[i], key, 8) == 0) {
            PrintAndLogEx(SUCCESS, "Key already at keyslot " _GREEN_("%d"), i);
            break;
        }

        if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) {
            memcpy(iClass_Key_Table[i], key, 8);
            PrintAndLogEx(SUCCESS, "Added key to keyslot " _GREEN_("%d"), i);
            break;
        }
    }

    if (i == ICLASS_KEYS_MAX) {
        PrintAndLogEx(INFO, "Couldn't find an empty keyslot");
    } else {
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf iclass managekeys p`") " to view keys");
    }
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
    bool found_key = false;
    //bool found_credit = false;
    bool got_csn = false;
    bool errors = false;
    uint8_t cmdp = 0x00;

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t fileNameLen = 0;

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
    uint32_t keycount = 0;

    // load keys
    int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
    if (res != PM3_SUCCESS || keycount == 0) {
        free(keyBlock);
        return res;
    }

    iclass_premac_t *pre = calloc(keycount, sizeof(iclass_premac_t));
    if (!pre) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    // Get CSN / UID and CCNR
    PrintAndLogEx(SUCCESS, "Reading tag CSN / CCNR...");
    for (uint8_t i = 0; i < ICLASS_AUTH_RETRY && !got_csn; i++) {
        got_csn = select_only(CSN, CCNR, false);
        if (got_csn == false)
            PrintAndLogEx(WARNING, "one more try");
    }

    if (got_csn == false) {
        PrintAndLogEx(WARNING, "Tried 10 times. Can't select card, aborting...");
        free(keyBlock);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, "   CCNR: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));

    PrintAndLogEx(SUCCESS, "Generating diversified keys %s", (use_elite || use_raw) ? NOLF : "");
    if (use_elite)
        PrintAndLogEx(NORMAL, "using " _YELLOW_("elite algo"));
    if (use_raw)
        PrintAndLogEx(NORMAL, "using " _YELLOW_("raw mode"));

    GenerateMacFrom(CSN, CCNR, use_raw, use_elite, keyBlock, keycount, pre);

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") " key...", (use_credit_key) ? "CREDIT" : "DEBIT");

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
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Aborted via keyboard!");
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

        bool looped = false;
        while (!WaitForResponseTimeout(CMD_HF_ICLASS_CHKKEYS, &resp, 2000)) {
            timeout++;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 120) {
                PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
                goto out;
            }
            looped = true;
        }

        if (looped)
            PrintAndLogEx(NORMAL, "");

        found_offset = resp.oldarg[1] & 0xFF;
        uint8_t isOK = resp.oldarg[0] & 0xFF;

        t2 = msclock() - t2;
        switch (isOK) {
            case 1: {
                found_key = true;
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(SUCCESS, "Found valid key " _GREEN_("%s")
                              , sprint_hex(keyBlock + (key_offset + found_offset) * 8, 8)
                             );
                break;
            }
            case 0: {
                PrintAndLogEx(INPLACE, "Chunk [%d/%d]", key_offset, keycount);
                break;
            }
            case 99: {
            }
            default: {
                break;
            }
        }

        // both keys found.
        if (found_key) {
            break;
        }

    } // end chunks of keys

out:
    t1 = msclock() - t1;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "time in iclass chk " _YELLOW_("%.0f") " seconds", (float)t1 / 1000.0);
    DropField();

    if (found_key) {
        uint8_t *key = keyBlock + (key_offset + found_offset) * 8;
        add_key(key);
    }

    free(pre);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// this method tries to identify in which configuration mode a iCLASS / iCLASS SE reader is in.
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

    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, " Epurse: %s", sprint_hex(EPURSE, sizeof(EPURSE)));
    PrintAndLogEx(SUCCESS, "   MACS: %s", sprint_hex(MACS, sizeof(MACS)));
    PrintAndLogEx(SUCCESS, "   CCNR: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));
    PrintAndLogEx(SUCCESS, "TAG MAC: %s", sprint_hex(MAC_TAG, sizeof(MAC_TAG)));

    uint8_t *keyBlock = NULL;
    uint32_t keycount = 0;

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

    PrintAndLogEx(SUCCESS, "Generating diversified keys...");
    GenerateMacKeyFrom(CSN, CCNR, use_raw, use_elite, keyBlock, keycount, prekey);

    if (use_elite)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_("elite algo"));
    if (use_raw)
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_("raw mode"));

    PrintAndLogEx(SUCCESS, "Sorting...");

    // sort mac list.
    qsort(prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") " key...", "DEBIT");
    iclass_prekey_t *item;
    iclass_prekey_t lookup;
    memcpy(lookup.mac, MAC_TAG, 4);

    // binsearch
    item = (iclass_prekey_t *) bsearch(&lookup, prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    if (item != NULL) {
        PrintAndLogEx(SUCCESS, "Found valid key " _GREEN_("%s"), sprint_hex(item->key, 8));
        add_key(item->key);
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "time in iclass lookup " _YELLOW_("%.0f") " seconds", (float)t1 / 1000.0);

    free(prekey);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// precalc diversified keys and their MAC
void GenerateMacFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_premac_t *list) {
    uint8_t key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//iceman: threading
    for (uint32_t i = 0; i < keycnt; i++) {

        memcpy(key, keys + 8 * i, 8);

        if (use_raw)
            memcpy(div_key, key, 8);
        else
            HFiClassCalcDivKey(CSN, key, div_key, use_elite);

        doMAC(CCNR, div_key, list[i].mac);
    }
}

void GenerateMacKeyFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_prekey_t *list) {

    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//iceman: threading
    for (uint32_t i = 0; i < keycnt; i++) {

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
void PrintPreCalcMac(uint8_t *keys, uint32_t keycnt, iclass_premac_t *pre_list) {

    iclass_prekey_t *b = calloc(keycnt, sizeof(iclass_prekey_t));
    if (!b)
        return;

    for (uint32_t i = 0; i < keycnt; i++) {
        memcpy(b[i].key, keys + 8 * i, 8);
        memcpy(b[i].mac, pre_list[i].mac, 4);
    }
    PrintPreCalc(b, keycnt);
    free(b);
}

void PrintPreCalc(iclass_prekey_t *list, uint32_t itemcnt) {
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
        PrintAndLogEx(WARNING, "wrong key size\n");
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
    if (strlen(Cmd) == 0 || cmdp == 'h')
        return usage_hf_iclass_permutekey();

    isReverse = (cmdp == 'r');

    param_gethex_ex(Cmd, 1, data, &len);
    if (len % 2)
        return usage_hf_iclass_permutekey();

    len >>= 1;

    memcpy(key, data, 8);

    if (isReverse) {
        generate_rev(data, len);
        uint8_t key_std_format[8] = {0};
        permutekey_rev(key, key_std_format);
        PrintAndLogEx(SUCCESS, "Standard NIST format key " _YELLOW_("%s") " \n", sprint_hex(key_std_format, 8));
    } else {
        generate(data, len);
        uint8_t key_iclass_format[8] = {0};
        permutekey(key, key_iclass_format);
        PrintAndLogEx(SUCCESS, "HID permuted iCLASS format: %s \n", sprint_hex(key_iclass_format, 8));
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("operations") " ---------------------"},
    {"help",        CmdHelp,                    AlwaysAvailable, "This help"},
//    {"clone",       CmdHFiClassClone,           IfPm3Iclass,     "[options..] Create a HID credential to Picopass / iCLASS tag"},
    {"dump",        CmdHFiClassDump,            IfPm3Iclass,     "[options..] Dump Picopass / iCLASS tag to file"},
    {"info",        CmdHFiClassInfo,            AlwaysAvailable, "            Tag information"},
    {"list",        CmdHFiClassList,            AlwaysAvailable, "            List iclass history"},
    {"rdbl",        CmdHFiClass_ReadBlock,      IfPm3Iclass,     "[options..] Read Picopass / iCLASS block"},
    {"reader",      CmdHFiClassReader,          IfPm3Iclass,     "            Act like an Picopass / iCLASS reader"},
    {"restore",     CmdHFiClassRestore,        IfPm3Iclass,     "[options..] Restore a dump file onto a Picopass / iCLASS tag"},
    {"sniff",       CmdHFiClassSniff,           IfPm3Iclass,     "            Eavesdrop Picopass / iCLASS communication"},
    {"wrbl",        CmdHFiClass_WriteBlock,     IfPm3Iclass,     "[options..] Write Picopass / iCLASS block"},

    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("recovery") " ---------------------"},
    {"chk",         CmdHFiClassCheckKeys,       AlwaysAvailable, "[options..] Check keys"},
    {"loclass",     CmdHFiClass_loclass,        AlwaysAvailable, "[options..] Use loclass to perform bruteforce reader attack"},
    {"lookup",      CmdHFiClassLookUp,          AlwaysAvailable, "[options..] Uses authentication trace to check for key in dictionary file"},
    {"replay",      CmdHFiClassReader_Replay,   IfPm3Iclass,     "<mac>       Read Picopass / iCLASS tag via replay attack"},

    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("simulation") " ---------------------"},
    {"sim",         CmdHFiClassSim,             IfPm3Iclass,     "[options..] Simulate iCLASS tag"},
    {"eload",       CmdHFiClassELoad,           IfPm3Iclass,     "[f <fn>   ] Load Picopass / iCLASS dump file into emulator memory"},
    {"esave",       CmdHFiClassESave,           IfPm3Iclass,     "[f <fn>   ] Save emulator memory to file"},
    {"eview",       CmdHFiClassEView,           IfPm3Iclass,     "[options..] View emulator memory"},

    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("utils") " ---------------------"},
    {"calcnewkey",  CmdHFiClassCalcNewKey,      AlwaysAvailable, "[options..] Calc diversified keys (blocks 3 & 4) to write new keys"},
    {"encrypt",     CmdHFiClassEncryptBlk,      AlwaysAvailable, "[options..] Encrypt given block data"},
    {"decrypt",     CmdHFiClassDecrypt,         AlwaysAvailable, "[options..] Decrypt given block data or tag dump file" },
    {"managekeys",  CmdHFiClassManageKeys,      AlwaysAvailable, "[options..] Manage keys to use with iclass commands"},
    {"permutekey",  CmdHFiClassPermuteKey,      IfPm3Iclass,     "            Permute function from 'heart of darkness' paper"},
    {"view",        CmdHFiClassView,            AlwaysAvailable, "[options..] Display content from tag dump file"},

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

//static void test_credential_type(void) {
// need AA1 key
// Block 5 -> tells if its a legacy or SIO,  also tells which key to use.

// tech   | blocks used           | desc                              | num of payloads
// -------+-----------------------+-----------------------------------+------
// legacy | 6,7,8,9               | AA!, Access control payload       | 1
// SE     | 6,7,8,9,10,11,12      | AA1, Secure identity object (SIO) | 1
// SR     | 6,7,8,9,              | AA1, Access control payload       | 2
//        | 10,11,12,13,14,15,16  | AA1, Secure identity object (SIO) |
// SEOS   |                       |                                   |
//}

int info_iclass(void) {

    uint32_t flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE);

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ICLASS_READER, flags, 0, 0, NULL, 0);
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

        uint8_t readStatus = resp.oldarg[0] & 0xff;

        // no tag found or button pressed
        if (readStatus == 0 || readStatus == 0xFF) {
            DropField();
            return PM3_EOPABORTED;
        }

        picopass_hdr *hdr = (picopass_hdr *)resp.data.asBytes;
        picopass_ns_hdr *ns_hdr = (picopass_ns_hdr *)resp.data.asBytes;

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " --------------------------");
        PrintAndLogEx(INFO, "-------------------------------------------------------------");

        if (readStatus & FLAG_ICLASS_CSN) {
            PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s") "  (uid)", sprint_hex(hdr->csn, sizeof(hdr->csn)));
        }

        if (readStatus & FLAG_ICLASS_CONF) {
            PrintAndLogEx(SUCCESS, " Config: %s  (Card configuration)", sprint_hex((uint8_t *)&hdr->conf, sizeof(hdr->conf)));
        }

        // page mapping.  If fuse0|1 == 0x01, card is in non-secure mode, with CSN, CONF, AIA as top 3 blocks.
        // page9 in http://www.proxmark.org/files/Documents/13.56%20MHz%20-%20iClass/DS%20Picopass%202KS%20V1-0.pdf
        uint8_t pagemap = get_pagemap(hdr);
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            PrintAndLogEx(SUCCESS, "    AIA: %s  (Application Issuer area)", sprint_hex(ns_hdr->app_issuer_area, sizeof(ns_hdr->app_issuer_area)));
        } else {

            if (readStatus & FLAG_ICLASS_CC) {
                PrintAndLogEx(SUCCESS, "E-purse: %s  (Card challenge, CC)", sprint_hex(hdr->epurse, sizeof(hdr->epurse)));
            }

            PrintAndLogEx(SUCCESS, "     Kd: %s  (Debit key, hidden)", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
            PrintAndLogEx(SUCCESS, "     Kc: %s  (Credit key, hidden)", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));

            if (readStatus & FLAG_ICLASS_AIA) {
                PrintAndLogEx(SUCCESS, "    AIA: %s  (Application Issuer area)", sprint_hex(hdr->app_issuer_area, sizeof(hdr->app_issuer_area)));
            }
        }

        if (readStatus & FLAG_ICLASS_CONF) {
            print_picopass_info(hdr);
        }

        PrintAndLogEx(INFO, "------ " _CYAN_("Fingerprint") " ------");

        uint8_t aia[8];
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE)
            memcpy(aia, ns_hdr->app_issuer_area, sizeof(aia));
        else
            memcpy(aia, hdr->app_issuer_area, sizeof(aia));

        // if CSN ends with FF12E0, it's inside HID CSN range.
        bool isHidRange = (memcmp(hdr->csn + 5, "\xFF\x12\xE0", 3) == 0);

        bool legacy = (memcmp(aia, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0);
        bool se_enabled = (memcmp(aia, "\xff\xff\xff\x00\x06\xff\xff\xff", 8) == 0);

        if (isHidRange) {
            PrintAndLogEx(SUCCESS, "CSN is in HID range");
            if (legacy)
                PrintAndLogEx(SUCCESS, "Credential : " _GREEN_("iCLASS legacy"));
            if (se_enabled)
                PrintAndLogEx(SUCCESS, "Credential : " _GREEN_("iCLASS SE"));

        } else {
            PrintAndLogEx(SUCCESS, _YELLOW_("PicoPass")" (CSN is not in HID range)");
        }

        uint8_t cardtype = get_mem_config(hdr);
        PrintAndLogEx(SUCCESS, " Card type : " _GREEN_("%s"), card_types[cardtype]);
    }

    DropField();
    return PM3_SUCCESS;
}

