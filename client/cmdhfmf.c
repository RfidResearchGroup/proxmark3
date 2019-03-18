//-----------------------------------------------------------------------------
// Copyright (C) 2011,2012 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#include "cmdhfmf.h"
#include "mifare/mifare4.h"
#include "mifare/mad.h"
#include "mifare/ndef.h"


#define MFBLOCK_SIZE 16

#define MIFARE_4K_MAXBLOCK 256
#define MIFARE_2K_MAXBLOCK 128
#define MIFARE_1K_MAXBLOCK 64
#define MIFARE_MINI_MAXBLOCK 20

#define MIFARE_MINI_MAXSECTOR 5
#define MIFARE_1K_MAXSECTOR 16
#define MIFARE_2K_MAXSECTOR 32
#define MIFARE_4K_MAXSECTOR 40

static int CmdHelp(const char *Cmd);

int usage_hf14_ice(void) {
    PrintAndLogEx(NORMAL, "Usage:   hf mf ice [l] <limit> [f] <name>");
    PrintAndLogEx(NORMAL, "  h            this help");
    PrintAndLogEx(NORMAL, "  l <limit>    nonces to be collected");
    PrintAndLogEx(NORMAL, "  f <name>     save nonces to <name> instead of hf-mf-<UID>-nonces.bin");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mf ice");
    PrintAndLogEx(NORMAL, "         hf mf ice f nonces.bin");
    return 0;
}

int usage_hf14_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:   hf mf dump [card memory] k <name> f <name>");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "  k <name>     : key filename, if no <name> given, UID will be used as filename");
    PrintAndLogEx(NORMAL, "  f <name>     : data filename, if no <name> given, UID will be used as filename");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mf dump");
    PrintAndLogEx(NORMAL, "         hf mf dump 4");
    return 0;
}

int usage_hf14_mifare(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf darkside [h] <block number> <A|B>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               this help");
    PrintAndLogEx(NORMAL, "      <block number>  (Optional) target other block");
    PrintAndLogEx(NORMAL, "      <A|B>           (optional) target key type");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf mf darkside");
    PrintAndLogEx(NORMAL, "           hf mf darkside 16");
    PrintAndLogEx(NORMAL, "           hf mf darkside 16 B");
    return 0;
}
int usage_hf14_mf1ksim(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf sim [h] u <uid> n <numreads> [i] [x] [e] [v]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h    this help");
    PrintAndLogEx(NORMAL, "      u    (Optional) UID 4,7 or 10bytes. If not specified, the UID 4b from emulator memory will be used");
    PrintAndLogEx(NORMAL, "      n    (Optional) Automatically exit simulation after <numreads> blocks have been read by reader. 0 = infinite");
    PrintAndLogEx(NORMAL, "      i    (Optional) Interactive, means that console will not be returned until simulation finishes or is aborted");
    PrintAndLogEx(NORMAL, "      x    (Optional) Crack, performs the 'reader attack', nr/ar attack against a reader");
    PrintAndLogEx(NORMAL, "      e    (Optional) Fill simulator keys from found keys");
    PrintAndLogEx(NORMAL, "      v    (Optional) Verbose");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf mf sim u 0a0a0a0a");
    PrintAndLogEx(NORMAL, "           hf mf sim u 11223344556677");
    PrintAndLogEx(NORMAL, "           hf mf sim u 112233445566778899AA");
    PrintAndLogEx(NORMAL, "           hf mf sim u 11223344 i x");
    return 0;
}
int usage_hf14_dbg(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf dbg [h] <debug level>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h    this help");
    PrintAndLogEx(NORMAL, "       <debug level>  (Optional) see list for valid levels");
    PrintAndLogEx(NORMAL, "           0 - no debug messages");
    PrintAndLogEx(NORMAL, "           1 - error messages");
    PrintAndLogEx(NORMAL, "           2 - plus information messages");
    PrintAndLogEx(NORMAL, "           3 - plus debug messages");
    PrintAndLogEx(NORMAL, "           4 - print even debug messages in timing critical functions");
    PrintAndLogEx(NORMAL, "               Note: this option therefore may cause malfunction itself");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf mf dbg 3");
    return 0;
}
int usage_hf14_sniff(void) {
    PrintAndLogEx(NORMAL, "It continuously gets data from the field and saves it to: log, emulator, emulator file.");
    PrintAndLogEx(NORMAL, "Usage:  hf mf sniff [h] [l] [d] [f]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h    this help");
    PrintAndLogEx(NORMAL, "      l    save encrypted sequence to logfile `uid.log`");
    PrintAndLogEx(NORMAL, "      d    decrypt sequence and put it to log file `uid.log`");
//  PrintAndLogEx(NORMAL, " n/a  e     decrypt sequence, collect read and write commands and save the result of the sequence to emulator memory");
    PrintAndLogEx(NORMAL, "      f    decrypt sequence, collect read and write commands and save the result of the sequence to emulator dump file `uid.eml`");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "           hf mf sniff l d f");
    return 0;
}
int usage_hf14_nested(void) {
    PrintAndLogEx(NORMAL, "Usage:");
    PrintAndLogEx(NORMAL, " all sectors:  hf mf nested  <card memory> <block number> <key A/B> <key (12 hex symbols)> [t,d]");
    PrintAndLogEx(NORMAL, " one sector:   hf mf nested  o <block number> <key A/B> <key (12 hex symbols)>");
    PrintAndLogEx(NORMAL, "               <target block number> <target key A/B> [t]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h    this help");
    PrintAndLogEx(NORMAL, "      card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K, <other> - 1K");
    PrintAndLogEx(NORMAL, "      t    transfer keys into emulator memory");
    PrintAndLogEx(NORMAL, "      d    write keys to binary file `hf-mf-<UID>-key.bin`");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf nested 1 0 A FFFFFFFFFFFF ");
    PrintAndLogEx(NORMAL, "      hf mf nested 1 0 A FFFFFFFFFFFF t ");
    PrintAndLogEx(NORMAL, "      hf mf nested 1 0 A FFFFFFFFFFFF d ");
    PrintAndLogEx(NORMAL, "      hf mf nested o 0 A FFFFFFFFFFFF 4 A");
    return 0;
}
int usage_hf14_hardnested(void) {
    PrintAndLogEx(NORMAL, "Usage:");
    PrintAndLogEx(NORMAL, "      hf mf hardnested <block number> <key A|B> <key (12 hex symbols)>");
    PrintAndLogEx(NORMAL, "                       <target block number> <target key A|B> [known target key (12 hex symbols)] [w] [s]");
    PrintAndLogEx(NORMAL, "  or  hf mf hardnested r [known target key]");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h         this help");
    PrintAndLogEx(NORMAL, "      w         acquire nonces and UID, and write them to binary file with default name hf-mf-<UID>-nonces.bin");
    PrintAndLogEx(NORMAL, "      s         slower acquisition (required by some non standard cards)");
    PrintAndLogEx(NORMAL, "      r         read hf-mf-<UID>-nonces.bin if tag present, otherwise read nonces.bin, then start attack");
    PrintAndLogEx(NORMAL, "      u <UID>   read/write hf-mf-<UID>-nonces.bin instead of default name");
    PrintAndLogEx(NORMAL, "      f <name>  read/write <name> instead of default name");
    PrintAndLogEx(NORMAL, "      t         tests?");
    PrintAndLogEx(NORMAL, "      i <X>     set type of SIMD instructions. Without this flag programs autodetect it.");
    PrintAndLogEx(NORMAL, "        i 5   = AVX512");
    PrintAndLogEx(NORMAL, "        i 2   = AVX2");
    PrintAndLogEx(NORMAL, "        i a   = AVX");
    PrintAndLogEx(NORMAL, "        i s   = SSE2");
    PrintAndLogEx(NORMAL, "        i m   = MMX");
    PrintAndLogEx(NORMAL, "        i n   = none (use CPU regular instruction set)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf hardnested 0 A FFFFFFFFFFFF 4 A");
    PrintAndLogEx(NORMAL, "      hf mf hardnested 0 A FFFFFFFFFFFF 4 A w");
    PrintAndLogEx(NORMAL, "      hf mf hardnested 0 A FFFFFFFFFFFF 4 A f nonces.bin w s");
    PrintAndLogEx(NORMAL, "      hf mf hardnested r");
    PrintAndLogEx(NORMAL, "      hf mf hardnested r a0a1a2a3a4a5");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Add the known target key to check if it is present in the remaining key space:");
    PrintAndLogEx(NORMAL, "      hf mf hardnested 0 A A0A1A2A3A4A5 4 A FFFFFFFFFFFF");
    return 0;
}
int usage_hf14_chk(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf chk [h] <block number>|<*card memory> <key type (A/B/?)> [t|d] [<key (12 hex symbols)>] [<dic (*.dic)>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h    this help");
    PrintAndLogEx(NORMAL, "      *    all sectors based on card memory, other values then below defaults to 1k");
    PrintAndLogEx(NORMAL, "                0 - MINI(320 bytes)");
    PrintAndLogEx(NORMAL, "                1 - 1K");
    PrintAndLogEx(NORMAL, "                2 - 2K");
    PrintAndLogEx(NORMAL, "                4 - 4K");
    PrintAndLogEx(NORMAL, "      d    write keys to binary file");
    PrintAndLogEx(NORMAL, "      t    write keys to emulator memory\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf chk 0 A 1234567890ab keys.dic     -- target block 0, Key A");
    PrintAndLogEx(NORMAL, "      hf mf chk *1 ? t                        -- target all blocks, all keys, 1K, write to emul");
    PrintAndLogEx(NORMAL, "      hf mf chk *1 ? d                        -- target all blocks, all keys, 1K, write to file");
    return 0;
}
int usage_hf14_chk_fast(void) {
    PrintAndLogEx(NORMAL, "This is a improved checkkeys method speedwise. It checks Mifare Classic tags sector keys against a dictionary file with keys");
    PrintAndLogEx(NORMAL, "Usage:  hf mf fchk [h] <card memory> [t|d|f] [<key (12 hex symbols)>] [<dic (*.dic)>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h    this help");
    PrintAndLogEx(NORMAL, "      <cardmem> all sectors based on card memory, other values than below defaults to 1k");
    PrintAndLogEx(NORMAL, "                 0 - MINI(320 bytes)");
    PrintAndLogEx(NORMAL, "                 1 - 1K   <default>");
    PrintAndLogEx(NORMAL, "                 2 - 2K");
    PrintAndLogEx(NORMAL, "                 4 - 4K");
    PrintAndLogEx(NORMAL, "      d    write keys to binary file");
    PrintAndLogEx(NORMAL, "      t    write keys to emulator memory");
    PrintAndLogEx(NORMAL, "      m    use dictionary from flashmemory\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf fchk 1 1234567890ab keys.dic    -- target 1K using key 1234567890ab, using dictionary file");
    PrintAndLogEx(NORMAL, "      hf mf fchk 1 t                        -- target 1K, write to emulator memory");
    PrintAndLogEx(NORMAL, "      hf mf fchk 1 d                        -- target 1K, write to file");
#ifdef WITH_FLASH
    PrintAndLogEx(NORMAL, "      hf mf fchk 1 m                        -- target 1K, use dictionary from flashmemory");
#endif
    return 0;
}
int usage_hf14_keybrute(void) {
    PrintAndLogEx(NORMAL, "J_Run's 2nd phase of multiple sector nested authentication key recovery");
    PrintAndLogEx(NORMAL, "You have a known 4 last bytes of a key recovered with mf_nonce_brute tool.");
    PrintAndLogEx(NORMAL, "First 2 bytes of key will be bruteforced");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, " ---[ This attack is obsolete,  try hardnested instead ]---");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf keybrute [h] <block number> <A|B> <key>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               this help");
    PrintAndLogEx(NORMAL, "      <block number>  target block number");
    PrintAndLogEx(NORMAL, "      <A|B>           target key type");
    PrintAndLogEx(NORMAL, "      <key>           candidate key from mf_nonce_brute tool");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf mf keybrute 1 A 000011223344");
    return 0;
}
int usage_hf14_restore(void) {
    PrintAndLogEx(NORMAL, "Usage:   hf mf restore [card memory] u <UID> k <name> f <name>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "  u <UID>      : uid, try to restore from hf-mf-<UID>-key.bin and hf-mf-<UID>-data.bin");
    PrintAndLogEx(NORMAL, "  k <name>     : key filename, specific the full filename of key file");
    PrintAndLogEx(NORMAL, "  f <name>     : data filename, specific the full filename of data file");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mf restore                            -- read the UID from tag first, then restore from hf-mf-<UID>-key.bin and and hf-mf-<UID>-data.bin");
    PrintAndLogEx(NORMAL, "         hf mf restore 1 u 12345678               -- restore from hf-mf-12345678-key.bin and hf-mf-12345678-data.bin");
    PrintAndLogEx(NORMAL, "         hf mf restore 1 u 12345678 k dumpkey.bin -- restore from dumpkey.bin and hf-mf-12345678-data.bin");
    PrintAndLogEx(NORMAL, "         hf mf restore 4                          -- read the UID from tag with 4K memory first, then restore from hf-mf-<UID>-key.bin and and hf-mf-<UID>-data.bin");
    return 0;
}
int usage_hf14_decryptbytes(void) {
    PrintAndLogEx(NORMAL, "Decrypt Crypto-1 encrypted bytes given some known state of crypto. See tracelog to gather needed values\n");
    PrintAndLogEx(NORMAL, "Usage:   hf mf decrypt [h] <nt> <ar_enc> <at_enc> <data>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h            this help");
    PrintAndLogEx(NORMAL, "      <nt>         reader nonce");
    PrintAndLogEx(NORMAL, "      <ar_enc>     encrypted reader response");
    PrintAndLogEx(NORMAL, "      <at_enc>     encrypted tag response");
    PrintAndLogEx(NORMAL, "      <data>       encrypted data, taken directly after at_enc and forward");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mf decrypt b830049b 9248314a 9280e203 41e586f9\n");
    PrintAndLogEx(NORMAL, "  this sample decrypts 41e586f9 -> 3003999a  Annotated: 30 03 [99 9a]  auth block 3 [crc]");
    return 0;
}

int usage_hf14_eget(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf eget <block number>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf eget 0 ");
    return 0;
}
int usage_hf14_eclr(void) {
    PrintAndLogEx(NORMAL, "It set card emulator memory to empty data blocks and key A/B FFFFFFFFFFFF \n");
    PrintAndLogEx(NORMAL, "Usage:  hf mf eclr");
    return 0;
}
int usage_hf14_eset(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mf eset <block number> <block data (32 hex symbols)>");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf eset 1 000102030405060708090a0b0c0d0e0f ");
    return 0;
}
int usage_hf14_eload(void) {
    PrintAndLogEx(NORMAL, "It loads emul dump from the file `filename.eml`");
    PrintAndLogEx(NORMAL, "Usage:  hf mf eload [card memory] <file name w/o `.eml`> [numblocks]");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K, u = UL");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf eload filename");
    PrintAndLogEx(NORMAL, "        hf mf eload 4 filename");
    return 0;
}
int usage_hf14_esave(void) {
    PrintAndLogEx(NORMAL, "It saves emul dump into the file `filename.eml` or `cardID.eml`");
    PrintAndLogEx(NORMAL, " Usage:  hf mf esave [card memory] [file name w/o `.eml`]");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf esave ");
    PrintAndLogEx(NORMAL, "        hf mf esave 4");
    PrintAndLogEx(NORMAL, "        hf mf esave 4 filename");
    return 0;
}
int usage_hf14_ecfill(void) {
    PrintAndLogEx(NORMAL, "Read card and transfer its data to emulator memory.");
    PrintAndLogEx(NORMAL, "Keys must be laid in the emulator memory. \n");
    PrintAndLogEx(NORMAL, "Usage:  hf mf ecfill <key A/B> [card memory]");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf ecfill A");
    PrintAndLogEx(NORMAL, "        hf mf ecfill A 4");
    return 0;
}
int usage_hf14_ekeyprn(void) {
    PrintAndLogEx(NORMAL, "It prints the keys loaded in the emulator memory");
    PrintAndLogEx(NORMAL, "Usage:  hf mf ekeyprn [card memory]");
    PrintAndLogEx(NORMAL, "  [card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mf ekeyprn 1");
    return 0;
}

int usage_hf14_csetuid(void) {
    PrintAndLogEx(NORMAL, "Set UID, ATQA, and SAK for magic Chinese card. Only works with magic cards");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf csetuid [h] <UID 8 hex symbols> [ATQA 4 hex symbols] [SAK 2 hex symbols] [w]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h        this help");
    PrintAndLogEx(NORMAL, "       w        wipe card before writing");
    PrintAndLogEx(NORMAL, "       <uid>    UID 8 hex symbols");
    PrintAndLogEx(NORMAL, "       <atqa>   ATQA 4 hex symbols");
    PrintAndLogEx(NORMAL, "       <sak>    SAK 2 hex symbols");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf csetuid 01020304");
    PrintAndLogEx(NORMAL, "      hf mf csetuid 01020304 0004 08 w");
    return 0;
}
int usage_hf14_csetblk(void) {
    PrintAndLogEx(NORMAL, "Set block data for magic Chinese card. Only works with magic cards");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf csetblk [h] <block number> <block data (32 hex symbols)> [w]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         this help");
    PrintAndLogEx(NORMAL, "       w         wipe card before writing");
    PrintAndLogEx(NORMAL, "       <block>   block number");
    PrintAndLogEx(NORMAL, "       <data>    block data to write (32 hex symbols)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mf csetblk 1 01020304050607080910111213141516");
    PrintAndLogEx(NORMAL, "       hf mf csetblk 1 01020304050607080910111213141516 w");
    return 0;
}
int usage_hf14_cload(void) {
    PrintAndLogEx(NORMAL, "It loads magic Chinese card from the file `filename.eml`");
    PrintAndLogEx(NORMAL, "or from emulator memory");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf cload [h] [e] <file name w/o `.eml`>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h            this help");
    PrintAndLogEx(NORMAL, "       e            load card with data from emulator memory");
    PrintAndLogEx(NORMAL, "       j <filename> load card with data from json file");
    PrintAndLogEx(NORMAL, "       b <filename> load card with data from binary file");
    PrintAndLogEx(NORMAL, "       <filename>   load card with data from eml file");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mf cload mydump");
    PrintAndLogEx(NORMAL, "       hf mf cload e");
    return 0;
}
int usage_hf14_cgetblk(void) {
    PrintAndLogEx(NORMAL, "Get block data from magic Chinese card. Only works with magic cards\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf cgetblk [h] <block number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h         this help");
    PrintAndLogEx(NORMAL, "      <block>   block number");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf cgetblk 1");
    return 0;
}
int usage_hf14_cgetsc(void) {
    PrintAndLogEx(NORMAL, "Get sector data from magic Chinese card. Only works with magic cards\n");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf cgetsc [h] <sector number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          this help");
    PrintAndLogEx(NORMAL, "      <sector>   sector number");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      hf mf cgetsc 0");
    return 0;
}
int usage_hf14_csave(void) {
    PrintAndLogEx(NORMAL, "It saves `magic Chinese` card dump into the file `filename.eml` or `cardID.eml`");
    PrintAndLogEx(NORMAL, "or into emulator memory");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf csave [h] [e] [u] [card memory] i <file name w/o `.eml`>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             this help");
    PrintAndLogEx(NORMAL, "       e             save data to emulator memory");
    PrintAndLogEx(NORMAL, "       u             save data to file, use carduid as filename");
    PrintAndLogEx(NORMAL, "       card memory   0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K");
    PrintAndLogEx(NORMAL, "       o <filename>  save data to file");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mf csave u 1");
    PrintAndLogEx(NORMAL, "       hf mf csave e 1");
    PrintAndLogEx(NORMAL, "       hf mf csave 4 o filename");
    return 0;
}
int usage_hf14_nack(void) {
    PrintAndLogEx(NORMAL, "Test a mifare classic based card for the NACK bug.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  hf mf nack [h] [v]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             this help");
    PrintAndLogEx(NORMAL, "       v             verbose");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mf nack");
    return 0;
}

int GetHFMF14AUID(uint8_t *uid, int *uidlen) {
    UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));
    memcpy(uid, card.uid, card.uidlen * sizeof(uint8_t));
    *uidlen = card.uidlen;
    return 1;
}

char *GenerateFilename(const char *prefix, const char *suffix) {
    uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int uidlen = 0;
    char *fptr = calloc(sizeof(char) * (strlen(prefix) + strlen(suffix)) + sizeof(uid) * 2 + 1,  sizeof(uint8_t));

    GetHFMF14AUID(uid, &uidlen);
    if (!uidlen) {
        PrintAndLogEx(WARNING, "No tag found.");
        free(fptr);
        return NULL;
    }

    strcpy(fptr, prefix);
    FillFileNameByUID(fptr, uid, suffix, uidlen);
    return fptr;
}

int CmdHF14AMfDarkside(const char *Cmd) {
    uint8_t blockno = 0, key_type = MIFARE_AUTH_KEYA;
    uint64_t key = 0;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf14_mifare();

    blockno = param_get8(Cmd, 0);

    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 'b')
        key_type = MIFARE_AUTH_KEYB;

    int isOK = mfDarkside(blockno, key_type, &key);
    PrintAndLogEx(NORMAL, "");
    switch (isOK) {
        case -1 :
            PrintAndLogEx(WARNING, "button pressed. Aborted.");
            return 1;
        case -2 :
            PrintAndLogEx(FAILED, "card is not vulnerable to Darkside attack (doesn't send NACK on authentication requests).");
            return 1;
        case -3 :
            PrintAndLogEx(FAILED, "card is not vulnerable to Darkside attack (its random number generator is not predictable).");
            return 1;
        case -4 :
            PrintAndLogEx(FAILED, "card is not vulnerable to Darkside attack (its random number generator seems to be based on the wellknown");
            PrintAndLogEx(FAILED, "generating polynomial with 16 effective bits only, but shows unexpected behaviour.");
            return 1;
        case -5 :
            PrintAndLogEx(WARNING, "aborted via keyboard.");
            return 1;
        default :
            PrintAndLogEx(SUCCESS, "found valid key: %012" PRIx64 "\n", key);
            break;
    }
    PrintAndLogEx(NORMAL, "");
    return 0;
}

int CmdHF14AMfWrBl(const char *Cmd) {
    uint8_t blockNo = 0;
    uint8_t keyType = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    char cmdp = 0x00;

    if (strlen(Cmd) < 3) {
        PrintAndLogEx(NORMAL, "Usage:  hf mf wrbl    <block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, "        hf mf wrbl 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F");
        return 0;
    }

    blockNo = param_get8(Cmd, 0);
    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 0x00) {
        PrintAndLogEx(NORMAL, "Key type must be A or B");
        return 1;
    }

    if (cmdp != 'a')
        keyType = 1;

    if (param_gethex(Cmd, 2, key, 12)) {
        PrintAndLogEx(NORMAL, "Key must include 12 HEX symbols");
        return 1;
    }

    if (param_gethex(Cmd, 3, bldata, 32)) {
        PrintAndLogEx(NORMAL, "Block data must include 32 HEX symbols");
        return 1;
    }

    PrintAndLogEx(NORMAL, "--block no:%d, key type:%c, key:%s", blockNo, keyType ? 'B' : 'A', sprint_hex(key, 6));
    PrintAndLogEx(NORMAL, "--data: %s", sprint_hex(bldata, 16));

    UsbCommand c = {CMD_MIFARE_WRITEBL, {blockNo, keyType, 0}};
    memcpy(c.d.asBytes, key, 6);
    memcpy(c.d.asBytes + 10, bldata, 16);
    clearCommandBuffer();
    SendCommand(&c);

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
    } else {
        PrintAndLogEx(NORMAL, "Command execute timeout");
    }

    return 0;
}

int CmdHF14AMfRdBl(const char *Cmd) {
    uint8_t blockNo = 0;
    uint8_t keyType = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    char cmdp = 0x00;

    if (strlen(Cmd) < 3) {
        PrintAndLogEx(NORMAL, "Usage:  hf mf rdbl    <block number> <key A/B> <key (12 hex symbols)>");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, "        hf mf rdbl 0 A FFFFFFFFFFFF ");
        return 0;
    }

    blockNo = param_get8(Cmd, 0);
    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 0x00) {
        PrintAndLogEx(NORMAL, "Key type must be A or B");
        return 1;
    }

    if (cmdp != 'a')
        keyType = 1;

    if (param_gethex(Cmd, 2, key, 12)) {
        PrintAndLogEx(NORMAL, "Key must include 12 HEX symbols");
        return 1;
    }
    PrintAndLogEx(NORMAL, "--block no:%d, key type:%c, key:%s ", blockNo, keyType ? 'B' : 'A', sprint_hex(key, 6));

    UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
    memcpy(c.d.asBytes, key, 6);
    clearCommandBuffer();
    SendCommand(&c);

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        uint8_t *data = resp.d.asBytes;

        if (isOK) {
            PrintAndLogEx(NORMAL, "isOk:%02x data:%s", isOK, sprint_hex(data, 16));
        } else {
            PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
            return 1;
        }

        if (mfIsSectorTrailer(blockNo) && (data[6] || data[7] || data[8])) {
            PrintAndLogEx(NORMAL, "Trailer decoded:");
            int bln = mfFirstBlockOfSector(mfSectorNum(blockNo));
            int blinc = (mfNumBlocksPerSector(mfSectorNum(blockNo)) > 4) ? 5 : 1;
            for (int i = 0; i < 4; i++) {
                PrintAndLogEx(NORMAL, "Access block %d%s: %s", bln, ((blinc > 1) && (i < 3) ? "+" : ""), mfGetAccessConditionsDesc(i, &data[6]));
                bln += blinc;
            }
            PrintAndLogEx(NORMAL, "UserData: %s", sprint_hex_inrow(&data[9], 1));
        }
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 2;
    }

    return 0;
}

int CmdHF14AMfRdSc(const char *Cmd) {
    int i;
    uint8_t sectorNo = 0;
    uint8_t keyType = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t isOK  = 0;
    uint8_t *data  = NULL;
    char cmdp = 0x00;

    if (strlen(Cmd) < 3) {
        PrintAndLogEx(NORMAL, "Usage:  hf mf rdsc    <sector number> <key A/B> <key (12 hex symbols)>");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, "        hf mf rdsc 0 A FFFFFFFFFFFF ");
        return 0;
    }

    sectorNo = param_get8(Cmd, 0);
    if (sectorNo > MIFARE_4K_MAXSECTOR) {
        PrintAndLogEx(NORMAL, "Sector number must be less than 40");
        return 1;
    }

    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp != 'a' && cmdp != 'b') {
        PrintAndLogEx(NORMAL, "Key type must be A or B");
        return 1;
    }

    if (cmdp != 'a')
        keyType = 1;

    if (param_gethex(Cmd, 2, key, 12)) {
        PrintAndLogEx(NORMAL, "Key must include 12 HEX symbols");
        return 1;
    }
    PrintAndLogEx(NORMAL, "--sector no:%d key type:%c key:%s ", sectorNo, keyType ? 'B' : 'A', sprint_hex(key, 6));

    UsbCommand c = {CMD_MIFARE_READSC, {sectorNo, keyType, 0}};
    memcpy(c.d.asBytes, key, 6);
    clearCommandBuffer();
    SendCommand(&c);
    PrintAndLogEx(NORMAL, "");

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        isOK  = resp.arg[0] & 0xff;
        data  = resp.d.asBytes;

        PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
        if (isOK) {
            for (i = 0; i < (sectorNo < 32 ? 3 : 15); i++) {
                PrintAndLogEx(NORMAL, "data   : %s", sprint_hex(data + i * 16, 16));
            }
            PrintAndLogEx(NORMAL, "trailer: %s", sprint_hex(data + (sectorNo < 32 ? 3 : 15) * 16, 16));

            PrintAndLogEx(NORMAL, "Trailer decoded:");
            int bln = mfFirstBlockOfSector(sectorNo);
            int blinc = (mfNumBlocksPerSector(sectorNo) > 4) ? 5 : 1;
            for (i = 0; i < 4; i++) {
                PrintAndLogEx(NORMAL, "Access block %d%s: %s", bln, ((blinc > 1) && (i < 3) ? "+" : ""), mfGetAccessConditionsDesc(i, &(data + (sectorNo < 32 ? 3 : 15) * 16)[6]));
                bln += blinc;
            }
            PrintAndLogEx(NORMAL, "UserData: %s", sprint_hex_inrow(&(data + (sectorNo < 32 ? 3 : 15) * 16)[9], 1));
        }
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }

    return 0;
}

uint16_t NumOfBlocks(char card) {
    switch (card) {
        case '0' :
            return MIFARE_MINI_MAXBLOCK;
        case '1' :
            return MIFARE_1K_MAXBLOCK;
        case '2' :
            return MIFARE_2K_MAXBLOCK;
        case '4' :
            return MIFARE_4K_MAXBLOCK;
        default  :
            return MIFARE_1K_MAXBLOCK;
    }
}
uint8_t NumOfSectors(char card) {
    switch (card) {
        case '0' :
            return MIFARE_MINI_MAXSECTOR;
        case '1' :
            return MIFARE_1K_MAXSECTOR;
        case '2' :
            return MIFARE_2K_MAXSECTOR;
        case '4' :
            return MIFARE_4K_MAXSECTOR;
        default  :
            return MIFARE_1K_MAXSECTOR;
    }
}

uint8_t FirstBlockOfSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return sectorNo * 4;
    } else {
        return 32 * 4 + (sectorNo - 32) * 16;
    }
}

uint8_t NumBlocksPerSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return 4;
    } else {
        return 16;
    }
}

int CmdHF14AMfDump(const char *Cmd) {

    uint8_t sectorNo, blockNo;
    uint8_t keyA[40][6];
    uint8_t keyB[40][6];
    uint8_t rights[40][4];
    uint8_t carddata[256][16];
    uint8_t numSectors = 16;
    uint8_t cmdp = 0;

    char keyFilename[FILE_PATH_SIZE] = {0};
    char dataFilename[FILE_PATH_SIZE];
    char *fptr;

    memset(keyFilename, 0, sizeof(keyFilename));
    memset(dataFilename, 0, sizeof(dataFilename));

    FILE *f;
    UsbCommand resp;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf14_dump();
            case 'k':
                param_getstr(Cmd, cmdp + 1, keyFilename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            case 'f':
                param_getstr(Cmd, cmdp + 1, dataFilename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            default:
                if (cmdp == 0) {
                    numSectors = NumOfSectors(param_getchar(Cmd, cmdp));
                    cmdp++;
                } else {
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                    return usage_hf14_dump();
                }
        }
    }

    if (keyFilename[0] == 0x00) {
        fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL)
            return 1;

        strcpy(keyFilename, fptr);
    }

    if ((f = fopen(keyFilename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), keyFilename);
        return 1;
    }

    // Read keys A from file
    size_t bytes_read;
    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        bytes_read = fread(keyA[sectorNo], 1, 6, f);
        if (bytes_read != 6) {
            PrintAndLogEx(WARNING, "File reading error.");
            fclose(f);
            return 2;
        }
    }

    // Read keys B from file
    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        bytes_read = fread(keyB[sectorNo], 1, 6, f);
        if (bytes_read != 6) {
            PrintAndLogEx(WARNING, "File reading error.");
            fclose(f);
            return 2;
        }
    }

    fclose(f);


    PrintAndLogEx(INFO, "Reading sector access bits...");

    uint8_t tries = 0;
    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        for (tries = 0; tries < MIFARE_SECTOR_RETRY; tries++) {

            UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 0, 0}};
            memcpy(c.d.asBytes, keyA[sectorNo], 6);
            clearCommandBuffer();
            SendCommand(&c);

            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                uint8_t isOK = resp.arg[0] & 0xff;
                uint8_t *data = resp.d.asBytes;
                if (isOK) {
                    rights[sectorNo][0] = ((data[7] & 0x10) >> 2) | ((data[8] & 0x1) << 1) | ((data[8] & 0x10) >> 4); // C1C2C3 for data area 0
                    rights[sectorNo][1] = ((data[7] & 0x20) >> 3) | ((data[8] & 0x2) << 0) | ((data[8] & 0x20) >> 5); // C1C2C3 for data area 1
                    rights[sectorNo][2] = ((data[7] & 0x40) >> 4) | ((data[8] & 0x4) >> 1) | ((data[8] & 0x40) >> 6); // C1C2C3 for data area 2
                    rights[sectorNo][3] = ((data[7] & 0x80) >> 5) | ((data[8] & 0x8) >> 2) | ((data[8] & 0x80) >> 7); // C1C2C3 for sector trailer
                    break;
                } else if (tries == 2) { // on last try set defaults
                    PrintAndLogEx(FAILED, "could not get access rights for sector %2d. Trying with defaults...", sectorNo);
                    rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
                    rights[sectorNo][3] = 0x01;
                }
            } else {
                PrintAndLogEx(FAILED, "command execute timeout when trying to read access rights for sector %2d. Trying with defaults...", sectorNo);
                rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
                rights[sectorNo][3] = 0x01;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "Finished reading sector access bits");
    PrintAndLogEx(INFO, "Dumping all blocks from card...");

    bool isOK = true;
    for (sectorNo = 0; isOK && sectorNo < numSectors; sectorNo++) {
        for (blockNo = 0; isOK && blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
            bool received = false;

            for (tries = 0; tries < MIFARE_SECTOR_RETRY; tries++) {
                if (blockNo == NumBlocksPerSector(sectorNo) - 1) { // sector trailer. At least the Access Conditions can always be read with key A.
                    UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 0, 0}};
                    memcpy(c.d.asBytes, keyA[sectorNo], 6);
                    clearCommandBuffer();
                    SendCommand(&c);
                    received = WaitForResponseTimeout(CMD_ACK, &resp, 1500);
                } else {                                           // data block. Check if it can be read with key A or key B
                    uint8_t data_area = (sectorNo < 32) ? blockNo : blockNo / 5;
                    if ((rights[sectorNo][data_area] == 0x03) || (rights[sectorNo][data_area] == 0x05)) { // only key B would work
                        UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 1, 0}};
                        memcpy(c.d.asBytes, keyB[sectorNo], 6);
                        SendCommand(&c);
                        received = WaitForResponseTimeout(CMD_ACK, &resp, 1500);
                    } else if (rights[sectorNo][data_area] == 0x07) {                                     // no key would work
                        isOK = false;
                        PrintAndLogEx(WARNING, "access rights do not allow reading of sector %2d block %3d", sectorNo, blockNo);
                        tries = MIFARE_SECTOR_RETRY;
                    } else {                                                                              // key A would work
                        UsbCommand c = {CMD_MIFARE_READBL, {FirstBlockOfSector(sectorNo) + blockNo, 0, 0}};
                        memcpy(c.d.asBytes, keyA[sectorNo], 6);
                        clearCommandBuffer();
                        SendCommand(&c);
                        received = WaitForResponseTimeout(CMD_ACK, &resp, 1500);
                    }
                }
                if (received) {
                    isOK  = resp.arg[0] & 0xff;
                    if (isOK) break;
                }
            }

            if (received) {
                isOK  = resp.arg[0] & 0xff;
                uint8_t *data  = resp.d.asBytes;
                if (blockNo == NumBlocksPerSector(sectorNo) - 1) { // sector trailer. Fill in the keys.
                    data[0]  = (keyA[sectorNo][0]);
                    data[1]  = (keyA[sectorNo][1]);
                    data[2]  = (keyA[sectorNo][2]);
                    data[3]  = (keyA[sectorNo][3]);
                    data[4]  = (keyA[sectorNo][4]);
                    data[5]  = (keyA[sectorNo][5]);
                    data[10] = (keyB[sectorNo][0]);
                    data[11] = (keyB[sectorNo][1]);
                    data[12] = (keyB[sectorNo][2]);
                    data[13] = (keyB[sectorNo][3]);
                    data[14] = (keyB[sectorNo][4]);
                    data[15] = (keyB[sectorNo][5]);
                }
                if (isOK) {
                    memcpy(carddata[FirstBlockOfSector(sectorNo) + blockNo], data, 16);
                    PrintAndLogEx(SUCCESS, "successfully read block %2d of sector %2d.", blockNo, sectorNo);
                } else {
                    PrintAndLogEx(FAILED, "could not read block %2d of sector %2d", blockNo, sectorNo);
                    break;
                }
            } else {
                isOK = false;
                PrintAndLogEx(WARNING, "command execute timeout when trying to read block %2d of sector %2d.", blockNo, sectorNo);
                break;
            }
        }
    }

    if (isOK == 0) {
        PrintAndLogEx(FAILED, "Something went wrong");
        return 0;
    }

    PrintAndLogEx(SUCCESS, "\nSuccedded in dumping all blocks");

    if (strlen(dataFilename) < 1) {
        fptr = dataFilename;
        fptr += sprintf(fptr, "hf-mf-");
        FillFileNameByUID(fptr, (uint8_t *)carddata, "-data", 4);
    }

    uint16_t bytes = 16 * (FirstBlockOfSector(numSectors - 1) + NumBlocksPerSector(numSectors - 1));

    saveFile(dataFilename, "bin", (uint8_t *)carddata, bytes);
    saveFileEML(dataFilename, "eml", (uint8_t *)carddata, bytes, MFBLOCK_SIZE);
    saveFileJSON(dataFilename, "json", jsfCardMemory, (uint8_t *)carddata, bytes);
    return 0;
}

int CmdHF14AMfRestore(const char *Cmd) {
    uint8_t sectorNo, blockNo;
    uint8_t keyType = 0;
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t bldata[16] = {0x00};
    uint8_t keyA[40][6];
    uint8_t keyB[40][6];
    uint8_t numSectors = 16;
    uint8_t cmdp = 0;
    char keyFilename[FILE_PATH_SIZE] = "";
    char dataFilename[FILE_PATH_SIZE] = "";
    char szTemp[FILE_PATH_SIZE - 20] = "";
    char *fptr;
    FILE *fdump, *fkeys;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf14_restore();
            case 'u':
                param_getstr(Cmd, cmdp + 1, szTemp, FILE_PATH_SIZE - 20);
                if (keyFilename[0] == 0x00)
                    snprintf(keyFilename, FILE_PATH_SIZE, "hf-mf-%s-key.bin", szTemp);
                if (dataFilename[0] == 0x00)
                    snprintf(dataFilename, FILE_PATH_SIZE, "hf-mf-%s-data.bin", szTemp);
                cmdp += 2;
                break;
            case 'k':
                param_getstr(Cmd, cmdp + 1, keyFilename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            case 'f':
                param_getstr(Cmd, cmdp + 1, dataFilename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            default:
                if (cmdp == 0) {
                    numSectors = NumOfSectors(param_getchar(Cmd, cmdp));
                    cmdp++;
                } else {
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                    return usage_hf14_restore();
                }
        }
    }

    if (keyFilename[0] == 0x00) {
        fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL)
            return 1;

        strcpy(keyFilename, fptr);
    }

    if ((fkeys = fopen(keyFilename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), keyFilename);
        return 1;
    }

    size_t bytes_read;
    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        bytes_read = fread(keyA[sectorNo], 1, 6, fkeys);
        if (bytes_read != 6) {
            PrintAndLogEx(WARNING, "File reading error  " _YELLOW_("%s"), keyFilename);
            fclose(fkeys);
            return 2;
        }
    }

    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        bytes_read = fread(keyB[sectorNo], 1, 6, fkeys);
        if (bytes_read != 6) {
            PrintAndLogEx(WARNING, "File reading error " _YELLOW_("%s"), keyFilename);
            fclose(fkeys);
            return 2;
        }
    }

    fclose(fkeys);

    if (dataFilename[0] == 0x00) {
        fptr = GenerateFilename("hf-mf-", "-data.bin");
        if (fptr == NULL)
            return 1;

        strcpy(dataFilename, fptr);
    }

    if ((fdump = fopen(dataFilename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), dataFilename);
        return 1;
    }
    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", dataFilename);

    for (sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        for (blockNo = 0; blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
            UsbCommand c = {CMD_MIFARE_WRITEBL, {FirstBlockOfSector(sectorNo) + blockNo, keyType, 0}};
            memcpy(c.d.asBytes, key, 6);
            bytes_read = fread(bldata, 1, 16, fdump);
            if (bytes_read != 16) {
                PrintAndLogEx(WARNING, "File reading error " _YELLOW_("%s"), dataFilename);
                fclose(fdump);
                fdump = NULL;
                return 2;
            }

            if (blockNo == NumBlocksPerSector(sectorNo) - 1) { // sector trailer
                bldata[0]  = (keyA[sectorNo][0]);
                bldata[1]  = (keyA[sectorNo][1]);
                bldata[2]  = (keyA[sectorNo][2]);
                bldata[3]  = (keyA[sectorNo][3]);
                bldata[4]  = (keyA[sectorNo][4]);
                bldata[5]  = (keyA[sectorNo][5]);
                bldata[10] = (keyB[sectorNo][0]);
                bldata[11] = (keyB[sectorNo][1]);
                bldata[12] = (keyB[sectorNo][2]);
                bldata[13] = (keyB[sectorNo][3]);
                bldata[14] = (keyB[sectorNo][4]);
                bldata[15] = (keyB[sectorNo][5]);
            }

            PrintAndLogEx(NORMAL, "Writing to block %3d: %s", FirstBlockOfSector(sectorNo) + blockNo, sprint_hex(bldata, 16));

            memcpy(c.d.asBytes + 10, bldata, 16);
            clearCommandBuffer();
            SendCommand(&c);

            UsbCommand resp;
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                uint8_t isOK  = resp.arg[0] & 0xff;
                PrintAndLogEx(SUCCESS, "isOk:%02x", isOK);
            } else {
                PrintAndLogEx(WARNING, "Command execute timeout");
            }
        }
    }

    fclose(fdump);
    return 0;
}

int CmdHF14AMfNested(const char *Cmd) {
    int i, res, iterations;
    sector_t *e_sector = NULL;
    uint8_t blockNo = 0;
    uint8_t keyType = 0;
    uint8_t trgBlockNo = 0;
    uint8_t trgKeyType = 0;
    uint8_t SectorsCnt = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t keyBlock[(MIFARE_DEFAULTKEYS_SIZE + 1) * 6];
    uint64_t key64 = 0;
    bool transferToEml = false;
    bool createDumpFile = false;
    FILE *fkeys;
    uint8_t standart[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char *fptr;

    if (strlen(Cmd) < 3) return usage_hf14_nested();

    char cmdp, ctmp;
    cmdp = tolower(param_getchar(Cmd, 0));
    blockNo = param_get8(Cmd, 1);
    ctmp = tolower(param_getchar(Cmd, 2));

    if (ctmp != 'a' && ctmp != 'b') {
        PrintAndLogEx(WARNING, "key type must be A or B");
        return 1;
    }

    if (ctmp != 'a')
        keyType = 1;

    if (param_gethex(Cmd, 3, key, 12)) {
        PrintAndLogEx(WARNING, "key must include 12 HEX symbols");
        return 1;
    }

    if (cmdp == 'o') {
        trgBlockNo = param_get8(Cmd, 4);
        ctmp = tolower(param_getchar(Cmd, 5));
        if (ctmp != 'a' && ctmp != 'b') {
            PrintAndLogEx(WARNING, "target key type must be A or B");
            return 1;
        }
        if (ctmp != 'a') {
            trgKeyType = 1;
        }
    } else {
        SectorsCnt = NumOfSectors(cmdp);
    }

    uint8_t j = 4;
    while (ctmp != 0x00) {

        ctmp = tolower(param_getchar(Cmd, j));
        transferToEml |= (ctmp == 't');
        createDumpFile |= (ctmp == 'd');

        j++;
    }

    // check if we can authenticate to sector
    res = mfCheckKeys(blockNo, keyType, true, 1, key, &key64);
    if (res) {
        PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%c", blockNo, keyType ? 'B' : 'A');
        return 3;
    }

    if (cmdp == 'o') {
        int16_t isOK = mfnested(blockNo, keyType, key, trgBlockNo, trgKeyType, keyBlock, true);
        switch (isOK) {
            case -1 :
                PrintAndLogEx(WARNING, "Error: No response from Proxmark.\n");
                break;
            case -2 :
                PrintAndLogEx(WARNING, "Button pressed. Aborted.\n");
                break;
            case -3 :
                PrintAndLogEx(FAILED, "Tag isn't vulnerable to Nested Attack (PRNG is not predictable).\n");
                break;
            case -4 :
                PrintAndLogEx(FAILED, "No valid key found");
                break;
            case -5 :
                key64 = bytes_to_num(keyBlock, 6);

                // transfer key to the emulator
                if (transferToEml) {
                    uint8_t sectortrailer;
                    if (trgBlockNo < 32 * 4) {  // 4 block sector
                        sectortrailer = trgBlockNo | 0x03;
                    } else {                    // 16 block sector
                        sectortrailer = trgBlockNo | 0x0f;
                    }
                    mfEmlGetMem(keyBlock, sectortrailer, 1);

                    if (!trgKeyType)
                        num_to_bytes(key64, 6, keyBlock);
                    else
                        num_to_bytes(key64, 6, &keyBlock[10]);
                    mfEmlSetMem(keyBlock, sectortrailer, 1);
                    PrintAndLogEx(SUCCESS, "Key transferred to emulator memory.");
                }
                return 0;
            default :
                PrintAndLogEx(WARNING, "Unknown Error.\n");
        }
        return 2;
    } else { // ------------------------------------  multiple sectors working
        uint64_t t1 = msclock();

        e_sector = calloc(SectorsCnt, sizeof(sector_t));
        if (e_sector == NULL) return 1;

        //test current key and additional standard keys first
        // add parameter key
        memcpy(keyBlock + (MIFARE_DEFAULTKEYS_SIZE * 6), key, 6);

        for (int cnt = 0; cnt < MIFARE_DEFAULTKEYS_SIZE; cnt++) {
            num_to_bytes(g_mifare_default_keys[cnt], 6, (uint8_t *)(keyBlock + cnt * 6));
        }

        PrintAndLogEx(SUCCESS, "Testing known keys. Sector count=%d", SectorsCnt);
        res = mfCheckKeys_fast(SectorsCnt, true, true, 1, MIFARE_DEFAULTKEYS_SIZE + 1, keyBlock, e_sector, false);

        uint64_t t2 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "Time to check %d known keys: %.0f seconds\n", MIFARE_DEFAULTKEYS_SIZE, (float)t2 / 1000.0);
        PrintAndLogEx(SUCCESS, "enter nested attack");

        // nested sectors
        iterations = 0;
        bool calibrate = true;

        for (i = 0; i < MIFARE_SECTOR_RETRY; i++) {
            for (uint8_t sectorNo = 0; sectorNo < SectorsCnt; ++sectorNo) {
                for (trgKeyType = 0; trgKeyType < 2; ++trgKeyType) {

                    if (e_sector[sectorNo].foundKey[trgKeyType]) continue;

                    int16_t isOK = mfnested(blockNo, keyType, key, FirstBlockOfSector(sectorNo), trgKeyType, keyBlock, calibrate);
                    switch (isOK) {
                        case -1 :
                            PrintAndLogEx(WARNING, "error: No response from Proxmark.\n");
                            break;
                        case -2 :
                            PrintAndLogEx(WARNING, "button pressed. Aborted.\n");
                            break;
                        case -3 :
                            PrintAndLogEx(FAILED, "Tag isn't vulnerable to Nested Attack (PRNG is not predictable).\n");
                            break;
                        case -4 : //key not found
                            calibrate = false;
                            iterations++;
                            continue;
                        case -5 :
                            calibrate = false;
                            iterations++;
                            e_sector[sectorNo].foundKey[trgKeyType] = 1;
                            e_sector[sectorNo].Key[trgKeyType] = bytes_to_num(keyBlock, 6);

                            res = mfCheckKeys_fast(SectorsCnt, true, true, 2, 1, keyBlock, e_sector, false);
                            continue;

                        default :
                            PrintAndLogEx(WARNING, "unknown Error.\n");
                    }
                    free(e_sector);
                    return 2;
                }
            }
        }

        t1 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "time in nested: %.0f seconds\n", (float)t1 / 1000.0);


        // 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
        PrintAndLogEx(INFO, "trying to read key B...");
        for (i = 0; i < SectorsCnt; i++) {
            // KEY A  but not KEY B
            if (e_sector[i].foundKey[0] && !e_sector[i].foundKey[1]) {

                uint8_t sectrail = (FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);

                PrintAndLogEx(SUCCESS, "reading block %d", sectrail);

                UsbCommand c = {CMD_MIFARE_READBL, {sectrail, 0, 0}};
                num_to_bytes(e_sector[i].Key[0], 6, c.d.asBytes); // KEY A
                clearCommandBuffer();
                SendCommand(&c);

                UsbCommand resp;
                if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) continue;

                uint8_t isOK  = resp.arg[0] & 0xff;
                if (!isOK) continue;

                uint8_t *data = resp.d.asBytes;
                key64 = bytes_to_num(data + 10, 6);
                if (key64) {
                    PrintAndLogEx(SUCCESS, "data: %s", sprint_hex(data + 10, 6));
                    e_sector[i].foundKey[1] = true;
                    e_sector[i].Key[1] = key64;
                }
            }
        }


        //print them
        printKeyTable(SectorsCnt, e_sector);

        // transfer them to the emulator
        if (transferToEml) {
            for (i = 0; i < SectorsCnt; i++) {
                mfEmlGetMem(keyBlock, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
                if (e_sector[i].foundKey[0])
                    num_to_bytes(e_sector[i].Key[0], 6, keyBlock);
                if (e_sector[i].foundKey[1])
                    num_to_bytes(e_sector[i].Key[1], 6, &keyBlock[10]);
                mfEmlSetMem(keyBlock, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
            }
            PrintAndLogEx(SUCCESS, "keys transferred to emulator memory.");
        }

        // Create dump file
        if (createDumpFile) {
            fptr = GenerateFilename("hf-mf-", "-key.bin");
            if (fptr == NULL) {
                free(e_sector);
                return 1;
            }

            if ((fkeys = fopen(fptr, "wb")) == NULL) {
                PrintAndLogEx(WARNING, "could not create file " _YELLOW_("%s"), fptr);
                free(e_sector);
                return 1;
            }

            PrintAndLogEx(SUCCESS, "saving keys to binary file " _YELLOW_("%s"), fptr);
            for (i = 0; i < SectorsCnt; i++) {
                if (e_sector[i].foundKey[0]) {
                    num_to_bytes(e_sector[i].Key[0], 6, tempkey);
                    fwrite(tempkey, 1, 6, fkeys);
                } else {
                    fwrite(&standart, 1, 6, fkeys);
                }
            }
            for (i = 0; i < SectorsCnt; i++) {
                if (e_sector[i].foundKey[1]) {
                    num_to_bytes(e_sector[i].Key[1], 6, tempkey);
                    fwrite(tempkey, 1, 6, fkeys);
                } else {
                    fwrite(&standart, 1, 6, fkeys);
                }
            }
            fflush(fkeys);
            fclose(fkeys);
        }
        free(e_sector);
    }
    return 0;
}

int CmdHF14AMfNestedHard(const char *Cmd) {
    uint8_t blockNo = 0;
    uint8_t keyType = 0;
    uint8_t trgBlockNo = 0;
    uint8_t trgKeyType = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t trgkey[6] = {0, 0, 0, 0, 0, 0};
    uint8_t cmdp = 0;
    char filename[FILE_PATH_SIZE], *fptr;
    char szTemp[FILE_PATH_SIZE - 20];
    char ctmp;

    bool know_target_key = false;
    bool nonce_file_read = false;
    bool nonce_file_write = false;
    bool slow = false;
    int tests = 0;

    switch (tolower(param_getchar(Cmd, cmdp))) {
        case 'h':
            return usage_hf14_hardnested();
        case 'r':
            fptr = GenerateFilename("hf-mf-", "-nonces.bin");
            if (fptr == NULL)
                strncpy(filename, "nonces.bin", FILE_PATH_SIZE - 1);
            else
                strncpy(filename, fptr, FILE_PATH_SIZE - 1);

            nonce_file_read = true;
            if (!param_gethex(Cmd, cmdp + 1, trgkey, 12)) {
                know_target_key = true;
            }
            cmdp++;
            break;
        case 't':
            tests = param_get32ex(Cmd, cmdp + 1, 100, 10);
            if (!param_gethex(Cmd, cmdp + 2, trgkey, 12)) {
                know_target_key = true;
            }
            cmdp += 2;
            break;
        default:
            if (param_getchar(Cmd, cmdp) == 0x00) {
                PrintAndLogEx(WARNING, "Block number is missing");
                return 1;

            }
            blockNo = param_get8(Cmd, cmdp);
            ctmp = tolower(param_getchar(Cmd, cmdp + 1));
            if (ctmp != 'a' && ctmp != 'b') {
                PrintAndLogEx(WARNING, "Key type must be A or B");
                return 1;
            }

            if (ctmp != 'a') {
                keyType = 1;
            }

            if (param_gethex(Cmd, cmdp + 2, key, 12)) {
                PrintAndLogEx(WARNING, "Key must include 12 HEX symbols");
                return 1;
            }

            if (param_getchar(Cmd, cmdp + 3) == 0x00) {
                PrintAndLogEx(WARNING, "Target block number is missing");
                return 1;
            }

            trgBlockNo = param_get8(Cmd, cmdp + 3);

            ctmp = tolower(param_getchar(Cmd, cmdp + 4));
            if (ctmp != 'a' && ctmp != 'b') {
                PrintAndLogEx(WARNING, "Target key type must be A or B");
                return 1;
            }
            if (ctmp != 'a') {
                trgKeyType = 1;
            }
            cmdp += 5;
    }
    if (!param_gethex(Cmd, cmdp, trgkey, 12)) {
        know_target_key = true;
        cmdp++;
    }

    while ((ctmp = param_getchar(Cmd, cmdp))) {
        switch (tolower(ctmp)) {
            case 's':
                slow = true;
                break;
            case 'w':
                nonce_file_write = true;
                fptr = GenerateFilename("hf-mf-", "-nonces.bin");
                if (fptr == NULL)
                    return 1;
                strncpy(filename, fptr, FILE_PATH_SIZE - 1);
                break;
            case 'u':
                param_getstr(Cmd, cmdp + 1, szTemp, FILE_PATH_SIZE - 20);
                snprintf(filename, FILE_PATH_SIZE, "hf-mf-%s-nonces.bin", szTemp);
                cmdp++;
                break;
            case 'f':
                param_getstr(Cmd, cmdp + 1, szTemp, FILE_PATH_SIZE - 20);
                strncpy(filename, szTemp, FILE_PATH_SIZE - 20);
                cmdp++;
                break;
            case 'i':
                SetSIMDInstr(SIMD_AUTO);
                ctmp = tolower(param_getchar(Cmd, cmdp + 1));
                switch (ctmp) {
                    case '5':
                        SetSIMDInstr(SIMD_AVX512);
                        break;
                    case '2':
                        SetSIMDInstr(SIMD_AVX2);
                        break;
                    case 'a':
                        SetSIMDInstr(SIMD_AVX);
                        break;
                    case 's':
                        SetSIMDInstr(SIMD_SSE2);
                        break;
                    case 'm':
                        SetSIMDInstr(SIMD_MMX);
                        break;
                    case 'n':
                        SetSIMDInstr(SIMD_NONE);
                        break;
                    default:
                        PrintAndLogEx(WARNING, "Unknown SIMD type. %c", ctmp);
                        return 1;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", ctmp);
                usage_hf14_hardnested();
                return 1;
        }
        cmdp++;
    }

    if (!know_target_key) {
        uint64_t key64 = 0;
        // check if we can authenticate to sector
        int res = mfCheckKeys(blockNo, keyType, true, 1, key, &key64);
        if (res) {
            PrintAndLogEx(WARNING, "Key is wrong. Can't authenticate to block:%3d key type:%c", blockNo, keyType ? 'B' : 'A');
            return 3;
        }
    }

    PrintAndLogEx(NORMAL, "--target block no:%3d, target key type:%c, known target key: 0x%02x%02x%02x%02x%02x%02x%s, file action: %s, Slow: %s, Tests: %d ",
                  trgBlockNo,
                  trgKeyType ? 'B' : 'A',
                  trgkey[0], trgkey[1], trgkey[2], trgkey[3], trgkey[4], trgkey[5],
                  know_target_key ? "" : " (not set)",
                  nonce_file_write ? "write" : nonce_file_read ? "read" : "none",
                  slow ? "Yes" : "No",
                  tests);

    uint64_t foundkey = 0;
    int16_t isOK = mfnestedhard(blockNo, keyType, key, trgBlockNo, trgKeyType, know_target_key ? trgkey : NULL, nonce_file_read, nonce_file_write, slow, tests, &foundkey, filename);

    DropField();
    if (isOK) {
        switch (isOK) {
            case 1 :
                PrintAndLogEx(WARNING, "Error: No response from Proxmark.\n");
                break;
            case 2 :
                PrintAndLogEx(NORMAL, "Button pressed. Aborted.\n");
                break;
            default :
                break;
        }
        return 2;
    }
    return 0;
}

int randInRange(int min, int max) {
    return min + (int)(rand() / (double)(RAND_MAX) * (max - min + 1));
}

//Fisher–Yates shuffle
void shuffle(uint8_t *array, uint16_t len) {
    uint8_t tmp[6];
    uint16_t x;
    time_t t;
    srand((unsigned) time(&t));
    while (len) {
        x = randInRange(0, (len -= 6)) | 0;  // 0 = i < n
        x %= 6;
        memcpy(tmp, array + x, 6);
        memcpy(array + x, array + len, 6);
        memcpy(array + len, tmp, 6);
    }
}

int CmdHF14AMfChk_fast(const char *Cmd) {

    char ctmp = 0x00;
    ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_chk_fast();

    FILE *f;
    char filename[FILE_PATH_SIZE] = {0};
    char buf[13];
    char *fptr;
    uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t *keyBlock, *p;
    uint8_t sectorsCnt = 1;
    int i, keycnt = 0;
    int clen = 0;
    int transferToEml = 0, createDumpFile = 0;
    uint32_t keyitems = MIFARE_DEFAULTKEYS_SIZE;
    bool use_flashmemory = false;

    sector_t *e_sector = NULL;

    keyBlock = calloc(MIFARE_DEFAULTKEYS_SIZE, 6);
    if (keyBlock == NULL) return 1;

    for (int cnt = 0; cnt < MIFARE_DEFAULTKEYS_SIZE; cnt++)
        num_to_bytes(g_mifare_default_keys[cnt], 6, keyBlock + cnt * 6);

    // sectors
    switch (ctmp) {
        case '0':
            sectorsCnt =  MIFARE_MINI_MAXSECTOR;
            break;
        case '1':
            sectorsCnt = MIFARE_1K_MAXSECTOR;
            break;
        case '2':
            sectorsCnt = MIFARE_2K_MAXSECTOR;
            break;
        case '4':
            sectorsCnt = MIFARE_4K_MAXSECTOR;
            break;
        default:
            sectorsCnt = MIFARE_1K_MAXSECTOR;
    }

    for (i = 1; param_getchar(Cmd, i); i++) {

        ctmp = tolower(param_getchar(Cmd, i));
        clen = param_getlength(Cmd, i);

        if (clen == 12) {

            if (param_gethex(Cmd, i, keyBlock + 6 * keycnt, 12)) {
                PrintAndLogEx(FAILED, "not hex, skipping");
                continue;
            }

            if (keyitems - keycnt < 2) {
                p = realloc(keyBlock, 6 * (keyitems += 64));
                if (!p) {
                    PrintAndLogEx(FAILED, "Cannot allocate memory for Keys");
                    free(keyBlock);
                    return 2;
                }
                keyBlock = p;
            }
            PrintAndLogEx(NORMAL, "[%2d] key %s", keycnt, sprint_hex((keyBlock + 6 * keycnt), 6));
            keycnt++;
        } else if (clen == 1) {
            if (ctmp == 't') { transferToEml = 1; continue; }
            if (ctmp == 'd') { createDumpFile = 1; continue; }
#ifdef WITH_FLASH
            if (ctmp == 'm') { use_flashmemory = true; continue; }
#endif
        } else {
            // May be a dic file
            if (param_getstr(Cmd, i, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                PrintAndLogEx(FAILED, "Filename too long");
                continue;
            }

            f = fopen(filename, "r");
            if (!f) {
                PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
                continue;
            }

            // read file
            while (fgets(buf, sizeof(buf), f)) {
                if (strlen(buf) < 12 || buf[11] == '\n')
                    continue;

                while (fgetc(f) != '\n' && !feof(f)) ;  //goto next line

                if (buf[0] == '#') continue; //The line start with # is comment, skip

                if (!isxdigit(buf[0])) {
                    PrintAndLogEx(FAILED, "File content error. '" _YELLOW_("%s")"' must include 12 HEX symbols", buf);
                    continue;
                }

                buf[12] = 0;
                if (keyitems - keycnt < 2) {
                    p = realloc(keyBlock, 6 * (keyitems += 64));
                    if (!p) {
                        PrintAndLogEx(FAILED, "Cannot allocate memory for default keys");
                        free(keyBlock);
                        fclose(f);
                        return 2;
                    }
                    keyBlock = p;
                }
                int pos = 6 * keycnt;
                memset(keyBlock + pos, 0, 6);
                num_to_bytes(strtoll(buf, NULL, 16), 6, keyBlock + pos);
                keycnt++;
                memset(buf, 0, sizeof(buf));
            }
            fclose(f);
            PrintAndLogEx(SUCCESS, "Loaded %2d keys from " _YELLOW_("%s"), keycnt, filename);
        }
    }

    if (keycnt == 0 && !use_flashmemory) {
        PrintAndLogEx(SUCCESS, "No key specified, trying default keys");
        for (; keycnt < MIFARE_DEFAULTKEYS_SIZE; keycnt++)
            PrintAndLogEx(NORMAL, "[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
                          (keyBlock + 6 * keycnt)[0], (keyBlock + 6 * keycnt)[1], (keyBlock + 6 * keycnt)[2],
                          (keyBlock + 6 * keycnt)[3], (keyBlock + 6 * keycnt)[4], (keyBlock + 6 * keycnt)[5]);
    }

    // // initialize storage for found keys
    e_sector = calloc(sectorsCnt, sizeof(sector_t));
    if (e_sector == NULL) {
        free(keyBlock);
        return 1;
    }

    uint32_t chunksize = keycnt > (USB_CMD_DATA_SIZE / 6) ? (USB_CMD_DATA_SIZE / 6) : keycnt;
    bool firstChunk = true, lastChunk = false;

    // time
    uint64_t t1 = msclock();

    if (use_flashmemory) {
        PrintAndLogEx(SUCCESS, "Using dictionary in flash memory");
        mfCheckKeys_fast(sectorsCnt, true, true, 1, 0, keyBlock, e_sector, use_flashmemory);
    } else {

        // strategys. 1= deep first on sector 0 AB,  2= width first on all sectors
        for (uint8_t strategy = 1; strategy < 3; strategy++) {
            PrintAndLogEx(SUCCESS, "Running strategy %u", strategy);

            // main keychunk loop
            for (uint32_t i = 0; i < keycnt; i += chunksize) {

                if (ukbhit()) {
                    int gc = getchar();
                    (void)gc;
                    PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                    goto out;
                }

                uint32_t size = ((keycnt - i)  > chunksize) ? chunksize : keycnt - i;

                // last chunk?
                if (size == keycnt - i)
                    lastChunk = true;

                int res = mfCheckKeys_fast(sectorsCnt, firstChunk, lastChunk, strategy, size, keyBlock + (i * 6), e_sector, false);

                if (firstChunk)
                    firstChunk = false;

                // all keys,  aborted
                if (res == 0 || res == 2)
                    goto out;
            } // end chunks of keys
            firstChunk = true;
            lastChunk = false;
        } // end strategy
    }
out:
    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "Time in checkkeys (fast):  %.1fs\n", (float)(t1 / 1000.0));

    // check..
    uint8_t found_keys = 0;
    for (uint8_t i = 0; i < sectorsCnt; ++i) {

        if (e_sector[i].foundKey[0])
            found_keys++;

        if (e_sector[i].foundKey[1])
            found_keys++;
    }

    if (found_keys == 0) {
        PrintAndLogEx(WARNING, "No keys found");
    } else {

        printKeyTable(sectorsCnt, e_sector);

        if (transferToEml) {
            uint8_t block[16] = {0x00};
            for (uint8_t i = 0; i < sectorsCnt; ++i) {
                mfEmlGetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
                if (e_sector[i].foundKey[0])
                    num_to_bytes(e_sector[i].Key[0], 6, block);
                if (e_sector[i].foundKey[1])
                    num_to_bytes(e_sector[i].Key[1], 6, block + 10);
                mfEmlSetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
            }
            PrintAndLogEx(SUCCESS, "Found keys have been transferred to the emulator memory");
        }

        if (createDumpFile) {
            fptr = GenerateFilename("hf-mf-", "-key.bin");
            if (fptr == NULL)
                return 1;

            FILE *fkeys = fopen(fptr, "wb");
            if (fkeys == NULL) {
                PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), fptr);
                free(keyBlock);
                free(e_sector);
                return 1;
            }
            PrintAndLogEx(SUCCESS, "Printing keys to binary file " _YELLOW_("%s")"...", fptr);

            for (i = 0; i < sectorsCnt; i++) {
                num_to_bytes(e_sector[i].Key[0], 6, tempkey);
                fwrite(tempkey, 1, 6, fkeys);
            }

            for (i = 0; i < sectorsCnt; i++) {
                num_to_bytes(e_sector[i].Key[1], 6, tempkey);
                fwrite(tempkey, 1, 6, fkeys);
            }

            fclose(fkeys);
            PrintAndLogEx(SUCCESS, "Found keys have been dumped to " _YELLOW_("%s")" --> 0xffffffffffff has been inserted for unknown keys.", fptr);
        }
    }

    free(keyBlock);
    free(e_sector);
    PrintAndLogEx(NORMAL, "");
    return 0;
}

int CmdHF14AMfChk(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || ctmp == 'h') return usage_hf14_chk();

    FILE *f;
    char filename[FILE_PATH_SIZE] = {0};
    char buf[13];
    uint8_t *keyBlock, *p;
    sector_t *e_sector = NULL;

    uint8_t blockNo = 0;
    uint8_t SectorsCnt = 1;
    uint8_t keyType = 0;
    uint32_t keyitems = MIFARE_DEFAULTKEYS_SIZE;
    uint64_t key64 = 0;
    uint8_t tempkey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char *fptr;
    int clen = 0;
    int transferToEml = 0;
    int createDumpFile = 0;
    int i, res, keycnt = 0;

    keyBlock = calloc(MIFARE_DEFAULTKEYS_SIZE, 6);
    if (keyBlock == NULL) return 1;

    for (int cnt = 0; cnt < MIFARE_DEFAULTKEYS_SIZE; cnt++)
        num_to_bytes(g_mifare_default_keys[cnt], 6, (uint8_t *)(keyBlock + cnt * 6));

    if (param_getchar(Cmd, 0) == '*') {
        blockNo = 3;
        SectorsCnt = NumOfSectors(param_getchar(Cmd + 1, 0));
    } else {
        blockNo = param_get8(Cmd, 0);
    }

    ctmp = tolower(param_getchar(Cmd, 1));
    clen = param_getlength(Cmd, 1);
    if (clen == 1) {
        switch (ctmp) {
            case 'a':
                keyType = 0;
                break;
            case 'b':
                keyType = 1;
                break;
            case '?':
                keyType = 2;
                break;
            default:
                PrintAndLogEx(FAILED, "Key type must be A , B or ?");
                free(keyBlock);
                return 1;
        };
    }

    for (i = 2; param_getchar(Cmd, i); i++) {

        ctmp = tolower(param_getchar(Cmd, i));
        clen = param_getlength(Cmd, i);

        if (clen == 12) {

            if (param_gethex(Cmd, i, keyBlock + 6 * keycnt, 12)) {
                PrintAndLogEx(FAILED, "not hex, skipping");
                continue;
            }

            if (keyitems - keycnt < 2) {
                p = realloc(keyBlock, 6 * (keyitems += 64));
                if (!p) {
                    PrintAndLogEx(FAILED, "cannot allocate memory for Keys");
                    free(keyBlock);
                    return 2;
                }
                keyBlock = p;
            }
            PrintAndLogEx(NORMAL, "[%2d] key %s", keycnt, sprint_hex((keyBlock + 6 * keycnt), 6));;
            keycnt++;
        } else if (clen == 1) {
            if (ctmp == 't') { transferToEml = 1; continue; }
            if (ctmp == 'd') { createDumpFile = 1; continue; }
        } else {
            // May be a dic file
            if (param_getstr(Cmd, i, filename, sizeof(filename)) >= FILE_PATH_SIZE) {
                PrintAndLogEx(FAILED, "File name too long");
                continue;
            }

            f = fopen(filename, "r");
            if (!f) {
                PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
                continue;
            }

            // load keys from dictionary file
            while (fgets(buf, sizeof(buf), f)) {
                if (strlen(buf) < 12 || buf[11] == '\n')
                    continue;

                while (fgetc(f) != '\n' && !feof(f)) ;  //goto next line

                if (buf[0] == '#') continue; //The line start with # is comment, skip

                // codesmell, only checks first char?
                if (!isxdigit(buf[0])) {
                    PrintAndLogEx(FAILED, "File content error. '" _YELLOW_("%s")"' must include 12 HEX symbols", buf);
                    continue;
                }

                buf[12] = 0;

                if (keyitems - keycnt < 2) {
                    p = realloc(keyBlock, 6 * (keyitems += 64));
                    if (!p) {
                        PrintAndLogEx(FAILED, "Cannot allocate memory for defKeys");
                        free(keyBlock);
                        fclose(f);
                        return 2;
                    }
                    keyBlock = p;
                }
                memset(keyBlock + 6 * keycnt, 0, 6);
                num_to_bytes(strtoll(buf, NULL, 16), 6, keyBlock + 6 * keycnt);
                //PrintAndLogEx(NORMAL, "check key[%2d] %012" PRIx64, keycnt, bytes_to_num(keyBlock + 6*keycnt, 6));
                keycnt++;
                memset(buf, 0, sizeof(buf));
            }
            fclose(f);
            PrintAndLogEx(SUCCESS, "Loaded %2d keys from " _YELLOW_("%s"), keycnt, filename);
        }
    }

    if (keycnt == 0) {
        PrintAndLogEx(INFO, "No key specified, trying default keys");
        for (; keycnt < MIFARE_DEFAULTKEYS_SIZE; keycnt++)
            PrintAndLogEx(NORMAL, "[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
                          (keyBlock + 6 * keycnt)[0], (keyBlock + 6 * keycnt)[1], (keyBlock + 6 * keycnt)[2],
                          (keyBlock + 6 * keycnt)[3], (keyBlock + 6 * keycnt)[4], (keyBlock + 6 * keycnt)[5], 6);
    }

    // initialize storage for found keys
    e_sector = calloc(SectorsCnt, sizeof(sector_t));
    if (e_sector == NULL) {
        free(keyBlock);
        return 1;
    }

    // empty e_sector
    for (int i = 0; i < SectorsCnt; ++i) {
        e_sector[i].Key[0] = 0xffffffffffff;
        e_sector[i].Key[1] = 0xffffffffffff;
        e_sector[i].foundKey[0] = false;
        e_sector[i].foundKey[1] = false;
    }


    uint8_t trgKeyType = 0;
    uint32_t max_keys = keycnt > (USB_CMD_DATA_SIZE / 6) ? (USB_CMD_DATA_SIZE / 6) : keycnt;

    // time
    uint64_t t1 = msclock();


    // check keys.
    for (trgKeyType = (keyType == 2) ? 0 : keyType; trgKeyType < 2; (keyType == 2) ? (++trgKeyType) : (trgKeyType = 2)) {

        int b = blockNo;
        for (int i = 0; i < SectorsCnt; ++i) {

            // skip already found keys.
            if (e_sector[i].foundKey[trgKeyType]) continue;

            for (uint32_t c = 0; c < keycnt; c += max_keys) {

                printf(".");
                fflush(stdout);
                if (ukbhit()) {
                    int gc = getchar();
                    (void)gc;
                    PrintAndLogEx(INFO, "\naborted via keyboard!\n");
                    goto out;
                }

                uint32_t size = keycnt - c > max_keys ? max_keys : keycnt - c;

                res = mfCheckKeys(b, trgKeyType, true, size, &keyBlock[6 * c], &key64);
                if (!res) {
                    e_sector[i].Key[trgKeyType] = key64;
                    e_sector[i].foundKey[trgKeyType] = true;
                    break;
                }


            }
            b < 127 ? (b += 4) : (b += 16);
        }
    }
    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\nTime in checkkeys: %.0f seconds\n", (float)t1 / 1000.0);


    // 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
    if (keyType != 1) {
        PrintAndLogEx(INFO, "testing to read key B...");
        for (i = 0; i < SectorsCnt; i++) {
            // KEY A  but not KEY B
            if (e_sector[i].foundKey[0] && !e_sector[i].foundKey[1]) {

                uint8_t sectrail = (FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);

                PrintAndLogEx(NORMAL, "Reading block %d", sectrail);

                UsbCommand c = {CMD_MIFARE_READBL, {sectrail, 0, 0}};
                num_to_bytes(e_sector[i].Key[0], 6, c.d.asBytes); // KEY A
                clearCommandBuffer();
                SendCommand(&c);

                UsbCommand resp;
                if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) continue;

                uint8_t isOK  = resp.arg[0] & 0xff;
                if (!isOK) continue;

                uint8_t *data = resp.d.asBytes;
                key64 = bytes_to_num(data + 10, 6);
                if (key64) {
                    PrintAndLogEx(NORMAL, "Data:%s", sprint_hex(data + 10, 6));
                    e_sector[i].foundKey[1] = 1;
                    e_sector[i].Key[1] = key64;
                }
            }
        }
    }

out:

    //print keys
    printKeyTable(SectorsCnt, e_sector);

    if (transferToEml) {
        uint8_t block[16] = {0x00};
        for (uint8_t i = 0; i < SectorsCnt; ++i) {
            mfEmlGetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
            if (e_sector[i].foundKey[0])
                num_to_bytes(e_sector[i].Key[0], 6, block);
            if (e_sector[i].foundKey[1])
                num_to_bytes(e_sector[i].Key[1], 6, block + 10);
            mfEmlSetMem(block, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1);
        }
        PrintAndLogEx(SUCCESS, "Found keys have been transferred to the emulator memory");
    }

    if (createDumpFile) {
        fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL) {
            free(keyBlock);
            free(e_sector);
            return 1;
        }

        FILE *fkeys = fopen(fptr, "wb");
        if (fkeys == NULL) {
            PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), fptr);
            free(keyBlock);
            free(e_sector);
            return 1;
        }
        PrintAndLogEx(INFO, "Printing keys to binary file " _YELLOW_("%s")"...", fptr);

        for (i = 0; i < SectorsCnt; i++) {
            num_to_bytes(e_sector[i].Key[0], 6, tempkey);
            fwrite(tempkey, 1, 6, fkeys);
        }
        for (i = 0; i < SectorsCnt; i++) {
            num_to_bytes(e_sector[i].Key[1], 6, tempkey);
            fwrite(tempkey, 1, 6, fkeys);
        }
        fclose(fkeys);
        PrintAndLogEx(SUCCESS, "Found keys have been dumped to file " _YELLOW_("%s")". 0xffffffffffff has been inserted for unknown keys.", fptr);
    }

    free(keyBlock);
    free(e_sector);
    PrintAndLogEx(NORMAL, "");
    return 0;
}

sector_t *k_sector = NULL;
uint8_t k_sectorsCount = 16;
static void emptySectorTable() {

    // initialize storage for found keys
    if (k_sector == NULL)
        k_sector = calloc(k_sectorsCount, sizeof(sector_t));
    if (k_sector == NULL)
        return;

    // empty e_sector
    for (int i = 0; i < k_sectorsCount; ++i) {
        k_sector[i].Key[0] = 0xffffffffffff;
        k_sector[i].Key[1] = 0xffffffffffff;
        k_sector[i].foundKey[0] = false;
        k_sector[i].foundKey[1] = false;
    }
}

void showSectorTable() {
    if (k_sector != NULL) {
        printKeyTable(k_sectorsCount, k_sector);
        free(k_sector);
        k_sector = NULL;
    }
}

void readerAttack(nonces_t data, bool setEmulatorMem, bool verbose) {

    uint64_t key = 0;
    bool success = false;

    if (k_sector == NULL)
        emptySectorTable();

    success = mfkey32_moebius(data, &key);
    if (success) {
        uint8_t sector = data.sector;
        uint8_t keytype = data.keytype;

        PrintAndLogEx(INFO, "Reader is trying authenticate with: Key %s, sector %02d: [%012" PRIx64 "]"
                      , keytype ? "B" : "A"
                      , sector
                      , key
                     );

        k_sector[sector].Key[keytype] = key;
        k_sector[sector].foundKey[keytype] = true;

        //set emulator memory for keys
        if (setEmulatorMem) {
            uint8_t memBlock[16] = {0, 0, 0, 0, 0, 0, 0xff, 0x0F, 0x80, 0x69, 0, 0, 0, 0, 0, 0};
            num_to_bytes(k_sector[sector].Key[0], 6, memBlock);
            num_to_bytes(k_sector[sector].Key[1], 6, memBlock + 10);
            //iceman,  guessing this will not work so well for 4K tags.
            PrintAndLogEx(INFO, "Setting Emulator Memory Block %02d: [%s]"
                          , (sector * 4) + 3
                          , sprint_hex(memBlock, sizeof(memBlock))
                         );
            mfEmlSetMem(memBlock, (sector * 4) + 3, 1);
        }
    }
}

int CmdHF14AMf1kSim(const char *Cmd) {

    uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t exitAfterNReads = 0;
    uint8_t flags = (FLAG_UID_IN_EMUL | FLAG_4B_UID_IN_DATA);
    int uidlen = 0;
    uint8_t cmdp = 0;
    bool errors = false, verbose = false, setEmulatorMem = false;
    nonces_t data[1];

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'e':
                setEmulatorMem = true;
                cmdp++;
                break;
            case 'h':
                return usage_hf14_mf1ksim();
            case 'i':
                flags |= FLAG_INTERACTIVE;
                cmdp++;
                break;
            case 'n':
                exitAfterNReads = param_get8(Cmd, cmdp + 1);
                cmdp += 2;
                break;
            case 'u':
                param_gethex_ex(Cmd, cmdp + 1, uid, &uidlen);
                switch (uidlen) {
                    case 20:
                        flags = FLAG_10B_UID_IN_DATA;
                        break;
                    case 14:
                        flags = FLAG_7B_UID_IN_DATA;
                        break;
                    case  8:
                        flags = FLAG_4B_UID_IN_DATA;
                        break;
                    default:
                        return usage_hf14_mf1ksim();
                }
                cmdp += 2;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            case 'x':
                flags |= FLAG_NR_AR_ATTACK;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) return usage_hf14_mf1ksim();

    PrintAndLogEx(NORMAL, " uid:%s, numreads:%d, flags:%d (0x%02x) "
                  , (uidlen == 0) ? "N/A" : sprint_hex(uid, uidlen >> 1)
                  , exitAfterNReads
                  , flags
                  , flags);

    UsbCommand c = {CMD_SIMULATE_MIFARE_CARD, {flags, exitAfterNReads, 0}};
    memcpy(c.d.asBytes, uid, sizeof(uid));
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;

    if (flags & FLAG_INTERACTIVE) {
        PrintAndLogEx(INFO, "Press pm3-button or send another cmd to abort simulation");

        while (!ukbhit()) {
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) continue;
            if (!(flags & FLAG_NR_AR_ATTACK)) break;
            if ((resp.arg[0] & 0xffff) != CMD_SIMULATE_MIFARE_CARD) break;

            memcpy(data, resp.d.asBytes, sizeof(data));
            readerAttack(data[0], setEmulatorMem, verbose);
        }
        showSectorTable();
    }
    return 0;
}

int CmdHF14AMfSniff(const char *Cmd) {
    bool wantLogToFile = false;
    bool wantDecrypt = false;
    //bool wantSaveToEml = false; TODO
    bool wantSaveToEmlFile = false;

    //var
    int res = 0, len = 0, blockLen = 0;
    int pckNum = 0, num = 0;
    uint8_t sak = 0;
    uint8_t uid[10];
    uint8_t uid_len = 0;
    uint8_t atqa[2] = {0x00, 0x00};
    bool isTag = false;
    uint8_t *buf = NULL;
    uint16_t bufsize = 0;
    uint8_t *bufPtr = NULL;
    uint16_t traceLen = 0;

    memset(uid, 0x00, sizeof(uid));

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hf14_sniff();

    for (int i = 0; i < 4; i++) {
        ctmp = tolower(param_getchar(Cmd, i));
        if (ctmp == 'l') wantLogToFile = true;
        if (ctmp == 'd') wantDecrypt = true;
        //if (ctmp == 'e') wantSaveToEml = true; TODO
        if (ctmp == 'f') wantSaveToEmlFile = true;
    }

    PrintAndLogEx(NORMAL, "-------------------------------------------------------------------------\n");
    PrintAndLogEx(NORMAL, "Executing mifare sniffing command. \n");
    PrintAndLogEx(NORMAL, "Press the key on the proxmark3 device to abort both proxmark3 and client.\n");
    PrintAndLogEx(NORMAL, "Press the key on pc keyboard to abort the client.\n");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------------------\n");

    UsbCommand c = {CMD_MIFARE_SNIFFER, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);

    UsbCommand resp;

    // wait cycle
    while (true) {
        printf(".");
        fflush(stdout);
        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(INFO, "\naborted via keyboard!\n");
            break;
        }

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            continue;
        }

        res = resp.arg[0] & 0xff;
        traceLen = resp.arg[1];
        len = resp.arg[2];

        if (res == 0) {
            PrintAndLogEx(SUCCESS, "hf mifare sniff finished");
            free(buf);
            return 0;
        }

        if (res == 1) {                             // there is (more) data to be transferred
            if (pckNum == 0) {                      // first packet, (re)allocate necessary buffer
                if (traceLen > bufsize || buf == NULL) {
                    uint8_t *p;
                    if (buf == NULL)                // not yet allocated
                        p = calloc(traceLen, sizeof(uint8_t));
                    else                            // need more memory
                        p = realloc(buf, traceLen);

                    if (p == NULL) {
                        PrintAndLogEx(FAILED, "Cannot allocate memory for trace");
                        free(buf);
                        return 2;
                    }
                    buf = p;
                }
                bufPtr = buf;
                bufsize = traceLen;
                memset(buf, 0x00, traceLen);
            }

            // what happens if LEN is bigger then TRACELEN --iceman
            memcpy(bufPtr, resp.d.asBytes, len);
            bufPtr += len;
            pckNum++;
        }

        if (res == 2) {                             // received all data, start displaying
            blockLen = bufPtr - buf;
            bufPtr = buf;
            PrintAndLogEx(NORMAL, ">\n");
            PrintAndLogEx(SUCCESS, "received trace len: %d packages: %d", blockLen, pckNum);
            while (bufPtr - buf < blockLen) {
                bufPtr += 6;                        // skip (void) timing information
                len = *((uint16_t *)bufPtr);
                if (len & 0x8000) {
                    isTag = true;
                    len &= 0x7fff;
                } else {
                    isTag = false;
                }
                bufPtr += 2;

                // the uid identification package
                // 0xFF 0xFF xx xx xx xx xx xx xx xx xx xx aa aa cc 0xFF 0xFF
                // x = uid,  a = atqa, c = sak
                if ((len == 17) && (bufPtr[0] == 0xff) && (bufPtr[1] == 0xff) && (bufPtr[15] == 0xff) && (bufPtr[16] == 0xff)) {
                    memcpy(uid, bufPtr + 2, 10);
                    memcpy(atqa, bufPtr + 2 + 10, 2);
                    switch (atqa[0] & 0xC0) {
                        case 0x80:
                            uid_len = 10;
                            break;
                        case 0x40:
                            uid_len = 7;
                            break;
                        default:
                            uid_len = 4;
                            break;
                    }
                    sak = bufPtr[14];
                    PrintAndLogEx(SUCCESS, "UID %s | ATQA %02x %02x | SAK 0x%02x",
                                  sprint_hex(uid, uid_len),
                                  atqa[1],
                                  atqa[0],
                                  sak);
                    if (wantLogToFile || wantDecrypt) {
                        FillFileNameByUID(logHexFileName, uid, ".log", uid_len);
                        AddLogCurrentDT(logHexFileName);
                        PrintAndLogEx(SUCCESS, "Trace saved to %s", logHexFileName);
                    }
                    if (wantDecrypt)
                        mfTraceInit(uid, uid_len, atqa, sak, wantSaveToEmlFile);
                } else {
                    PrintAndLogEx(NORMAL, "%03d| %s |%s", num, isTag ? "TAG" : "RDR", sprint_hex(bufPtr, len));
                    if (wantLogToFile)
                        AddLogHex(logHexFileName, isTag ? "TAG| " : "RDR| ", bufPtr, len);
                    if (wantDecrypt)
                        mfTraceDecode(bufPtr, len, wantSaveToEmlFile);
                    num++;
                }
                bufPtr += len;
                bufPtr += ((len - 1) / 8 + 1); // ignore parity
            }
            pckNum = 0;
        }
    } // while (true)

    free(buf);
    return 0;
}

int CmdHF14AMfDbg(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_dbg();

    uint8_t dbgMode = param_get8ex(Cmd, 0, 0, 10);
    if (dbgMode > 4) return usage_hf14_dbg();

    UsbCommand c = {CMD_MIFARE_SET_DBGMODE, {dbgMode, 0, 0}};
    SendCommand(&c);
    return 0;
}

int CmdHF14AMfKeyBrute(const char *Cmd) {

    uint8_t blockNo = 0, keytype = 0;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint64_t foundkey = 0;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf14_keybrute();

    // block number
    blockNo = param_get8(Cmd, 0);

    // keytype
    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 'b') keytype = 1;

    // key
    if (param_gethex(Cmd, 2, key, 12)) return usage_hf14_keybrute();

    uint64_t t1 = msclock();

    if (mfKeyBrute(blockNo, keytype, key, &foundkey))
        PrintAndLogEx(SUCCESS, "found valid key: %012" PRIx64 " \n", foundkey);
    else
        PrintAndLogEx(FAILED, "key not found");

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in keybrute: %.0f seconds\n", (float)t1 / 1000.0);
    return 0;
}

void printKeyTable(uint8_t sectorscnt, sector_t *e_sector) {
    char strA[12 + 1] = {0};
    char strB[12 + 1] = {0};
    PrintAndLogEx(NORMAL, "|---|----------------|---|----------------|---|");
    PrintAndLogEx(NORMAL, "|sec|key A           |res|key B           |res|");
    PrintAndLogEx(NORMAL, "|---|----------------|---|----------------|---|");
    for (uint8_t i = 0; i < sectorscnt; ++i) {

        snprintf(strA, sizeof(strA), "------------");
        snprintf(strB, sizeof(strB), "------------");

        if (e_sector[i].foundKey[0])
            snprintf(strA, sizeof(strA), "%012" PRIx64, e_sector[i].Key[0]);

        if (e_sector[i].foundKey[1])
            snprintf(strB, sizeof(strB), "%012" PRIx64, e_sector[i].Key[1]);


        PrintAndLogEx(NORMAL, "|%03d|  %s  | %d |  %s  | %d |"
                      , i
                      , strA, e_sector[i].foundKey[0]
                      , strB, e_sector[i].foundKey[1]
                     );
    }
    PrintAndLogEx(NORMAL, "|---|----------------|---|----------------|---|");
}

// EMULATOR COMMANDS
int CmdHF14AMfEGet(const char *Cmd) {
    uint8_t blockNo = 0;
    uint8_t data[16] = {0x00};
    char c = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 1 || c == 'h') return usage_hf14_eget();

    blockNo = param_get8(Cmd, 0);

    PrintAndLogEx(NORMAL, "");
    if (!mfEmlGetMem(data, blockNo, 1)) {
        PrintAndLogEx(NORMAL, "data[%3d]:%s", blockNo, sprint_hex(data, sizeof(data)));
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
    return 0;
}

int CmdHF14AMfEClear(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h') return usage_hf14_eclr();

    UsbCommand cmd = {CMD_MIFARE_EML_MEMCLR, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&cmd);
    return 0;
}

int CmdHF14AMfESet(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    uint8_t memBlock[16];
    uint8_t blockNo = 0;
    memset(memBlock, 0x00, sizeof(memBlock));

    if (strlen(Cmd) < 3 || c == 'h')
        return usage_hf14_eset();

    blockNo = param_get8(Cmd, 0);

    if (param_gethex(Cmd, 1, memBlock, 32)) {
        PrintAndLogEx(WARNING, "block data must include 32 HEX symbols");
        return 1;
    }

    //  1 - blocks count
    return mfEmlSetMem(memBlock, blockNo, 1);
}

int CmdHF14AMfELoad(const char *Cmd) {

    size_t counter = 0;
    char filename[FILE_PATH_SIZE];
    int blockNum, numBlocks, nameParamNo = 1;
    uint8_t blockWidth = 16;
    char c = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 2 &&  c == 'h')
        return usage_hf14_eload();

    switch (c) {
        case '0' :
            numBlocks = MIFARE_MINI_MAXBLOCK;
            break;
        case '1' :
        case '\0':
            numBlocks = MIFARE_1K_MAXBLOCK;
            break;
        case '2' :
            numBlocks = MIFARE_2K_MAXBLOCK;
            break;
        case '4' :
            numBlocks = MIFARE_4K_MAXBLOCK;
            break;
        case 'u' :
            numBlocks = 255;
            blockWidth = 4;
            break;
        default:  {
            numBlocks = MIFARE_1K_MAXBLOCK;
            nameParamNo = 0;
        }
    }
    uint32_t numblk2 = param_get32ex(Cmd, 2, 0, 10);
    if (numblk2 > 0)
        numBlocks = numblk2;

    param_getstr(Cmd, nameParamNo, filename, sizeof(filename));

    uint8_t *data = calloc(4096, sizeof(uint8_t));
    size_t datalen = 0;
    //int res = loadFile(filename, "bin", data, maxdatalen, &datalen);
    int res = loadFileEML(filename, "eml", data, &datalen);
    if (res) {
        free(data);
        return 1;
    }

    // 64 or 256 blocks.
    if ((datalen % blockWidth) != 0) {
        PrintAndLogEx(FAILED, "File content error. Size doesn't match blockwidth ");
        free(data);
        return 2;
    }

    PrintAndLogEx(INFO, "Copying to emulator memory");

    blockNum = 0;
    while (datalen) {

        if (mfEmlSetMem_xt(data + counter, blockNum, 1, blockWidth)) {
            PrintAndLogEx(FAILED, "Cant set emul block: %3d", blockNum);
            free(data);
            return 3;
        }
        printf(".");
        fflush(stdout);

        blockNum++;
        counter += blockWidth;
        datalen -= blockWidth;
    }
    PrintAndLogEx(NORMAL, "\n");

    // Ultralight /Ntag
    if (blockWidth == 4) {
        if ((blockNum != numBlocks)) {
            PrintAndLogEx(FAILED, "Warning, Ultralight/Ntag file content, Loaded %d blocks into emulator memory", blockNum);
            free(data);
            return 0;
        }
    } else {
        if ((blockNum != numBlocks)) {
            PrintAndLogEx(FAILED, "Error, file content, Only loaded %d blocks, must be %d blocks into emulator memory", blockNum, numBlocks);
            free(data);
            return 4;
        }
    }
    PrintAndLogEx(SUCCESS, "Loaded %d blocks from file: " _YELLOW_("%s"), blockNum, filename);
    free(data);
    return 0;
}

int CmdHF14AMfESave(const char *Cmd) {

    char filename[FILE_PATH_SIZE];
    char *fnameptr = filename;
    uint8_t *dump;
    int len, bytes, nameParamNo = 1;
    uint16_t blocks;

    memset(filename, 0, sizeof(filename));

    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h') return usage_hf14_esave();

    blocks = NumOfBlocks(c);
    bytes = blocks * MFBLOCK_SIZE;

    dump = calloc(bytes, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 1;
    }
    memset(dump, 0, bytes);

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return 2;
    }

    len = param_getstr(Cmd, nameParamNo, filename, sizeof(filename));
    if (len > FILE_PATH_SIZE - 5) len = FILE_PATH_SIZE - 5;

    // user supplied filename?
    if (len < 1) {
        fnameptr += sprintf(fnameptr, "hf-mf-");
        FillFileNameByUID(fnameptr, dump, "-dump", 4);
    }

    saveFile(filename, "bin", dump, bytes);
    saveFileEML(filename, "eml", dump, bytes, MFBLOCK_SIZE);
    saveFileJSON(filename, "json", jsfCardMemory, dump, bytes);
    free(dump);
    return 0;
}

int CmdHF14AMfECFill(const char *Cmd) {
    uint8_t keyType = 0;
    uint8_t numSectors = 16;
    char c = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 1 || c == 'h')
        return usage_hf14_ecfill();

    if (c != 'a' &&  c != 'b') {
        PrintAndLogEx(WARNING, "Key type must be A or B");
        return 1;
    }
    if (c != 'a')
        keyType = 1;

    c = tolower(param_getchar(Cmd, 1));
    numSectors = NumOfSectors(c);

    PrintAndLogEx(NORMAL, "--params: numSectors: %d, keyType: %c\n", numSectors, (keyType == 0) ? 'A' : 'B');
    UsbCommand cmd = {CMD_MIFARE_EML_CARDLOAD, {numSectors, keyType, 0}};
    clearCommandBuffer();
    SendCommand(&cmd);
    return 0;
}

int CmdHF14AMfEKeyPrn(const char *Cmd) {
    int i;
    uint8_t numSectors;
    uint8_t data[16];
    uint64_t keyA, keyB;

    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h')
        return usage_hf14_ekeyprn();

    numSectors = NumOfSectors(c);

    PrintAndLogEx(NORMAL, "|---|----------------|----------------|");
    PrintAndLogEx(NORMAL, "|sec|key A           |key B           |");
    PrintAndLogEx(NORMAL, "|---|----------------|----------------|");
    for (i = 0; i < numSectors; i++) {
        if (mfEmlGetMem(data, FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1, 1)) {
            PrintAndLogEx(WARNING, "error get block %d", FirstBlockOfSector(i) + NumBlocksPerSector(i) - 1);
            break;
        }
        keyA = bytes_to_num(data, 6);
        keyB = bytes_to_num(data + 10, 6);
        PrintAndLogEx(NORMAL, "|%03d|  %012" PRIx64 "  |  %012" PRIx64 "  |", i, keyA, keyB);
    }
    PrintAndLogEx(NORMAL, "|---|----------------|----------------|");
    return 0;
}

// CHINESE MAGIC COMMANDS
int CmdHF14AMfCSetUID(const char *Cmd) {
    uint8_t wipeCard = 0;
    uint8_t uid[8] = {0x00};
    uint8_t oldUid[8] = {0x00};
    uint8_t atqa[2] = {0x00};
    uint8_t sak[1] = {0x00};
    uint8_t atqaPresent = 1;
    int res, argi = 0;
    char ctmp;

    if (strlen(Cmd) < 1 || param_getchar(Cmd, argi) == 'h')
        return usage_hf14_csetuid();

    if (param_getchar(Cmd, argi) && param_gethex(Cmd, argi, uid, 8))
        return usage_hf14_csetuid();

    argi++;

    ctmp = tolower(param_getchar(Cmd, argi));
    if (ctmp == 'w') {
        wipeCard = 1;
        atqaPresent = 0;
    }

    if (atqaPresent) {
        if (param_getchar(Cmd, argi)) {
            if (param_gethex(Cmd, argi, atqa, 4)) {
                PrintAndLogEx(WARNING, "ATQA must include 4 HEX symbols");
                return 1;
            }
            argi++;
            if (!param_getchar(Cmd, argi) || param_gethex(Cmd, argi, sak, 2)) {
                PrintAndLogEx(WARNING, "SAK must include 2 HEX symbols");
                return 1;
            }
            argi++;
        } else
            atqaPresent = 0;
    }

    if (!wipeCard) {
        ctmp = tolower(param_getchar(Cmd, argi));
        if (ctmp == 'w') {
            wipeCard = 1;
        }
    }

    PrintAndLogEx(NORMAL, "--wipe card:%s  uid:%s", (wipeCard) ? "YES" : "NO", sprint_hex(uid, 4));

    res = mfCSetUID(uid, (atqaPresent) ? atqa : NULL, (atqaPresent) ? sak : NULL, oldUid, wipeCard);
    if (res) {
        PrintAndLogEx(WARNING, "Can't set UID. error=%d", res);
        return 1;
    }

    PrintAndLogEx(SUCCESS, "old UID:%s", sprint_hex(oldUid, 4));
    PrintAndLogEx(SUCCESS, "new UID:%s", sprint_hex(uid, 4));
    return 0;
}

int CmdHF14AMfCSetBlk(const char *Cmd) {
    uint8_t block[16] = {0x00};
    uint8_t blockNo = 0;
    uint8_t params = MAGIC_SINGLE;
    int res;
    char ctmp = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_csetblk();

    blockNo = param_get8(Cmd, 0);

    if (param_gethex(Cmd, 1, block, 32)) return usage_hf14_csetblk();

    ctmp = tolower(param_getchar(Cmd, 2));
    if (ctmp == 'w')
        params |= MAGIC_WIPE;

    PrintAndLogEx(NORMAL, "--block number:%2d data:%s", blockNo, sprint_hex(block, 16));

    res = mfCSetBlock(blockNo, block, NULL, params);
    if (res) {
        PrintAndLogEx(WARNING, "Can't write block. error=%d", res);
        return 1;
    }
    return 0;
}

int CmdHF14AMfCLoad(const char *Cmd) {

    uint8_t buf8[16] = {0x00};
    uint8_t fillFromEmulator = 0;
    int blockNum, flags = 0;
    bool fillFromJson = false;
    bool fillFromBin = false;
    char fileName[50] = {0};

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (param_getlength(Cmd, 0) == 1) {
        if (ctmp == 'h' || ctmp == 0x00) return usage_hf14_cload();
        if (ctmp == 'e') fillFromEmulator = 1;
        if (ctmp == 'j') fillFromJson = true;
        if (ctmp == 'b') fillFromBin = true;
    }

    if (fillFromJson || fillFromBin)
        param_getstr(Cmd, 1, fileName, sizeof(fileName));


    if (fillFromEmulator) {
        for (blockNum = 0; blockNum < 16 * 4; blockNum += 1) {
            if (mfEmlGetMem(buf8, blockNum, 1)) {
                PrintAndLogEx(WARNING, "Cant get block: %d", blockNum);
                return 2;
            }
            if (blockNum == 0) flags = MAGIC_INIT + MAGIC_WUPC;             // switch on field and send magic sequence
            if (blockNum == 1) flags = 0;                                   // just write
            if (blockNum == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;     // Done. Magic Halt and switch off field.

            if (mfCSetBlock(blockNum, buf8, NULL, flags)) {
                PrintAndLogEx(WARNING, "Cant set magic card block: %d", blockNum);
                return 3;
            }
            printf(".");
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, "\n");
        return 0;
    }

    size_t maxdatalen = 4096;
    uint8_t *data = calloc(maxdatalen, sizeof(uint8_t));
    size_t datalen = 0;
    int res = 0;
    if (fillFromBin) {
        res = loadFile(fileName, "bin", data, maxdatalen, &datalen);
    } else {
        if (fillFromJson) {
            res = loadFileJSON(fileName, "json", data, maxdatalen, &datalen);
        } else {
            res = loadFileEML(Cmd, "eml", data, &datalen);
        }
    }

    if (res) {
        if (data)
            free(data);
        return 1;
    }

//  PrintAndLogEx(INFO, "DATA | %s", sprint_hex(data+1000, 24) );


    // 64 or 256blocks.
    if (datalen != 1024 && datalen != 4096) {
        PrintAndLogEx(WARNING, "File content error. ");
        free(data);
        return 2;
    }

    PrintAndLogEx(INFO, "Copying to magic card");

    blockNum = 0;
    while (datalen) {

        // switch on field and send magic sequence
        if (blockNum == 0) flags = MAGIC_INIT + MAGIC_WUPC;

        // write
        if (blockNum == 1) flags = 0;

        // Switch off field.
        if (blockNum == 16 * 4 - 1) flags = MAGIC_HALT + MAGIC_OFF;

        if (mfCSetBlock(blockNum, data + (16 * blockNum), NULL, flags)) {
            PrintAndLogEx(WARNING, "Can't set magic card block: %d", blockNum);
            free(data);
            return 3;
        }

        datalen -= 16;

        printf(".");
        fflush(stdout);
        blockNum++;

        // magic card type - mifare 1K
        if (blockNum >= MIFARE_1K_MAXBLOCK) break;
    }
    PrintAndLogEx(NORMAL, "\n");

    // 64 or 256blocks.
    if (blockNum != 16 * 4 && blockNum != 32 * 4 + 8 * 16) {
        PrintAndLogEx(WARNING, "File content error. There must be 64 blocks");
        free(data);
        return 4;
    }

    PrintAndLogEx(SUCCESS, "Card loaded %d blocks from file", blockNum);
    free(data);
    return 0;
}

int CmdHF14AMfCGetBlk(const char *Cmd) {
    uint8_t data[16] = {0};
    uint8_t blockNo = 0;
    int res;
    memset(data, 0x00, sizeof(data));

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_cgetblk();

    blockNo = param_get8(Cmd, 0);

    PrintAndLogEx(NORMAL, "--block number:%2d ", blockNo);

    res = mfCGetBlock(blockNo, data, MAGIC_SINGLE);
    if (res) {
        PrintAndLogEx(WARNING, "Can't read block. error=%d", res);
        return 1;
    }

    PrintAndLogEx(NORMAL, "data: %s", sprint_hex(data, sizeof(data)));

    if (mfIsSectorTrailer(blockNo)) {
        PrintAndLogEx(NORMAL, "Trailer decoded:");
        PrintAndLogEx(NORMAL, "Key A: %s", sprint_hex_inrow(data, 6));
        PrintAndLogEx(NORMAL, "Key B: %s", sprint_hex_inrow(&data[10], 6));
        int bln = mfFirstBlockOfSector(mfSectorNum(blockNo));
        int blinc = (mfNumBlocksPerSector(mfSectorNum(blockNo)) > 4) ? 5 : 1;
        for (int i = 0; i < 4; i++) {
            PrintAndLogEx(NORMAL, "Access block %d%s: %s", bln, ((blinc > 1) && (i < 3) ? "+" : ""), mfGetAccessConditionsDesc(i, &data[6]));
            bln += blinc;
        }
        PrintAndLogEx(NORMAL, "UserData: %s", sprint_hex_inrow(&data[9], 1));
    }

    return 0;
}

int CmdHF14AMfCGetSc(const char *Cmd) {
    uint8_t data[16] = {0};
    uint8_t sector = 0;
    int i, res, flags;

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_cgetsc();

    sector = param_get8(Cmd, 0);
    if (sector > 39) {
        PrintAndLogEx(WARNING, "Sector number must be less then 40");
        return 1;
    }

    PrintAndLogEx(NORMAL, "\n  # | data    |  Sector | %02d/ 0x%02X ", sector, sector);
    PrintAndLogEx(NORMAL, "----+------------------------------------------------");
    uint8_t blocks = 4;
    uint8_t start = sector * 4;
    if (sector > 32) {
        blocks = 16;
        start = 128 + (sector - 32) * 16;
    }

    flags = MAGIC_INIT + MAGIC_WUPC;

    for (i = 0; i < blocks; i++) {
        if (i == 1) flags = 0;
        if (i == blocks - 1) flags = MAGIC_HALT + MAGIC_OFF;

        res = mfCGetBlock(start + i, data, flags);
        if (res) {
            PrintAndLogEx(WARNING, "Can't read block. %d error=%d", start + i, res);
            return 1;
        }
        PrintAndLogEx(NORMAL, "%3d | %s", start + i, sprint_hex(data, 16));
    }
    return 0;
}

int CmdHF14AMfCSave(const char *Cmd) {

    char filename[FILE_PATH_SIZE];
    char *fnameptr = filename;
    uint8_t *dump;
    bool fillEmulator = false;
    bool errors = false, hasname = false, useuid = false;
    int i, len, flags;
    uint8_t numblocks = 0, cmdp = 0;
    uint16_t bytes = 0;
    char ctmp;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        ctmp = tolower(param_getchar(Cmd, cmdp));
        switch (ctmp) {
            case 'e':
                useuid = true;
                fillEmulator = true;
                cmdp++;
                break;
            case 'h':
                return usage_hf14_csave();
            case '0':
            case '1':
            case '2':
            case '4':
                numblocks = NumOfBlocks(ctmp);
                bytes =  numblocks * MFBLOCK_SIZE;
                PrintAndLogEx(SUCCESS, "Saving magic mifare %cK", ctmp);
                cmdp++;
                break;
            case 'u':
                useuid = true;
                hasname = true;
                cmdp++;
                break;
            case 'o':
                len = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (len < 1) {
                    errors = true;
                    break;
                }

                useuid = false;
                hasname = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (!hasname && !fillEmulator) errors = true;

    if (errors || cmdp == 0) return usage_hf14_csave();

    dump = calloc(bytes, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return 1;
    }
    memset(dump, 0, bytes);

    flags = MAGIC_INIT + MAGIC_WUPC;
    for (i = 0; i < numblocks; i++) {
        if (i == 1) flags = 0;
        if (i == numblocks - 1) flags = MAGIC_HALT + MAGIC_OFF;

        if (mfCGetBlock(i, dump + (i * MFBLOCK_SIZE), flags)) {
            PrintAndLogEx(WARNING, "Cant get block: %d", i);
            free(dump);
            return 2;
        }
    }

    if (useuid) {
        fnameptr += sprintf(fnameptr, "hf-mf-");
        FillFileNameByUID(fnameptr, dump, "-dump", 4);
    }

    if (fillEmulator) {
        PrintAndLogEx(INFO, "uploading to emulator memory");
        for (i = 0; i < numblocks; i += 5) {
            if (mfEmlSetMem(dump + (i * MFBLOCK_SIZE), i, 5)) {
                PrintAndLogEx(WARNING, "Cant set emul block: %d", i);
            }
            printf(".");
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, "\n");
        PrintAndLogEx(SUCCESS, "uploaded %d bytes to emulator memory", bytes);
    }

    saveFile(filename, "bin", dump, bytes);
    saveFileEML(filename, "eml", dump, bytes, MFBLOCK_SIZE);
    saveFileJSON(filename, "json", jsfCardMemory, dump, bytes);
    free(dump);
    return 0;
}

//needs nt, ar, at, Data to decrypt
int CmdHf14AMfDecryptBytes(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_hf14_decryptbytes();

    uint32_t nt     = param_get32ex(Cmd, 0, 0, 16);
    uint32_t ar_enc = param_get32ex(Cmd, 1, 0, 16);
    uint32_t at_enc = param_get32ex(Cmd, 2, 0, 16);

    int len = param_getlength(Cmd, 3);
    if (len & 1) {
        PrintAndLogEx(WARNING, "Uneven hex string length. LEN=%d", len);
        return 1;
    }

    PrintAndLogEx(NORMAL, "nt\t%08X", nt);
    PrintAndLogEx(NORMAL, "ar enc\t%08X", ar_enc);
    PrintAndLogEx(NORMAL, "at enc\t%08X", at_enc);

    uint8_t *data = calloc(len, sizeof(uint8_t));
    param_gethex_ex(Cmd, 3, data, &len);
    len >>= 1;
    tryDecryptWord(nt, ar_enc, at_enc, data, len);
    free(data);
    return 0;
}

int CmdHf14AMfSetMod(const char *Cmd) {
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint8_t mod = 2;

    char ctmp = param_getchar(Cmd, 0);
    if (ctmp == '0') {
        mod = 0;
    } else if (ctmp == '1') {
        mod = 1;
    }
    int gethexfail = param_gethex(Cmd, 1, key, 12);
    if (mod == 2 || gethexfail) {
        PrintAndLogEx(NORMAL, "Sets the load modulation strength of a MIFARE Classic EV1 card.");
        PrintAndLogEx(NORMAL, "Usage: hf mf setmod <0|1> <block 0 key A>");
        PrintAndLogEx(NORMAL, "       0 = normal modulation");
        PrintAndLogEx(NORMAL, "       1 = strong modulation (default)");
        return 1;
    }

    UsbCommand c = {CMD_MIFARE_SETMOD, {mod, 0, 0}};
    memcpy(c.d.asBytes, key, 6);
    clearCommandBuffer();
    SendCommand(&c);

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t ok = resp.arg[0] & 0xff;
        PrintAndLogEx(SUCCESS, "isOk:%02x", ok);
        if (!ok)
            PrintAndLogEx(FAILED, "Failed.");
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
    return 0;
}

// Mifare NACK bug detection
int CmdHf14AMfNack(const char *Cmd) {

    bool verbose = false;
    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_hf14_nack();
    if (ctmp == 'v') verbose = true;

    if (verbose)
        PrintAndLogEx(INFO, "Started testing card for NACK bug. Press key to abort");

    detect_classic_nackbug(verbose);
    return 0;
}

int CmdHF14AMfice(const char *Cmd) {

    uint8_t blockNo = 0;
    uint8_t keyType = 0;
    uint8_t trgBlockNo = 0;
    uint8_t trgKeyType = 1;
    bool slow = false;
    bool initialize = true;
    bool acquisition_completed = false;
    uint8_t cmdp = 0;
    uint32_t flags = 0;
    uint32_t total_num_nonces = 0;
    char ctmp;
    char filename[FILE_PATH_SIZE], *fptr;
    FILE *fnonces = NULL;
    UsbCommand resp;

    uint32_t part_limit = 3000;
    uint32_t limit = 50000;

    while ((ctmp = param_getchar(Cmd, cmdp))) {
        switch (tolower(ctmp)) {
            case 'h':
                return usage_hf14_ice();
            case 'f':
                param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp++;
                break;
            case 'l':
                limit = param_get32ex(Cmd, cmdp + 1, 50000, 10);
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", ctmp);
                usage_hf14_ice();
                return 1;
        }
        cmdp++;
    }

    if (filename[0] == '\0') {
        fptr = GenerateFilename("hf-mf-", "-nonces.bin");
        if (fptr == NULL)
            return 1;
        strcpy(filename, fptr);
    }

    PrintAndLogEx(NORMAL, "Collecting %u nonces \n", limit);

    if ((fnonces = fopen(filename, "wb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), filename);
        return 3;
    }

    clearCommandBuffer();

    uint64_t t1 = msclock();

    do {
        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(INFO, "\naborted via keyboard!\n");
            break;
        }

        flags = 0;
        flags |= initialize ? 0x0001 : 0;
        flags |= slow ? 0x0002 : 0;
        UsbCommand c = {CMD_MIFARE_ACQUIRE_NONCES, {blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, flags}};
        clearCommandBuffer();
        SendCommand(&c);

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) goto out;
        if (resp.arg[0])  goto out;

        uint32_t items = resp.arg[2];
        if (fnonces) {
            fwrite(resp.d.asBytes, 1, items * 4, fnonces);
            fflush(fnonces);
        }

        total_num_nonces += items;
        if (total_num_nonces > part_limit) {
            PrintAndLogEx(INFO, "Total nonces %u\n", total_num_nonces);
            part_limit += 3000;
        }

        acquisition_completed = (total_num_nonces > limit);

        initialize = false;

    } while (!acquisition_completed);

out:
    PrintAndLogEx(SUCCESS, "time: %" PRIu64 " seconds\n", (msclock() - t1) / 1000);

    if (fnonces) {
        fflush(fnonces);
        fclose(fnonces);
    }

    UsbCommand c = {CMD_MIFARE_ACQUIRE_NONCES, {blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, 4}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHF14AMfAuth4(const char *Cmd) {
    uint8_t keyn[20] = {0};
    int keynlen = 0;
    uint8_t key[16] = {0};
    int keylen = 0;

    CLIParserInit("hf mf auth4",
                  "Executes AES authentication command in ISO14443-4",
                  "Usage:\n\thf mf auth4 4000 000102030405060708090a0b0c0d0e0f -> executes authentication\n"
                  "\thf mf auth4 9003 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -> executes authentication\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL,  NULL,     "<Key Num (HEX 2 bytes)>", NULL),
        arg_str1(NULL,  NULL,     "<Key Value (HEX 16 bytes)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    CLIGetHexWithReturn(1, keyn, &keynlen);
    CLIGetHexWithReturn(2, key, &keylen);
    CLIParserFree();

    if (keynlen != 2) {
        PrintAndLogEx(ERR, "<Key Num> must be 2 bytes long instead of: %d", keynlen);
        return 1;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<Key Value> must be 16 bytes long instead of: %d", keylen);
        return 1;
    }

    return MifareAuth4(NULL, keyn, key, true, false, true);
}

// https://www.nxp.com/docs/en/application-note/AN10787.pdf
int CmdHF14AMfMAD(const char *Cmd) {

    CLIParserInit("hf mf mad",
                  "Checks and prints Mifare Application Directory (MAD)",
                  "Usage:\n\thf mf mad -> shows MAD if exists\n"
                  "\thf mf mad -a 03e1 -k ffffffffffff -b -> shows NDEF data if exists. read card with custom key and key B\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose",  "show technical data"),
        arg_str0("aA",  "aid",      "print all sectors with aid", NULL),
        arg_str0("kK",  "key",      "key for printing sectors", NULL),
        arg_lit0("bB",  "keyb",     "use key B for access printing sectors (by default: key A)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);
    bool verbose = arg_get_lit(1);
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(2, aid, &aidlen);
    uint8_t key[6] = {0};
    int keylen;
    CLIGetHexWithReturn(3, key, &keylen);
    bool keyB = arg_get_lit(4);

    CLIParserFree();

    if (aidlen != 2 && keylen > 0) {
        PrintAndLogEx(WARNING, "do not need a key without aid.");
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};
    if (mfReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector0)) {
        PrintAndLogEx(ERR, "read sector 0 error. card don't have MAD or don't have MAD on default keys.");
        return 2;
    }

    if (verbose) {
        for (int i = 0; i < 4; i ++)
            PrintAndLogEx(NORMAL, "[%d] %s", i, sprint_hex(&sector0[i * 16], 16));
    }

    bool haveMAD2 = false;
    MAD1DecodeAndPrint(sector0, verbose, &haveMAD2);

    if (haveMAD2) {
        if (mfReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector10)) {
            PrintAndLogEx(ERR, "read sector 0x10 error. card don't have MAD or don't have MAD on default keys.");
            return 2;
        }

        MAD2DecodeAndPrint(sector10, verbose);
    }

    if (aidlen == 2) {
        uint16_t aaid = (aid[0] << 8) + aid[1];
        PrintAndLogEx(NORMAL, "\n-------------- AID 0x%04x ---------------", aaid);

        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        if (MADDecode(sector0, sector10, mad, &madlen)) {
            PrintAndLogEx(ERR, "can't decode mad.");
            return 10;
        }

        uint8_t akey[6] = {0};
        memcpy(akey, g_mifare_ndef_key, 6);
        if (keylen == 6) {
            memcpy(akey, key, 6);
        }

        for (int i = 0; i < madlen; i++) {
            if (aaid == mad[i]) {
                uint8_t vsector[16 * 4] = {0};
                if (mfReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector)) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(ERR, "read sector %d error.", i + 1);
                    return 2;
                }

                for (int j = 0; j < (verbose ? 4 : 3); j ++)
                    PrintAndLogEx(NORMAL, " [%03d] %s", (i + 1) * 4 + j, sprint_hex(&vsector[j * 16], 16));
            }
        }
    }

    return 0;
}

int CmdHFMFNDEF(const char *Cmd) {

    CLIParserInit("hf mf ndef",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "Usage:\n\thf mf ndef -> shows NDEF data\n"
                  "\thf mf ndef -a 03e1 -k ffffffffffff -b -> shows NDEF data with custom AID, key and with key B\n");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("vV",  "verbose",  0, 2, "show technical data"),
        arg_str0("aA",  "aid",      "replace default aid for NDEF", NULL),
        arg_str0("kK",  "key",      "replace default key for NDEF", NULL),
        arg_lit0("bB",  "keyb",     "use key B for access sectors (by default: key A)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    bool verbose2 = arg_get_lit(1) > 1;
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(2, aid, &aidlen);
    uint8_t key[6] = {0};
    int keylen;
    CLIGetHexWithReturn(3, key, &keylen);
    bool keyB = arg_get_lit(4);

    CLIParserFree();

    uint16_t ndefAID = 0x03e1;
    if (aidlen == 2)
        ndefAID = (aid[0] << 8) + aid[1];

    uint8_t ndefkey[6] = {0};
    memcpy(ndefkey, g_mifare_ndef_key, 6);
    if (keylen == 6) {
        memcpy(ndefkey, key, 6);
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};
    uint8_t data[4096] = {0};
    int datalen = 0;

    PrintAndLogEx(NORMAL, "");

    if (mfReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector0)) {
        PrintAndLogEx(ERR, "read sector 0 error. card don't have MAD or don't have MAD on default keys.");
        return 2;
    }

    bool haveMAD2 = false;
    int res = MADCheck(sector0, NULL, verbose, &haveMAD2);
    if (res) {
        PrintAndLogEx(ERR, "MAD error %d.", res);
        return res;
    }

    if (haveMAD2) {
        if (mfReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector10)) {
            PrintAndLogEx(ERR, "read sector 0x10 error. card don't have MAD or don't have MAD on default keys.");
            return 2;
        }
    }

    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    if (MADDecode(sector0, (haveMAD2 ? sector10 : NULL), mad, &madlen)) {
        PrintAndLogEx(ERR, "can't decode mad.");
        return 10;
    }

    printf("data reading:");
    for (int i = 0; i < madlen; i++) {
        if (ndefAID == mad[i]) {
            uint8_t vsector[16 * 4] = {0};
            if (mfReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, ndefkey, vsector)) {
                PrintAndLogEx(ERR, "read sector %d error.", i + 1);
                return 2;
            }

            memcpy(&data[datalen], vsector, 16 * 3);
            datalen += 16 * 3;

            printf(".");
        }
    }
    printf(" OK\n");

    if (!datalen) {
        PrintAndLogEx(ERR, "no NDEF data.");
        return 11;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "NDEF data:");
        dump_buffer(data, datalen, stdout, 1);
    }

    NDEFDecodeAndPrint(data, datalen, verbose);

    return 0;
}

int CmdHF14AMfList(const char *Cmd) {
    CmdTraceList("mf");
    return 0;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                1, "This help"},
    {"list",        CmdHF14AMfList,         0, "[Deprecated] List ISO 14443-a / Mifare history"},
    {"darkside",    CmdHF14AMfDarkside,     0, "Darkside attack. read parity error messages."},
    {"nested",      CmdHF14AMfNested,       0, "Nested attack. Test nested authentication"},
    {"hardnested",  CmdHF14AMfNestedHard,   0, "Nested attack for hardened Mifare cards"},
    {"keybrute",    CmdHF14AMfKeyBrute,     0, "J_Run's 2nd phase of multiple sector nested authentication key recovery"},
    {"nack",        CmdHf14AMfNack,         0, "Test for Mifare NACK bug"},
    {"chk",         CmdHF14AMfChk,          0, "Check keys"},
    {"fchk",        CmdHF14AMfChk_fast,     0, "Check keys fast, targets all keys on card"},
    {"decrypt",     CmdHf14AMfDecryptBytes, 1, "[nt] [ar_enc] [at_enc] [data] - to decrypt sniff or trace"},
    {"-----------", CmdHelp,                1, ""},
    {"dbg",         CmdHF14AMfDbg,          0, "Set default debug mode"},
    {"rdbl",        CmdHF14AMfRdBl,         0, "Read MIFARE classic block"},
    {"rdsc",        CmdHF14AMfRdSc,         0, "Read MIFARE classic sector"},
    {"dump",        CmdHF14AMfDump,         0, "Dump MIFARE classic tag to binary file"},
    {"restore",     CmdHF14AMfRestore,      0, "Restore MIFARE classic binary file to BLANK tag"},
    {"wrbl",        CmdHF14AMfWrBl,         0, "Write MIFARE classic block"},
    {"setmod",      CmdHf14AMfSetMod,       0, "Set MIFARE Classic EV1 load modulation strength"},
    {"auth4",       CmdHF14AMfAuth4,        0, "ISO14443-4 AES authentication"},
//    {"sniff",       CmdHF14AMfSniff,        0, "Sniff card-reader communication"},
    {"-----------", CmdHelp,                1, ""},
    {"sim",         CmdHF14AMf1kSim,        0, "Simulate MIFARE card"},
    {"eclr",        CmdHF14AMfEClear,       0, "Clear simulator memory block"},
    {"eget",        CmdHF14AMfEGet,         0, "Get simulator memory block"},
    {"eset",        CmdHF14AMfESet,         0, "Set simulator memory block"},
    {"eload",       CmdHF14AMfELoad,        0, "Load from file emul dump"},
    {"esave",       CmdHF14AMfESave,        0, "Save to file emul dump"},
    {"ecfill",      CmdHF14AMfECFill,       0, "Fill simulator memory with help of keys from simulator"},
    {"ekeyprn",     CmdHF14AMfEKeyPrn,      0, "Print keys from simulator memory"},
    {"-----------", CmdHelp,                1, ""},
    {"csetuid",     CmdHF14AMfCSetUID,      0, "Set UID for magic Chinese card"},
    {"csetblk",     CmdHF14AMfCSetBlk,      0, "Write block - Magic Chinese card"},
    {"cgetblk",     CmdHF14AMfCGetBlk,      0, "Read block - Magic Chinese card"},
    {"cgetsc",      CmdHF14AMfCGetSc,       0, "Read sector - Magic Chinese card"},
    {"cload",       CmdHF14AMfCLoad,        0, "Load dump into magic Chinese card"},
    {"csave",       CmdHF14AMfCSave,        0, "Save dump from magic Chinese card into file or emulator"},
    {"-----------", CmdHelp,                1, ""},
    {"mad",         CmdHF14AMfMAD,          0, "Checks and prints MAD"},
    {"ndef",        CmdHFMFNDEF,            0, "Prints NDEF records from card"},

    {"ice",         CmdHF14AMfice,          0, "collect Mifare Classic nonces to file"},
    {NULL, NULL, 0, NULL}
};

int CmdHFMF(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
