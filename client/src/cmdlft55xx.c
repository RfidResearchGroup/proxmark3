//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

// ensure localtime_r is available even with -std=c99; must be included before
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif

#include "cmdlft55xx.h"

#include <ctype.h>
#include <time.h> // MingW

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "protocols.h"
#include "proxgui.h"
#include "graph.h"
#include "cmddata.h"
#include "lfdemod.h"
#include "cmdhf14a.h"   // for getTagInfo
#include "fileutils.h"  // loadDictionary
#include "util_posix.h"

// Some defines for readability
#define T55XX_DLMODE_FIXED         0 // Default Mode
#define T55XX_DLMODE_LLR           1 // Long Leading Reference
#define T55XX_DLMODE_LEADING_ZERO  2 // Leading Zero
#define T55XX_DLMODE_1OF4          3 // 1 of 4
// #define T55XX_LONGLEADINGREFERENCE 4 // Value to tell Write Bit to send long reference
#define T55XX_DLMODE_ALL           4 // Tell help to show 'r 4' for all dl modes
#define T55XX_DLMODE_SINGLE        5 // Tell help file NOT to show 'r 4' (not available)

#define T55XX_PrintConfig           true
#define T55XX_DontPrintConfig       false

//static uint8_t bit_rates[9] = {8, 16, 32, 40, 50, 64, 100, 128, 0};

// Default configuration
t55xx_conf_block_t config = {
    .modulation = DEMOD_ASK,
    .inverted = false,
    .offset = 0x00,
    .block0 = 0x00,
    .Q5 = false,
    .usepwd = false,
    .downlink_mode = refFixedBit
};

static t55xx_memory_item_t cardmem[T55x7_BLOCK_COUNT] = {{0}};

t55xx_conf_block_t Get_t55xx_Config(void) {
    return config;
}

void Set_t55xx_Config(t55xx_conf_block_t conf) {
    config = conf;
}

static void print_usage_t55xx_downloadlink(uint8_t ShowAll, uint8_t dl_mode_default) {
    if (ShowAll == T55XX_DLMODE_ALL)
        PrintAndLogEx(NORMAL, "     r <mode>     - downlink encoding 0|1|2|3|4");
    else
        PrintAndLogEx(NORMAL, "     r <mode>     - downlink encoding 0|1|2|3");
    PrintAndLogEx(NORMAL, "                       0 - fixed bit length%s", (dl_mode_default == 0) ? " (detected default)" : ""); // default will be whats in config struct
    PrintAndLogEx(NORMAL, "                       1 - long leading reference%s", (dl_mode_default == 1) ? " (detected default)" : "");
    PrintAndLogEx(NORMAL, "                       2 - leading zero%s", (dl_mode_default == 2) ? " (detected default)" : "");
    PrintAndLogEx(NORMAL, "                       3 - 1 of 4 coding reference%s", (dl_mode_default == 3) ? " (detected default)" : "");
    if (ShowAll == T55XX_DLMODE_ALL)
        PrintAndLogEx(NORMAL, "                       4 - Try all downlink modes%s", (dl_mode_default == 4) ? " (default)" : "");
}

static int usage_t55xx_config(void) {
    PrintAndLogEx(NORMAL, "Usage: lf t55xx config [c <blk0>] [d <demodulation>] [i [0/1]] [o <offset>] [Q5 [0/1]] [ST [0/1]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h                                - This help");
    PrintAndLogEx(NORMAL, "     c <block0>                       - set configuration from a block0");
    PrintAndLogEx(NORMAL, "     b <8|16|32|40|50|64|100|128>     - Set bitrate");
    PrintAndLogEx(NORMAL, "     d <FSK|FSK1|FSK1a|FSK2|FSK2a|ASK|PSK1|PSK2|NRZ|BI|BIa>  - Set demodulation FSK / ASK / PSK / NRZ / Biphase / Biphase A");
    PrintAndLogEx(NORMAL, "     i [0/1]                          - Set/reset data signal inversion");
    PrintAndLogEx(NORMAL, "     o [offset]                       - Set offset, where data should start decode in bitstream");
    PrintAndLogEx(NORMAL, "     Q5 [0/1]                         - Set/reset as T5555 ( Q5 ) chip instead of T55x7");
    PrintAndLogEx(NORMAL, "     ST [0/1]                         - Set/reset Sequence Terminator on");
    PrintAndLogEx(NORMAL, ""); // layout is a little differnet, so seperate until a better fix
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK          - FSK demodulation");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK i 1      - FSK demodulation, inverse data");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK i 1 o 3  - FSK demodulation, inverse data, offset=3,start from position 3 to decode data");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_read(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx read [r <mode>] b <block> [p <password>] [o] <page1>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     b <block>    - block number to read. Between 0-7");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password (8 hex characters)");
    PrintAndLogEx(NORMAL, "     o            - OPTIONAL override safety check");
    PrintAndLogEx(NORMAL, "     1            - OPTIONAL 0|1  read Page 1 instead of Page 0");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "     " _RED_("**** WARNING ****"));
    PrintAndLogEx(NORMAL, "     Use of read with password on a tag not configured");
    PrintAndLogEx(NORMAL, "     for a password can damage the tag");
    PrintAndLogEx(NORMAL, "     " _RED_("*****************"));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0                 - read data from block 0");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0 p feedbeef      - read data from block 0 password feedbeef");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0 p feedbeef o    - read data from block 0 password feedbeef safety check");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_resetread(void) {
    PrintAndLogEx(NORMAL, "Send Reset Cmd then lf read the stream to attempt to identify the start of it (needs a demod and/or plot after)");
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx resetread [r <mode>]");
    PrintAndLogEx(NORMAL, "Options:");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx resetread");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_write(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx write [r <mode>] b <block> d <data> [p <password>] [1] [t] [v]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     b <block>    - block number to write. Between 0-7");
    PrintAndLogEx(NORMAL, "     d <data>     - 4 bytes of data to write (8 hex characters)");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password 4bytes (8 hex characters)");
    PrintAndLogEx(NORMAL, "     1            - OPTIONAL write Page 1 instead of Page 0");
    PrintAndLogEx(NORMAL, "     t            - OPTIONAL test mode write - ****DANGER****");
    PrintAndLogEx(NORMAL, "     v            - OPTIONAL validate data afterwards");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx write b 3 d 11223344            - write 11223344 to block 3");
    PrintAndLogEx(NORMAL, "      lf t55xx write b 3 d 11223344 p feedbeef - write 11223344 to block 3 password feedbeef");
    PrintAndLogEx(NORMAL, "      lf t55xx write b 3 d 11223344 v          - write 11223344 to block 3 and try to validate data");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_trace(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx trace [1] [r mode]");
    PrintAndLogEx(NORMAL, "Options:");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx trace");
    PrintAndLogEx(NORMAL, "      lf t55xx trace 1");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_info(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx info [1] [r <mode>] [c <blk0> [q]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     (default)    - read data from tag.");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password 4bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer instead of reading tag.");
    PrintAndLogEx(NORMAL, "     c <block0>   - set configuration from a block0");
    PrintAndLogEx(NORMAL, "                    if set, use these data instead of reading tag.");
    PrintAndLogEx(NORMAL, "     q            - if set, provided data are interpreted as Q5 config.");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx info");
    PrintAndLogEx(NORMAL, "      lf t55xx info 1");
    PrintAndLogEx(NORMAL, "      lf t55xx info d 00083040");
    PrintAndLogEx(NORMAL, "      lf t55xx info d 6001805A q");
    PrintAndLogEx(NORMAL, "      lf t55xx info p 11223344");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx dump [r <mode>] [p <password> [o]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password 4bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "     o            - OPTIONAL override, force pwd read despite danger to card");
    PrintAndLogEx(NORMAL, "     f <prefix>   - overide filename prefix (optional).  Default is based on blk 0");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx dump");
    PrintAndLogEx(NORMAL, "      lf t55xx dump p feedbeef o");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_restore(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx restore f <filename> [p password]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     f <filename> - filename of the dump file (.bin/.eml)");
    PrintAndLogEx(NORMAL, "     p <password> - optional password if target card has password set");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, _YELLOW_("     Assumes lf t55 detect has been run first!"));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx restore f lf-t55xx-00148040-dump.bin");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int usage_t55xx_detect(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx detect [1] [r <mode>] [p <password>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "     p <password  - OPTIONAL password (8 hex characters)");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx detect");
    PrintAndLogEx(NORMAL, "      lf t55xx detect 1");
    PrintAndLogEx(NORMAL, "      lf t55xx detect p 11223344");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_detectP1(void) {
    PrintAndLogEx(NORMAL, "Command: Detect Page 1 of a t55xx chip");
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx p1detect [1] [r <mode>] [p <password>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password (8 hex characters)");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode); // Need to setup to try all modes
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect 1");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect p 11223344");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_wakup(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx wakeup [h] [r <mode>] p <password>");
    PrintAndLogEx(NORMAL, "This commands sends the Answer-On-Request command and leaves the readerfield ON afterwards.");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    PrintAndLogEx(NORMAL, "     p <password> - password 4bytes (8 hex symbols)");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx wakeup p 11223344  - send wakeup password");
    return PM3_SUCCESS;
}
static int usage_t55xx_chk(void) {
    PrintAndLogEx(NORMAL, "This command uses a dictionary attack");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL,  _RED_("WARNING:") " this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try to reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx chk [h] [m] [r <mode>] [i <*.dic>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    PrintAndLogEx(NORMAL, "     m            - use dictionary from flashmemory\n");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    PrintAndLogEx(NORMAL, "     i <*.dic>    - loads a default keys dictionary file <*.dic>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx chk m");
    PrintAndLogEx(NORMAL, "       lf t55xx chk i t55xx_default_pwds");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_bruteforce(void) {
    PrintAndLogEx(NORMAL, "This command uses bruteforce to scan a number range");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, _RED_("WARNING:") " this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx bruteforce [h] [r <mode>] [s <start password>] [e <end password>]");
    PrintAndLogEx(NORMAL, "       password must be 4 bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    PrintAndLogEx(NORMAL, "     s <start_pwd>  - 4 byte hex value to start pwd search at");
    PrintAndLogEx(NORMAL, "     e <end_pwd>    - 4 byte hex value to end pwd search at");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx bruteforce r 2 s aaaaaa77 e aaaaaa99");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_recoverpw(void) {
    PrintAndLogEx(NORMAL, "This command uses a few tricks to try to recover mangled password");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, _RED_("WARNING:") " this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx recoverpw [r <mode>] [p <password>]");
    PrintAndLogEx(NORMAL, "       password must be 4 bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "       default password is 51243648, used by many cloners");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    PrintAndLogEx(NORMAL, "     p <password>   - 4 byte hex value of password written by cloner");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx recoverpw");
    PrintAndLogEx(NORMAL, "       lf t55xx recoverpw p 51243648");
    PrintAndLogEx(NORMAL, "       lf t55xx recoverpw r 3 p 51243648");

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_wipe(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx wipe [h] [Q5] [p <password>] [c <blk0>]");
    PrintAndLogEx(NORMAL, "This commands wipes a tag, fills blocks 1-7 with zeros and a default configuration block");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h               - this help");
    PrintAndLogEx(NORMAL, "     c <block0>      - set configuration from a block0");
    PrintAndLogEx(NORMAL, "     q               - indicates to use T5555 ( Q5 ) default configuration block");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx wipe      -  wipes a T55x7 tag,    config block 0x000880E0");
    PrintAndLogEx(NORMAL, "      lf t55xx wipe q    -  wipes a T5555 ( Q5 ) tag, config block 0x6001F004");
    return PM3_SUCCESS;
}
static int usage_t55xx_deviceconfig(void) {
    PrintAndLogEx(NORMAL, "Sets t55x7 timings for direct commands. The timings are set here in Field Clocks (FC), \nwhich is converted to (US) on device");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx deviceconfig [r <mode>] a <gap> b <gap> c <gap> d <gap> e <gap> f <gap> g <gap> [p]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - This help");
    PrintAndLogEx(NORMAL, "     a <8..255>   - Set start gap");
    PrintAndLogEx(NORMAL, "     b <8..255>   - Set write gap");
    PrintAndLogEx(NORMAL, "     c <8..255>   - Set write ZERO gap");
    PrintAndLogEx(NORMAL, "     d <8..255>   - Set write ONE gap");
    PrintAndLogEx(NORMAL, "     e <8..255>   - Set read gap");
    PrintAndLogEx(NORMAL, "     f <8..255>   - Set write TWO gap (1 of 4 only)");
    PrintAndLogEx(NORMAL, "     g <8..255>   - Set write THREE gap (1 of 4 only)");
    PrintAndLogEx(NORMAL, "     p            - persist to flashmemory");
    PrintAndLogEx(NORMAL, "     z            - Set default t55x7 timings (use p to save if required)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx deviceconfig a 29 b 17 c 15 d 47 e 15   - default T55XX");
    PrintAndLogEx(NORMAL, "      lf t55xx deviceconfig a 55 b 14 c 21 d 30        - default EM4305");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_protect(void) {
    PrintAndLogEx(NORMAL, "This command sets the pwd bit on T5577.");
    PrintAndLogEx(NORMAL, _RED_("WARNING:") " this locks the tag!");
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx protect [r <mode>] [p <password>] [o] [n <new_password>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     p <password>        - OPTIONAL password (8 hex characters)");
    PrintAndLogEx(NORMAL, "     o                   - OPTIONAL override safety check");
    PrintAndLogEx(NORMAL, "     n <new password>    - new password");
    print_usage_t55xx_downloadlink(T55XX_DLMODE_SINGLE, config.downlink_mode);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx protect n 01020304         - sets new password to 01020304");
    PrintAndLogEx(NORMAL, "      lf t55xx protect p 11223344         - use pwd 11223344 to set newpwd to 00000000");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_dangerraw(void) {
    PrintAndLogEx(NORMAL, "This command allows to emit arbitrary raw commands on T5577 and cut the field after arbitrary duration.");
    PrintAndLogEx(NORMAL, _RED_("WARNING:") " this may lock definitively the tag in an unusable state!");
    PrintAndLogEx(NORMAL, "Uncontrolled usage can easily write an invalid configuration, activate lock bits,");
    PrintAndLogEx(NORMAL, "OTP bit, password protection bit, deactivate test-mode, lock your card forever.");
    PrintAndLogEx(NORMAL, "Uncontrolled usage is known to the State of California to cause cancer.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx dangerraw [h] [b <bitstream> t <timing>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h                 - This help");
    PrintAndLogEx(NORMAL, "     b <bitstream>     - raw bitstream");
    PrintAndLogEx(NORMAL, "     t <timing>        - time in microseconds before dropping the field");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int usage_t55xx_clonehelp(void) {
    PrintAndLogEx(NORMAL, "For cloning specific techs on T55xx tags, see commands available in corresponding LF sub-menus, e.g.:");
    PrintAndLogEx(NORMAL, _GREEN_("lf awid clone"));
// todo:  rename to clone
    PrintAndLogEx(NORMAL, _GREEN_("lf em 410x_write"));
// todo:  implement restore
//    PrintAndLogEx(NORMAL, _GREEN_("lf em 4x05_write"));
//    PrintAndLogEx(NORMAL, _GREEN_("lf em 4x50_write"));
    PrintAndLogEx(NORMAL, _GREEN_("lf fdx clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf gallagher clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf gproxii clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf hid clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf indala clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf io clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf jablotron clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf keri clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf nedap clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf noralsy clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf motorola clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf pac clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf paradox clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf presco clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf pyramid clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf securakey clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf viking clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf visa2000 clone"));
    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

static int CmdT55xxCloneHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return usage_t55xx_clonehelp();
}

static void T55x7_SaveBlockData(uint8_t idx, uint32_t data) {
    if (idx < T55x7_BLOCK_COUNT) {
        cardmem[idx].valid      = true;
        cardmem[idx].blockdata  = data;
    }
}
static void T55x7_ClearAllBlockData(void) {
    for (uint8_t idx = 0; idx < T55x7_BLOCK_COUNT; idx++) {
        cardmem[idx].valid      = false;
        cardmem[idx].blockdata  = 0x00;
    }
}

int clone_t55xx_tag(uint32_t *blockdata, uint8_t numblocks) {

    if (blockdata == NULL)
        return PM3_EINVARG;
    if (numblocks < 1 || numblocks > 8)
        return PM3_EINVARG;

    PacketResponseNG resp;

    // fast push mode
    conn.block_after_ACK = true;

    for (int8_t i = 0; i < numblocks; i++) {

        // Disable fast mode on last packet
        if (i == numblocks - 1) {
            conn.block_after_ACK = false;
        }

        clearCommandBuffer();

        t55xx_write_block_t ng;
        ng.data = blockdata[i];
        ng.pwd = 0;
        ng.blockno = i;
        ng.flags = 0;

        SendCommandNG(CMD_LF_T55XX_WRITEBL, (uint8_t *)&ng, sizeof(ng));
        if (!WaitForResponseTimeout(CMD_LF_T55XX_WRITEBL, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    }

    uint8_t res = 0;
    for (int8_t i = 0; i < numblocks; i++) {

        if (i == 0) {
            SetConfigWithBlock0(blockdata[0]);
            if (t55xxAquireAndCompareBlock0(false, 0, blockdata[0], false))
                continue;
        }

        if (t55xxVerifyWrite(i, 0, false, false, 0, 0xFF, blockdata[i]) == false)
            res++;
    }

    if (res == 0)
        PrintAndLogEx(SUCCESS, "Success writing to tag");

    return PM3_SUCCESS;
}

static bool t55xxProtect(bool lock, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, uint32_t new_password) {

    PrintAndLogEx(INFO, "Checking current configuration");

    bool testmode = false;
    uint32_t block0 = 0;

    int res = T55xxReadBlockEx(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, usepwd, override, password, downlink_mode, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to read block0, use " _YELLOW_("`p`") " password parameter?");
        return false;
    }

    if (GetT55xxBlockData(&block0) == false) {
        PrintAndLogEx(DEBUG, "ERROR decoded block0 == %08x", block0);
        return false;
    }
    PrintAndLogEx(DEBUG, "OK read block0 == %08x", block0);


    bool isPwdBitAlreadySet = (block0 >> (32 - 28) & 1);
    if (isPwdBitAlreadySet) {
        PrintAndLogEx(INFO, "PWD bit is already set");
        usepwd = true;
    }

    // set / clear pwd bit
    if (lock) {
        block0 |= 1 << 4;
    } else {
        block0 &= ~(1 << 4);
    }

    // write new password
    if (t55xxWrite(T55x7_PWD_BLOCK, T55x7_PAGE0, usepwd, testmode, password, downlink_mode, new_password) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to write new password");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Wrote new password");
    }

    // validate new password
    uint32_t curr_password = (isPwdBitAlreadySet) ? new_password : password;

    if (t55xxVerifyWrite(T55x7_PWD_BLOCK, T55x7_PAGE0, usepwd, override, curr_password, downlink_mode, new_password) == false) {
        PrintAndLogEx(WARNING, "Failed to validate the password write. aborting.");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Validated new password");
    }

    // write config
    if (t55xxWrite(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, usepwd, testmode, curr_password, downlink_mode, block0) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to write modified configuration block %08X", block0);
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Wrote modified configuration block");
    }

    // validate new config.  If all went well,  card should now demand pwd, hence override = 0.
    override = 0;
    if (t55xxVerifyWrite(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, true, override, new_password, downlink_mode, block0) == false) {
        PrintAndLogEx(WARNING, "Failed to validate pwd bit set on configuration block. aborting.");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "New configuration block " _YELLOW_("%08X")" password " _YELLOW_("%08X"), block0, new_password);
        PrintAndLogEx(SUCCESS, "Success, tag is locked");
        return true;
    }
}

bool t55xxAquireAndCompareBlock0(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose) {

    if (verbose)
        PrintAndLogEx(INFO, "Block0 write detected, running `detect` to see if validation is possible");

    for (uint8_t m = 0; m < 4; m++) {
        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, m) == false) {
            continue;
        }

        if (DecodeT55xxBlock() == false) {
            continue;
        }

        for (uint16_t i = 0; DemodBufferLen - 32; i++) {
            uint32_t tmp = PackBits(i, 32, DemodBuffer);
            if (tmp == known_block0) {
                config.offset = i;
                config.downlink_mode = m;
                return true;
            }
        }
    }
    return false;
}

bool t55xxAquireAndDetect(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose) {

    if (verbose)
        PrintAndLogEx(INFO, "Block0 write detected, running `detect` to see if validation is possible");

    // Update flags for usepwd pwd assume its correct
    config.usepwd = usepwd;
    if (usepwd)
        config.pwd = password;
    else
        config.pwd = 0x00;

    for (uint8_t m = 0; m < 4; m++) {
        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, m) == false)
            continue;

        if (tryDetectModulationEx(m, verbose, known_block0) == false)
            continue;

        config.downlink_mode = m;
        return true;
    }
    config.usepwd = false; // unknown so assume no password
    config.pwd = 0x00;

    return false;
}

bool t55xxVerifyWrite(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, uint32_t data) {

    uint32_t read_data = 0;

    if (downlink_mode == 0xFF)
        downlink_mode = config.downlink_mode;

    int res = T55xxReadBlockEx(block, page1, usepwd, override, password, downlink_mode, false);
    if (res == PM3_SUCCESS) {

        if (GetT55xxBlockData(&read_data) == false)
            return false;

    } else if (res == PM3_EWRONGANSWER) {

        // could't decode.  Lets see if this was a block 0 write and try read/detect it auto.
        // this messes up with ppls config..
        if (block == 0 && page1 == false) {

            if (t55xxAquireAndDetect(usepwd, password, data, true) == false)
                return false;

            return t55xxVerifyWrite(block, page1, usepwd, 2, password, config.downlink_mode, data);
        }
    }

    return (read_data == data);
}

int t55xxWrite(uint8_t block, bool page1, bool usepwd, bool testMode, uint32_t password, uint8_t downlink_mode, uint32_t data) {

    uint8_t flags;
    flags  = (usepwd)   ? 0x1 : 0;
    flags |= (page1)    ? 0x2 : 0;
    flags |= (testMode) ? 0x4 : 0;
    flags |= (downlink_mode << 3);

    /*
        OLD style
       arg0 = data, (4 bytes)
       arg1 = block (1 byte)
       arg2 = password (4 bytes)
       flags = data[0] (1 byte)

       new style
       uses struct in pm3_cmd.h
    */
    t55xx_write_block_t ng;
    ng.data    = data;
    ng.pwd     = password;
    ng.blockno = block;
    ng.flags   = flags;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_WRITEBL, (uint8_t *)&ng, sizeof(ng));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_WRITEBL, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not ACK write operation.");
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

void printT5xxHeader(uint8_t page) {
    PrintAndLogEx(SUCCESS, "Reading Page %d:", page);
    PrintAndLogEx(SUCCESS, "blk | hex data | binary                           | ascii");
    PrintAndLogEx(SUCCESS, "----+----------+----------------------------------+-------");
}

void SetConfigWithBlock0(uint32_t block0) {
    SetConfigWithBlock0Ex(block0, 0, false);
}
void SetConfigWithBlock0Ex(uint32_t block0, uint8_t offset, bool Q5) {
    // T55x7
    uint32_t extend = (block0 >> (32 - 15)) & 0x01;
    uint32_t dbr;
    if (extend)
        dbr = (block0 >> (32 - 14)) & 0x3F;
    else
        dbr = (block0 >> (32 - 14)) & 0x07;

    uint32_t datamod  = (block0 >> (32 - 20)) & 0x1F;
    bool pwd = (bool)((block0 >> (32 - 28)) & 0x01);
    bool sst = (bool)((block0 >> (32 - 29)) & 0x01);
    bool inv = (bool)((block0 >> (32 - 31)) & 0x01);

    config.modulation = datamod;
    config.bitrate = dbr;

    // FSK1a, FSK2a
    if (datamod == DEMOD_FSK1a || datamod == DEMOD_FSK2a || datamod ==  DEMOD_BIa)
        config.inverted = 1;
    else
        config.inverted = inv;

    config.Q5 = Q5;
    config.ST = sst;
    config.usepwd = pwd;
    config.offset = offset;
    config.block0 = block0;
}

static int CmdT55xxSetConfig(const char *Cmd) {

    // No args
    if (strlen(Cmd) == 0) return printConfiguration(config);

    uint8_t offset = 0, bitRate = 0;
    char modulation[6] = {0x00};
    uint8_t rates[9] = {8, 16, 32, 40, 50, 64, 100, 128, 0};
    uint8_t cmdp = 0;
    uint8_t downlink_mode = 0;
    bool errors = false;
    uint32_t block0 = 0;
    bool gotconf = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        char tmp = tolower(param_getchar(Cmd, cmdp));
        switch (tmp) {
            case 'h':
                return usage_t55xx_config();
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &bitRate);
                if (!errors) {
                    uint8_t i = 0;
                    for (; i < 9; i++) {
                        if (rates[i] == bitRate) {
                            config.bitrate = i;
                            break;
                        }
                    }
                    if (i == 9) errors = true;
                }
                cmdp += 2;
                break;
            case 'c':
                block0 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotconf = true;
                cmdp += 2;
                break;
            case 'd':
                param_getstr(Cmd, cmdp + 1, modulation, sizeof(modulation));
                cmdp += 2;

                if (strcmp(modulation, "FSK") == 0) {
                    config.modulation = DEMOD_FSK;
                } else if (strcmp(modulation, "FSK1") == 0) {
                    config.modulation = DEMOD_FSK1;
                    config.inverted = 1;
                } else if (strcmp(modulation, "FSK1a") == 0) {
                    config.modulation = DEMOD_FSK1a;
                    config.inverted = 0;
                } else if (strcmp(modulation, "FSK2") == 0) {
                    config.modulation = DEMOD_FSK2;
                    config.inverted = 0;
                } else if (strcmp(modulation, "FSK2a") == 0) {
                    config.modulation = DEMOD_FSK2a;
                    config.inverted = 1;
                } else if (strcmp(modulation, "ASK") == 0) {
                    config.modulation = DEMOD_ASK;
                } else if (strcmp(modulation, "NRZ") == 0) {
                    config.modulation = DEMOD_NRZ;
                } else if (strcmp(modulation, "PSK1") == 0) {
                    config.modulation = DEMOD_PSK1;
                } else if (strcmp(modulation, "PSK2") == 0) {
                    config.modulation = DEMOD_PSK2;
                } else if (strcmp(modulation, "PSK3") == 0) {
                    config.modulation = DEMOD_PSK3;
                } else if (strcmp(modulation, "BIa") == 0) {
                    config.modulation = DEMOD_BIa;
                    config.inverted = 1;
                } else if (strcmp(modulation, "BI") == 0) {
                    config.modulation = DEMOD_BI;
                    config.inverted = 0;
                } else {
                    PrintAndLogEx(WARNING, "Unknown modulation '%s'", modulation);
                    errors = true;
                }
                break;
            case 'i':
                if ((param_getchar(Cmd, cmdp + 1) == '0') || (param_getchar(Cmd, cmdp + 1) == '1')) {
                    config.inverted = param_getchar(Cmd, cmdp + 1) == '1';
                    cmdp += 2;
                } else {
                    config.inverted = true;
                    cmdp += 1;
                }
                break;
            case 'o':
                errors |= param_getdec(Cmd, cmdp + 1, &offset);
                if (!errors)
                    config.offset = offset;
                cmdp += 2;
                break;
            case 'q':
                if ((param_getchar(Cmd, cmdp + 1) == '0') || (param_getchar(Cmd, cmdp + 1) == '1')) {
                    config.Q5 = param_getchar(Cmd, cmdp + 1) == '1';
                    cmdp += 2;
                } else {
                    config.Q5 = true;
                    cmdp += 1;
                }
                break;
            case 's':
                if ((param_getchar(Cmd, cmdp + 1) == '0') || (param_getchar(Cmd, cmdp + 1) == '1')) {
                    config.ST = param_getchar(Cmd, cmdp + 1) == '1';
                    cmdp += 2;
                } else {
                    config.ST = true;
                    cmdp += 1;
                }
                break;
            case 'r':
                errors = param_getdec(Cmd, cmdp + 1, &downlink_mode);
                if (downlink_mode > 3)
                    downlink_mode = 0;
                if (!errors)
                    config.downlink_mode = downlink_mode;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_t55xx_config();

    if (gotconf) {
        SetConfigWithBlock0Ex(block0, config.offset, config.Q5);
    } else {
        config.block0 = 0;
    }

    return printConfiguration(config);
}
int T55xxReadBlock(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode) {
    return T55xxReadBlockEx(block, page1, usepwd, override, password, downlink_mode, true);
}

int T55xxReadBlockEx(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, bool verbose) {
    //Password mode
    if (usepwd) {
        // try reading the config block and verify that PWD bit is set before doing this!
        // override = 1 (override and display)
        // override = 2 (override and no display)
        if (override == 0) {
            if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, false, 0, downlink_mode) == false)
                return PM3_ERFTRANS;

            if (tryDetectModulation(downlink_mode, false) == false) {
                PrintAndLogEx(WARNING, "Safety check: Could not detect if PWD bit is set in config block. Exits.");
                return PM3_EWRONGANSWER;
            } else {
                PrintAndLogEx(WARNING, "Safety check: PWD bit is NOT set in config block. Reading without password...");
                usepwd = false;
                page1 = false; // ??
            }
        } else if (override == 1) {
            PrintAndLogEx(INFO, "Safety check overridden - proceeding despite risk");
        }
    }

    if (AcquireData(page1, block, usepwd, password, downlink_mode) == false)
        return PM3_ERFTRANS;

    if (DecodeT55xxBlock() == false)
        return PM3_EWRONGANSWER;

    if (verbose)
        printT55xxBlock(block, page1);

    return PM3_SUCCESS;
}

static int CmdT55xxReadBlock(const char *Cmd) {
    uint8_t block = REGULAR_READ_MODE_BLOCK;
    uint8_t override = 0;
    uint8_t cmdp = 0;
    uint8_t downlink_mode = config.downlink_mode;
    uint32_t password = 0; //default to blank Block 7
    bool usepwd = false;
    bool page1 = false;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_read();
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &block);
                cmdp += 2;
                break;
            case 'o':
                override = 1;
                cmdp++;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case '1':
                page1 = true;
                cmdp++;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || cmdp == 0) return usage_t55xx_read();

    if (block > 7 && block != REGULAR_READ_MODE_BLOCK) {
        PrintAndLogEx(NORMAL, "Block must be between 0 and 7");
        return PM3_ESOFT;
    }

    printT5xxHeader(page1);
    return T55xxReadBlock(block, page1, usepwd, override, password, downlink_mode);
}

bool DecodeT55xxBlock(void) {

    char buf[30] = {0x00};
    char *cmdStr = buf;
    int ans = 0;
    bool ST = config.ST;
    uint8_t bitRate[8] = {8, 16, 32, 40, 50, 64, 100, 128};
    DemodBufferLen = 0x00;

    switch (config.modulation) {
        case DEMOD_FSK:
            snprintf(cmdStr, sizeof(buf), "%d %d", bitRate[config.bitrate], config.inverted);
            ans = FSKrawDemod(cmdStr, false);
            break;
        case DEMOD_FSK1:
        case DEMOD_FSK1a:
            snprintf(cmdStr, sizeof(buf), "%d %d 8 5", bitRate[config.bitrate], config.inverted);
            ans = FSKrawDemod(cmdStr, false);
            break;
        case DEMOD_FSK2:
        case DEMOD_FSK2a:
            snprintf(cmdStr, sizeof(buf), "%d %d 10 8", bitRate[config.bitrate], config.inverted);
            ans = FSKrawDemod(cmdStr, false);
            break;
        case DEMOD_ASK:
            snprintf(cmdStr, sizeof(buf), "%d %d 1", bitRate[config.bitrate], config.inverted);
            ans = ASKDemod_ext(cmdStr, false, false, 1, &ST);
            break;
        case DEMOD_PSK1:
            snprintf(cmdStr, sizeof(buf), "%d %d 6", bitRate[config.bitrate], config.inverted);
            ans = PSKDemod(cmdStr, false);
            break;
        case DEMOD_PSK2: //inverted won't affect this
        case DEMOD_PSK3: //not fully implemented
            snprintf(cmdStr, sizeof(buf), "%d 0 6", bitRate[config.bitrate]);
            ans = PSKDemod(cmdStr, false);
            psk1TOpsk2(DemodBuffer, DemodBufferLen);
            break;
        case DEMOD_NRZ:
            snprintf(cmdStr, sizeof(buf), "%d %d 1", bitRate[config.bitrate], config.inverted);
            ans = NRZrawDemod(cmdStr, false);
            break;
        case DEMOD_BI:
        case DEMOD_BIa:
            snprintf(cmdStr, sizeof(buf), "0 %d %d 1", bitRate[config.bitrate], config.inverted);
            ans = ASKbiphaseDemod(cmdStr, false);
            break;
        default:
            return false;
    }
    return (ans == PM3_SUCCESS);
}

static bool DecodeT5555TraceBlock(void) {
    DemodBufferLen = 0x00;

    // According to datasheet. Always: RF/64, not inverted, Manchester
    return (ASKDemod("64 0 1", false, false, 1) == PM3_SUCCESS);
}

// sanity check. Don't use proxmark if it is offline and you didn't specify useGraphbuf
static int SanityOfflineCheck(bool useGraphBuffer) {
    if (!useGraphBuffer && !session.pm3_present) {
        PrintAndLogEx(WARNING, "Your proxmark3 device is offline. Specify [1] to use graphbuffer data instead");
        return PM3_ENODATA;
    }
    return PM3_SUCCESS;
}

static void T55xx_Print_DownlinkMode(uint8_t downlink_mode) {
    char msg[80];
    sprintf(msg, "Downlink Mode used : ");

    switch (downlink_mode) {
        case  1 :
            strcat(msg, _YELLOW_("long leading reference"));
            break;
        case  2 :
            strcat(msg, _YELLOW_("leading zero reference"));
            break;
        case  3 :
            strcat(msg, _YELLOW_("1 of 4 coding reference"));
            break;
        default :
            strcat(msg, _YELLOW_("default/fixed bit length"));
            break;
    }

    PrintAndLogEx(NORMAL, msg);
}

static int CmdT55xxDetect(const char *Cmd) {

    bool errors = false;
    bool useGB = false;
    bool usepwd = false;
    bool try_with_pwd = false;
    bool try_all_dl_modes = true;
    bool found = false;
    uint32_t password = 0;
    uint8_t cmdp = 0;
    uint8_t downlink_mode = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_detect();
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case '1':
                useGB = true;
                cmdp++;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode <= 3) try_all_dl_modes = false; // User selected ONLY 1 so honor.
                if (downlink_mode == 4) try_all_dl_modes = true;
                if (downlink_mode > 3) downlink_mode = 0;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_detect();

    // detect called so clear data blocks
    T55x7_ClearAllBlockData();

    // sanity check.
    if (SanityOfflineCheck(useGB) != PM3_SUCCESS)
        return PM3_ESOFT;

    if (useGB == false) {
        // do ... while to check without password then loop back if password supplied
        do {

            if (try_all_dl_modes) {
                for (uint8_t m = downlink_mode; m < 4; m++) {

                    if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, try_with_pwd && usepwd, password, m) == false)
                        continue;

                    // pre fill to save passing in.
                    config.usepwd = try_with_pwd;
                    if (try_with_pwd)
                        config.pwd = password;
                    else
                        config.pwd = 0x00;

                    if (tryDetectModulation(m, T55XX_PrintConfig) == false)
                        continue;

                    found = true;
                    break;
                }
            } else {
                config.usepwd = try_with_pwd;
                if (try_with_pwd)
                    config.pwd = password;
                else
                    config.pwd = 0x00;

                if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, downlink_mode)) {
                    found = tryDetectModulation(downlink_mode, T55XX_PrintConfig);
                }
            }

            if (!found && usepwd)
                try_with_pwd = !try_with_pwd; // toggle so we loop back if not found and try with pwd

            if (found)
                try_with_pwd = false; // force exit as decect block has been found.

        } while (try_with_pwd);

    } else {
        found = tryDetectModulation(downlink_mode, T55XX_PrintConfig);
    }

    if (found == false) {
        config.usepwd = false;
        config.pwd = 0x00;
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));
    }
    return PM3_SUCCESS;
}

// detect configuration?
bool tryDetectModulation(uint8_t downlink_mode, bool print_config) {
    return tryDetectModulationEx(downlink_mode, print_config, 0);
}

bool tryDetectModulationEx(uint8_t downlink_mode, bool print_config, uint32_t wanted_conf) {

    t55xx_conf_block_t tests[15];
    int bitRate = 0, clk = 0, firstClockEdge = 0;
    uint8_t hits = 0, fc1 = 0, fc2 = 0, ans = 0;

    ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);

    if (ans && ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5))) {
        if ((FSKrawDemod("0 0", false) == PM3_SUCCESS) && test(DEMOD_FSK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
            tests[hits].modulation = DEMOD_FSK;
            if (fc1 == 8 && fc2 == 5)
                tests[hits].modulation = DEMOD_FSK1a;
            else if (fc1 == 10 && fc2 == 8)
                tests[hits].modulation = DEMOD_FSK2;
            tests[hits].bitrate = bitRate;
            tests[hits].inverted = false;
            tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
            tests[hits].ST = false;
            tests[hits].downlink_mode = downlink_mode;
            ++hits;
        }
        if ((FSKrawDemod("0 1", false) == PM3_SUCCESS) && test(DEMOD_FSK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
            tests[hits].modulation = DEMOD_FSK;
            if (fc1 == 8 && fc2 == 5)
                tests[hits].modulation = DEMOD_FSK1;
            else if (fc1 == 10 && fc2 == 8)
                tests[hits].modulation = DEMOD_FSK2a;
            tests[hits].bitrate = bitRate;
            tests[hits].inverted = true;
            tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
            tests[hits].ST = false;
            tests[hits].downlink_mode = downlink_mode;
            ++hits;
        }
    } else {
        clk = GetAskClock("", false);
        if (clk > 0) {
            tests[hits].ST = true;
            // "0 0 1 " == clock auto, invert false, maxError 1.
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true
            if ((ASKDemod_ext("0 0 1", false, false, 1, &tests[hits].ST) == PM3_SUCCESS) && test(DEMOD_ASK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_ASK;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            tests[hits].ST = true;
            // "0 0 1 " == clock auto, invert true, maxError 1.
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true
            if ((ASKDemod_ext("0 1 1", false, false, 1, &tests[hits].ST) == PM3_SUCCESS) && test(DEMOD_ASK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_ASK;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((ASKbiphaseDemod("0 0 0 2", false) == PM3_SUCCESS) && test(DEMOD_BI, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BI;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((ASKbiphaseDemod("0 0 1 2", false) == PM3_SUCCESS) && test(DEMOD_BIa, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BIa;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
        }
        clk = GetNrzClock("", false);
        if (clk > 8) { //clock of rf/8 is likely a false positive, so don't use it.
            if ((NRZrawDemod("0 0 1", false) == PM3_SUCCESS) && test(DEMOD_NRZ, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_NRZ;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }

            if ((NRZrawDemod("0 1 1", false) == PM3_SUCCESS) && test(DEMOD_NRZ, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_NRZ;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
        }

        clk = GetPskClock("", false);
        if (clk > 0) {
            // allow undo
            save_restoreGB(GRAPH_SAVE);
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            CmdLtrim("160");
            if ((PSKDemod("0 0 6", false) == PM3_SUCCESS) && test(DEMOD_PSK1, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((PSKDemod("0 1 6", false) == PM3_SUCCESS) && test(DEMOD_PSK1, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            //ICEMAN: are these PSKDemod calls needed?
            // PSK2 - needs a call to psk1TOpsk2.
            if (PSKDemod("0 0 6", false) == PM3_SUCCESS) {
                psk1TOpsk2(DemodBuffer, DemodBufferLen);
                if (test(DEMOD_PSK2, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                    tests[hits].modulation = DEMOD_PSK2;
                    tests[hits].bitrate = bitRate;
                    tests[hits].inverted = false;
                    tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                    tests[hits].ST = false;
                    tests[hits].downlink_mode = downlink_mode;
                    ++hits;
                }
            } // inverse waves does not affect this demod
            // PSK3 - needs a call to psk1TOpsk2.
            if (PSKDemod("0 0 6", false) == PM3_SUCCESS) {
                psk1TOpsk2(DemodBuffer, DemodBufferLen);
                if (test(DEMOD_PSK3, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                    tests[hits].modulation = DEMOD_PSK3;
                    tests[hits].bitrate = bitRate;
                    tests[hits].inverted = false;
                    tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                    tests[hits].ST = false;
                    tests[hits].downlink_mode = downlink_mode;
                    ++hits;
                }
            } // inverse waves does not affect this demod
            //undo trim samples
            save_restoreGB(GRAPH_RESTORE);
        }
    }
    if (hits == 1) {
        config.modulation = tests[0].modulation;
        config.bitrate = tests[0].bitrate;
        config.inverted = tests[0].inverted;
        config.offset = tests[0].offset;
        config.block0 = tests[0].block0;
        config.Q5 = tests[0].Q5;
        config.ST = tests[0].ST;
        config.downlink_mode = downlink_mode;

        if (print_config)
            printConfiguration(config);

        return true;
    }

    bool retval = false;
    if (hits > 1) {
        PrintAndLogEx(SUCCESS, "Found [%d] possible matches for modulation.", hits);
        for (int i = 0; i < hits; ++i) {

            bool wanted = false;
            if (wanted_conf > 0)
                wanted = (wanted_conf == tests[i].block0);

            retval = testKnownConfigBlock(tests[i].block0);
            if (retval || wanted) {
                PrintAndLogEx(NORMAL, "--[%d]--------------- << selected this", i + 1);
                config.modulation = tests[i].modulation;
                config.bitrate = tests[i].bitrate;
                config.inverted = tests[i].inverted;
                config.offset = tests[i].offset;
                config.block0 = tests[i].block0;
                config.Q5 = tests[i].Q5;
                config.ST = tests[i].ST;
                config.downlink_mode = tests[i].downlink_mode;
            } else {
                PrintAndLogEx(NORMAL, "--[%d]---------------", i + 1);
            }

            if (print_config)
                printConfiguration(tests[i]);
        }
    }
    return retval;
}

bool testKnownConfigBlock(uint32_t block0) {
    switch (block0) {
        case T55X7_DEFAULT_CONFIG_BLOCK:
        case T55X7_RAW_CONFIG_BLOCK:
        case T55X7_EM_UNIQUE_CONFIG_BLOCK:
        case T55X7_FDXB_CONFIG_BLOCK:
        case T55X7_HID_26_CONFIG_BLOCK:
        case T55X7_PYRAMID_CONFIG_BLOCK:
        case T55X7_INDALA_64_CONFIG_BLOCK:
        case T55X7_INDALA_224_CONFIG_BLOCK:
        case T55X7_GUARDPROXII_CONFIG_BLOCK:
        case T55X7_VIKING_CONFIG_BLOCK:
        case T55X7_NORALYS_CONFIG_BLOCK:
        case T55X7_IOPROX_CONFIG_BLOCK:
        case T55X7_PRESCO_CONFIG_BLOCK:
        case T55X7_NEDAP_64_CONFIG_BLOCK:
        case T55X7_NEDAP_128_CONFIG_BLOCK:
            return true;
    }
    return false;
}

bool GetT55xxBlockData(uint32_t *blockdata) {

    if (DemodBufferLen == 0)
        return false;

    uint8_t idx = config.offset;

    if (idx + 32 > DemodBufferLen) {
        PrintAndLogEx(WARNING, "The configured offset %d is too big. Possible offset: %zu)", idx, DemodBufferLen - 32);
        return false;
    }

    *blockdata = PackBits(0, 32, DemodBuffer + idx);
    return true;
}

void printT55xxBlock(uint8_t blockNum, bool page1) {

    uint32_t blockData = 0;
    uint8_t bytes[4] = {0};

    if (GetT55xxBlockData(&blockData) == false)
        return;

    num_to_bytes(blockData, 4, bytes);

    T55x7_SaveBlockData((page1) ? blockNum + 8 : blockNum, blockData);

    PrintAndLogEx(SUCCESS, " %02d | %08X | %s | %s", blockNum, blockData, sprint_bin(DemodBuffer + config.offset, 32), sprint_ascii(bytes, 4));
}

static bool testModulation(uint8_t mode, uint8_t modread) {
    switch (mode) {
        case DEMOD_FSK:
            if (modread >= DEMOD_FSK1 && modread <= DEMOD_FSK2a) return true;
            break;
        case DEMOD_ASK:
            if (modread == DEMOD_ASK) return true;
            break;
        case DEMOD_PSK1:
            if (modread == DEMOD_PSK1) return true;
            break;
        case DEMOD_PSK2:
            if (modread == DEMOD_PSK2) return true;
            break;
        case DEMOD_PSK3:
            if (modread == DEMOD_PSK3) return true;
            break;
        case DEMOD_NRZ:
            if (modread == DEMOD_NRZ) return true;
            break;
        case DEMOD_BI:
            if (modread == DEMOD_BI) return true;
            break;
        case DEMOD_BIa:
            if (modread == DEMOD_BIa) return true;
            break;
        default:
            return false;
    }
    return false;
}

static bool testQ5Modulation(uint8_t mode, uint8_t modread) {
    switch (mode) {
        case DEMOD_FSK:
            if (modread >= 4 && modread <= 5) return true;
            break;
        case DEMOD_ASK:
            if (modread == 0) return true;
            break;
        case DEMOD_PSK1:
            if (modread == 1) return true;
            break;
        case DEMOD_PSK2:
            if (modread == 2) return true;
            break;
        case DEMOD_PSK3:
            if (modread == 3) return true;
            break;
        case DEMOD_NRZ:
            if (modread == 7) return true;
            break;
        case DEMOD_BI:
            if (modread == 6) return true;
            break;
        default:
            return false;
    }
    return false;
}

static int convertQ5bitRate(uint8_t bitRateRead) {
    uint8_t expected[] = {8, 16, 32, 40, 50, 64, 100, 128};
    for (int i = 0; i < 8; i++)
        if (expected[i] == bitRateRead)
            return i;

    return -1;
}

static bool testQ5(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk) {

    if (DemodBufferLen < 64) return false;

    for (uint8_t idx = 28; idx < 64; idx++) {
        uint8_t si = idx;
        if (PackBits(si, 28, DemodBuffer) == 0x00) continue;

        uint8_t safer     = PackBits(si, 4, DemodBuffer);
        si += 4;     //master key
        uint8_t resv      = PackBits(si, 8, DemodBuffer);
        si += 8;
        // 2nibble must be zeroed.
        if (safer != 0x6 && safer != 0x9) continue;
        if (resv > 0x00) continue;
        //uint8_t pageSel   = PackBits(si, 1, DemodBuffer); si += 1;
        //uint8_t fastWrite = PackBits(si, 1, DemodBuffer); si += 1;
        si += 1 + 1;
        int bitRate       = PackBits(si, 6, DemodBuffer) * 2 + 2;
        si += 6;     //bit rate
        if (bitRate > 128 || bitRate < 8) continue;

        //uint8_t AOR       = PackBits(si, 1, DemodBuffer); si += 1;
        //uint8_t PWD       = PackBits(si, 1, DemodBuffer); si += 1;
        //uint8_t pskcr     = PackBits(si, 2, DemodBuffer); si += 2;  //could check psk cr
        //uint8_t inverse   = PackBits(si, 1, DemodBuffer); si += 1;
        si += 1 + 1 + 2 + 1;
        uint8_t modread   = PackBits(si, 3, DemodBuffer);
        si += 3;
        uint8_t maxBlk    = PackBits(si, 3, DemodBuffer);
        si += 3;
        //uint8_t ST        = PackBits(si, 1, DemodBuffer); si += 1;
        if (maxBlk == 0) continue;

        //test modulation
        if (!testQ5Modulation(mode, modread)) continue;
        if (bitRate != clk) continue;

        *fndBitRate = convertQ5bitRate(bitRate);
        if (*fndBitRate < 0) continue;

        *offset = idx;

        return true;
    }
    return false;
}

static bool testBitRate(uint8_t readRate, uint8_t clk) {
    uint8_t expected[] = {8, 16, 32, 40, 50, 64, 100, 128};
    if (expected[readRate] == clk)
        return true;

    return false;
}

bool test(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk, bool *Q5) {

    if (DemodBufferLen < 64) return false;
    for (uint8_t idx = 28; idx < 64; idx++) {
        uint8_t si = idx;
        if (PackBits(si, 28, DemodBuffer) == 0x00) continue;

        uint8_t safer    = PackBits(si, 4, DemodBuffer);
        si += 4;     //master key
        uint8_t resv     = PackBits(si, 4, DemodBuffer);
        si += 4;     //was 7 & +=7+3 //should be only 4 bits if extended mode
        // 2nibble must be zeroed.
        // moved test to here, since this gets most faults first.
        if (resv > 0x00) continue;

        int bitRate      = PackBits(si, 6, DemodBuffer);
        si += 6;     //bit rate (includes extended mode part of rate)
        uint8_t extend   = PackBits(si, 1, DemodBuffer);
        si += 1;     //bit 15 extended mode
        uint8_t modread  = PackBits(si, 5, DemodBuffer);
        si += 5 + 2 + 1;
        //uint8_t pskcr   = PackBits(si, 2, DemodBuffer); si += 2+1;  //could check psk cr
        //uint8_t nml01    = PackBits(si, 1, DemodBuffer); si += 1+5;   //bit 24, 30, 31 could be tested for 0 if not extended mode
        //uint8_t nml02    = PackBits(si, 2, DemodBuffer); si += 2;

        //if extended mode
        bool extMode = ((safer == 0x6 || safer == 0x9) && extend) ? true : false;

        if (!extMode) {
            if (bitRate > 7) continue;
            if (!testBitRate(bitRate, clk)) continue;
        } else { //extended mode bitrate = same function to calc bitrate as em4x05
            if (EM4x05_GET_BITRATE(bitRate) != clk) continue;

        }
        //test modulation
        if (!testModulation(mode, modread)) continue;
        *fndBitRate = bitRate;
        *offset = idx;
        *Q5 = false;
        return true;
    }
    if (testQ5(mode, offset, fndBitRate, clk)) {
        *Q5 = true;
        return true;
    }
    return false;
}

int special(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    uint8_t bits[32] = {0x00};

    PrintAndLogEx(NORMAL, "OFFSET | DATA  | BINARY                              | ASCII");
    PrintAndLogEx(NORMAL, "-------+-------+-------------------------------------+------");
    int i, j = 0;
    for (; j < 64; ++j) {

        for (i = 0; i < 32; ++i)
            bits[i] = DemodBuffer[j + i];

        uint32_t blockData = PackBits(0, 32, bits);

        PrintAndLogEx(NORMAL, "%02d | 0x%08X | %s", j, blockData, sprint_bin(bits, 32));
    }
    return PM3_SUCCESS;
}

int printConfiguration(t55xx_conf_block_t b) {
    PrintAndLogEx(INFO, "     Chip Type      : " _GREEN_("%s"), (b.Q5) ? "T5555 ( Q5 )" : "T55x7");
    PrintAndLogEx(INFO, "     Modulation     : " _GREEN_("%s"), GetSelectedModulationStr(b.modulation));
    PrintAndLogEx(INFO, "     Bit Rate       : %s", GetBitRateStr(b.bitrate, (b.block0 & T55x7_X_MODE && (b.block0 >> 28 == 6 || b.block0 >> 28 == 9))));
    PrintAndLogEx(INFO, "     Inverted       : %s", (b.inverted) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(INFO, "     Offset         : %d", b.offset);
    PrintAndLogEx(INFO, "     Seq. Term.     : %s", (b.ST) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(INFO, "     Block0         : 0x%08X", b.block0);
    PrintAndLogEx(INFO, "     Downlink Mode  : %s", GetDownlinkModeStr(b.downlink_mode));
    PrintAndLogEx(INFO, "     Password Set   : %s", (b.usepwd) ? _RED_("Yes") : _GREEN_("No"));
    if (b.usepwd) {
        PrintAndLogEx(INFO, "     Password       : %08X", b.pwd);
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdT55xxWakeUp(const char *Cmd) {

    uint32_t password = 0;
    uint8_t cmdp = 0;
    bool errors = false;
    uint8_t downlink_mode = config.downlink_mode;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_wakup();
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_t55xx_wakup();

    struct p {
        uint32_t password;
        uint8_t flags;
    } PACKED payload;

    payload.password = password;
    payload.flags = (downlink_mode & 3) << 3;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_WAKEUP, (uint8_t *)&payload, sizeof(payload));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_WAKEUP, NULL, 1000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    PrintAndLogEx(SUCCESS, "Wake up command sent. Try read now");
    return PM3_SUCCESS;
}

static int CmdT55xxWriteBlock(const char *Cmd) {
    uint8_t block = 0xFF;    // default to invalid block
    uint32_t data = 0;       // default to blank Block
    uint32_t password = 0;   // default to blank Block 7
    bool usepwd = false;
    bool page1 = false;
    bool gotdata = false;
    bool testMode = false;
    bool errors = false;
    bool validate = false;
    uint8_t cmdp = 0;
    uint32_t downlink_mode = config.downlink_mode;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_write();
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &block);
                cmdp += 2;

                if (block > 7) {
                    PrintAndLogEx(WARNING, "Block number must be between 0 and 7");
                    errors = true;
                }
                break;
            case 'd':
                data = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotdata = true;
                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case 't':
                testMode = true;
                cmdp++;
                break;
            case '1':
                page1 = true;
                cmdp++;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case 'v':
                validate = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || !gotdata) return usage_t55xx_write();

    char pwdStr[16] = {0};
    snprintf(pwdStr, sizeof(pwdStr), "pwd: 0x%08X", password);

    PrintAndLogEx(INFO, "Writing page %d  block: %02d  data: 0x%08X %s", page1, block, data, (usepwd) ? pwdStr : "");

    if (t55xxWrite(block, page1, usepwd, testMode, password, downlink_mode, data) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Write failed");
        return PM3_ESOFT;
    }

    if (validate) {
        bool isOK = t55xxVerifyWrite(block, page1, usepwd, 1, password, downlink_mode, data);
        if (isOK)
            PrintAndLogEx(SUCCESS, "Write OK, validation successful");
        else
            PrintAndLogEx(WARNING, "Write could not validate the written data");
    }

    return PM3_SUCCESS;
}

static int CmdT55xxDangerousRaw(const char *Cmd) {
    // supports only default downlink mode
    t55xx_test_block_t ng;
    ng.time = 0;
    ng.bitlen = 0;
    memset(ng.data, 0x00, sizeof(ng.data));
    bool errors = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_dangerraw();
            case 't':
                ng.time = param_get32ex(Cmd, cmdp + 1, 0, 10);
                if (ng.time == 0 || ng.time > 200000) {
                    PrintAndLogEx(ERR, "Timing off 1..200000 limits, got %i", ng.time);
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 'b': {
                uint32_t n = param_getlength(Cmd, cmdp + 1);
                if (n > 128) {
                    PrintAndLogEx(ERR, "Bitstream too long, max 128 bits, got %i", n);
                    errors = true;
                    break;
                }
                for (uint8_t i = 0; i < n; i++) {
                    char c = param_getchar_indx(Cmd, i, cmdp + 1);
                    if (c == '0')
                        ng.data[i] = 0;
                    else if (c == '1')
                        ng.data[i] = 1;
                    else {
                        PrintAndLogEx(ERR, "Unknown bit char '%c'", c);
                        errors = true;
                        break;
                    }
                }
                ng.bitlen = n;
                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(ERR, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || ng.bitlen == 0 || ng.time == 0) {
        return usage_t55xx_dangerraw();
    }
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_DANGERRAW, (uint8_t *)&ng, sizeof(ng));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_DANGERRAW, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not ACK write operation.");
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int CmdT55xxReadTrace(const char *Cmd) {

    bool frombuff = false;
    uint8_t downlink_mode = config.downlink_mode;
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_trace();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case '1':
                frombuff = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_t55xx_trace();

    if (!frombuff) {
        // sanity check.
        if (SanityOfflineCheck(false) != PM3_SUCCESS) return PM3_ENODATA;

        bool pwdmode = false;
        uint32_t password = 0;

        // REGULAR_READ_MODE_BLOCK - yeilds correct Page 1 Block 2 data i.e. + 32 bit offset.
        if (!AcquireData(T55x7_PAGE1, REGULAR_READ_MODE_BLOCK, pwdmode, password, downlink_mode))
            return PM3_ENODATA;
    }

    if (config.Q5) {
        if (!DecodeT5555TraceBlock()) return PM3_ESOFT;
    } else {
        if (!DecodeT55xxBlock()) return PM3_ESOFT;
    }

    if (!DemodBufferLen) return PM3_ESOFT;

    RepaintGraphWindow();
    uint8_t repeat = (config.offset > 5) ? 32 : 0;

    uint8_t si = config.offset + repeat;
    uint32_t bl1 = PackBits(si, 32, DemodBuffer);
    uint32_t bl2 = PackBits(si + 32, 32, DemodBuffer);

    if (config.Q5) {
        uint32_t hdr = PackBits(si, 9,  DemodBuffer);
        si += 9;

        if (hdr != 0x1FF) {
            PrintAndLogEx(FAILED, "Invalid T555 ( Q5 ) Trace data header (expected 0x1FF, found %X)", hdr);
            return PM3_ESOFT;
        }

        t5555_tracedata_t data = {.bl1 = bl1, .bl2 = bl2, .icr = 0, .lotidc = '?', .lotid = 0, .wafer = 0, .dw = 0};

        data.icr     = PackBits(si, 2,  DemodBuffer);
        si += 2;
        data.lotidc  = 'Z' - PackBits(si, 2,  DemodBuffer);
        si += 3;

        data.lotid   = PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.lotid <<= 1;
        data.lotid  |= PackBits(si, 1,  DemodBuffer);
        si += 1;

        data.wafer   = PackBits(si, 3,  DemodBuffer);
        si += 4;
        data.wafer <<= 2;
        data.wafer  |= PackBits(si, 2,  DemodBuffer);
        si += 2;

        data.dw      = PackBits(si, 2,  DemodBuffer);
        si += 3;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  DemodBuffer);
        si += 5;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  DemodBuffer);

        printT5555Trace(data, repeat);

    } else {

        t55x7_tracedata_t data = {.bl1 = bl1, .bl2 = bl2, .acl = 0, .mfc = 0, .cid = 0, .year = 0, .quarter = 0, .icr = 0,  .lotid = 0, .wafer = 0, .dw = 0};

        data.acl = PackBits(si, 8,  DemodBuffer);
        si += 8;
        if (data.acl != 0xE0) {
            PrintAndLogEx(FAILED, "The modulation is most likely wrong since the ACL is not 0xE0. ");
            return PM3_ESOFT;
        }

        data.mfc     = PackBits(si, 8,  DemodBuffer);
        si += 8;
        data.cid     = PackBits(si, 5,  DemodBuffer);
        si += 5;
        data.icr     = PackBits(si, 3,  DemodBuffer);
        si += 3;
        data.year    = PackBits(si, 4,  DemodBuffer);
        si += 4;
        data.quarter = PackBits(si, 2,  DemodBuffer);
        si += 2;
        data.lotid   = PackBits(si, 14, DemodBuffer);
        si += 14;
        data.wafer   = PackBits(si, 5,  DemodBuffer);
        si += 5;
        data.dw      = PackBits(si, 15, DemodBuffer);

        struct tm *ct, tm_buf;
        time_t now = time(NULL);
#if defined(_WIN32)
        ct = localtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
        ct = localtime_r(&now, &tm_buf);
#endif

        if (data.year > ct->tm_year - 110)
            data.year += 2000;
        else
            data.year += 2010;

        printT55x7Trace(data, repeat);
    }
    return PM3_SUCCESS;
}

void printT55x7Trace(t55x7_tracedata_t data, uint8_t repeat) {
    PrintAndLogEx(NORMAL, "-- T55x7 Trace Information ----------------------------------");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, " ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X (%d)", data.acl, data.acl);
    PrintAndLogEx(NORMAL, " MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X (%d) - %s", data.mfc, data.mfc, getTagInfo(data.mfc));
    PrintAndLogEx(NORMAL, " CID                                     : 0x%02X (%d) - %s", data.cid, data.cid, GetModelStrFromCID(data.cid));
    PrintAndLogEx(NORMAL, " ICR IC Revision                         : %d", data.icr);
    PrintAndLogEx(NORMAL, " Manufactured");
    PrintAndLogEx(NORMAL, "     Year/Quarter : %d/%d", data.year, data.quarter);
    PrintAndLogEx(NORMAL, "     Lot ID       : %d", data.lotid);
    PrintAndLogEx(NORMAL, "     Wafer number : %d", data.wafer);
    PrintAndLogEx(NORMAL, "     Die Number   : %d", data.dw);
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, " Raw Data - Page 1");
    PrintAndLogEx(NORMAL, "     Block 1  : 0x%08X  %s", data.bl1, sprint_bin(DemodBuffer + config.offset + repeat, 32));
    PrintAndLogEx(NORMAL, "     Block 2  : 0x%08X  %s", data.bl2, sprint_bin(DemodBuffer + config.offset + repeat + 32, 32));
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");

    /*
    Trace info.
      M1, M2  has the about ATMEL defintion of trace data.
      M3 has unique format following industry defacto standard with row/col parity

    TRACE - BLOCK O
        Bits    Definition                             HEX
        1-8     ACL Allocation class (ISO/IEC 15963-1) 0xE0
        9-16    MFC Manufacturer ID (ISO/IEC 7816-6)   0x15 Atmel Corporation
        17-21   CID                                    0x1 = Atmel ATA5577M1
                                                       0x2 = Atmel ATA5577M2
                                                       0x3 = Atmel ATA5577M3
        22-24   ICR IC revision
        25-28   YEAR (BCD encoded)                     9 (= 2009)
        29-30   QUARTER                                1,2,3,4
        31-32   LOT ID

    TRACE - BLOCK 1
        1-12    LOT ID
        13-17   Wafer number
        18-32   DW,  die number sequential


    Startup times (FC)
      M1, M2 = 192
      M3     = 128
    */
}

void printT5555Trace(t5555_tracedata_t data, uint8_t repeat) {
    PrintAndLogEx(NORMAL, "-- T5555 ( Q5 ) Trace Information ---------------------------");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, " ICR IC Revision  : %d", data.icr);
    PrintAndLogEx(NORMAL, "     Lot          : %c%d", data.lotidc, data.lotid);
    PrintAndLogEx(NORMAL, "     Wafer number : %d", data.wafer);
    PrintAndLogEx(NORMAL, "     Die Number   : %d", data.dw);
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, " Raw Data - Page 1");
    PrintAndLogEx(NORMAL, "     Block 1  : 0x%08X  %s", data.bl1, sprint_bin(DemodBuffer + config.offset + repeat, 32));
    PrintAndLogEx(NORMAL, "     Block 2  : 0x%08X  %s", data.bl2, sprint_bin(DemodBuffer + config.offset + repeat + 32, 32));

    /*
        ** Q5 **
        TRACE - BLOCK O and BLOCK1
        Bits  Definition                HEX
        1-9   Header                  0x1FF
        10-11 IC Revision
        12-13 Lot ID char
        15-35 Lot ID (NB parity)
        36-41 Wafer number (NB parity)
        42-58 DW, die number sequential (NB parity)
        60-63 Parity bits
        64    Always zero
    */
}

static void printT5x7KnownBlock0(uint32_t b0) {

    char s[40];
    memset(s, 0, sizeof(s));

    switch (b0) {
        case T55X7_DEFAULT_CONFIG_BLOCK:
            snprintf(s, sizeof(s) - strlen(s), "T55x7 Default ");
            break;
        case T55X7_RAW_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "T55x7 Raw ");
            break;
        case T55X7_EM_UNIQUE_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "EM unique, Paxton ");
            break;
        case T55X7_FDXB_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "FDXB ");
            break;
        case T55X7_HID_26_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "HID 26b (ProxCard) ");
            break;
        case T55X7_PYRAMID_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Pyramid ");
            break;
        case T55X7_INDALA_64_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Indala 64");
            break;
        case T55X7_INDALA_224_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Indala 224 ");
            break;
        case T55X7_GUARDPROXII_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Guard Prox II ");
            break;
        case T55X7_VIKING_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Viking ");
            break;
        case T55X7_NORALYS_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Noralys ");
            break;
        case T55X7_IOPROX_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "IO Prox ");
            break;
        case T55X7_PRESCO_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Presco ");
            break;
        case T55X7_NEDAP_64_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Nedap 64 ");
            break;
        case T55X7_NEDAP_128_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Nedap 128 ");
            break;
        default:
            break;
    }

    if (strlen(s) > 0)
        PrintAndLogEx(NORMAL, "\n Config block match        : " _YELLOW_("%s"), s);
}

static int CmdT55xxInfo(const char *Cmd) {
    /*
        Page 0 Block 0 Configuration data.
        Normal mode
        Extended mode
    */
    bool frombuff = false, gotdata = false, dataasq5 = false, usepwd = false;
    uint8_t cmdp = 0;
    uint8_t downlink_mode = config.downlink_mode;
    uint32_t block0 = 0, password = 0;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_info();
            case 'c':
                block0 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotdata = true;
                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case '1':
                frombuff = true;
                cmdp += 2;
                break;
            case 'q':
                dataasq5 = true;
                cmdp += 2;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                return usage_t55xx_info();
        }
    }

    if (gotdata && frombuff)
        return usage_t55xx_info();

    if (dataasq5 && !gotdata)
        return usage_t55xx_info();

    if (!frombuff && !gotdata) {
        // sanity check.
        if (SanityOfflineCheck(false) != PM3_SUCCESS) return PM3_ENODATA;

        if (!AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, downlink_mode))
            return PM3_ENODATA;
    }

    if (!gotdata) {
        if (!DecodeT55xxBlock()) return PM3_ESOFT;

        // too little space to start with
        if (DemodBufferLen < 32 + config.offset) return PM3_ESOFT;

        //PrintAndLogEx(NORMAL, "Offset+32 ==%d\n DemodLen == %d", config.offset + 32, DemodBufferLen);
        block0 = PackBits(config.offset, 32, DemodBuffer);
    }

    PrintAndLogEx(NORMAL, "");
    if (((!gotdata) && config.Q5) || (gotdata && dataasq5)) {
        uint32_t header   = (block0 >> (32 - 12)) & 0xFFF;
        uint32_t ps       = (block0 >> (32 - 13)) & 0x01;
        uint32_t fw       = (block0 >> (32 - 14)) & 0x01;
        uint32_t dbr      = (block0 >> (32 - 20)) & 0x3F;
        uint32_t aor      = (block0 >> (32 - 21)) & 0x01;
        uint32_t pwd      = (block0 >> (32 - 22)) & 0x01;
        uint32_t pskcf    = (block0 >> (32 - 24)) & 0x03;
        uint32_t inv      = (block0 >> (32 - 25)) & 0x01;
        uint32_t datamod  = (block0 >> (32 - 28)) & 0x07;
        uint32_t maxblk   = (block0 >> (32 - 31)) & 0x07;
        uint32_t st       = block0 & 0x01;
        PrintAndLogEx(NORMAL, "--- " _CYAN_("Q5 Configuration & Information") " ------------");
        PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
        PrintAndLogEx(NORMAL, " Header                    : 0x%03X%s", header, (header != 0x600) ? _RED_(" - Warning") : "");
        PrintAndLogEx(NORMAL, " Page select               : %d", ps);
        PrintAndLogEx(NORMAL, " Fast Write                : %s", (fw)  ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " Data bit rate             : %s", GetBitRateStr(dbr, 1));
        PrintAndLogEx(NORMAL, " AOR - Answer on Request   : %s", (aor) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " Password mode             : %s", (pwd) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " PSK clock frequency       : %s", GetPskCfStr(pskcf, 1));
        PrintAndLogEx(NORMAL, " Inverse data              : %s", (inv) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " Modulation                : %s", GetQ5ModulationStr(datamod));
        PrintAndLogEx(NORMAL, " Max block                 : %d", maxblk);
        PrintAndLogEx(NORMAL, " Sequence Terminator       : %s", (st) ? _GREEN_("Yes") : "No");
    } else {
        uint32_t safer    = (block0 >> (32 -  4)) & 0x0F;
        uint32_t extend   = (block0 >> (32 - 15)) & 0x01;
        uint32_t resv, dbr;
        if (extend) {
            resv     = (block0 >> (32 -  8)) & 0x0F;
            dbr      = (block0 >> (32 - 14)) & 0x3F;
        } else {
            resv     = (block0 >> (32 - 11)) & 0x7F;
            dbr      = (block0 >> (32 - 14)) & 0x07;
        }
        uint32_t datamod  = (block0 >> (32 - 20)) & 0x1F;
        uint32_t pskcf    = (block0 >> (32 - 22)) & 0x03;
        uint32_t aor      = (block0 >> (32 - 23)) & 0x01;
        uint32_t otp      = (block0 >> (32 - 24)) & 0x01;
        uint32_t maxblk   = (block0 >> (32 - 27)) & 0x07;
        uint32_t pwd      = (block0 >> (32 - 28)) & 0x01;
        uint32_t sst      = (block0 >> (32 - 29)) & 0x01;
        uint32_t fw       = (block0 >> (32 - 30)) & 0x01;
        uint32_t inv      = (block0 >> (32 - 31)) & 0x01;
        uint32_t por      = (block0 >> (32 - 32)) & 0x01;

        PrintAndLogEx(NORMAL, "--- " _CYAN_("T55x7 Configuration & Information") " ---------");
        PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
        PrintAndLogEx(NORMAL, " Safer key                 : %s", GetSaferStr(safer));
        PrintAndLogEx(NORMAL, " reserved                  : %d", resv);
        PrintAndLogEx(NORMAL, " Data bit rate             : %s", GetBitRateStr(dbr, extend));
        PrintAndLogEx(NORMAL, " eXtended mode             : %s", (extend) ? _YELLOW_("Yes - Warning") : "No");
        PrintAndLogEx(NORMAL, " Modulation                : %s", GetModulationStr(datamod, extend));
        PrintAndLogEx(NORMAL, " PSK clock frequency       : %s", GetPskCfStr(pskcf, 0));
        PrintAndLogEx(NORMAL, " AOR - Answer on Request   : %s", (aor) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " OTP - One Time Pad        : %s", (otp) ? ((extend) ? _YELLOW_("Yes - Warning") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(NORMAL, " Max block                 : %d", maxblk);
        PrintAndLogEx(NORMAL, " Password mode             : %s", (pwd) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " Sequence %-12s     : %s", (extend) ? "Start Marker" : "Terminator", (sst) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(NORMAL, " Fast Write                : %s", (fw)  ? ((extend) ? _GREEN_("Yes") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(NORMAL, " Inverse data              : %s", (inv) ? ((extend) ? _GREEN_("Yes") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(NORMAL, " POR-Delay                 : %s", (por) ? _GREEN_("Yes") : "No");
    }
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, " Raw Data - Page 0");
    if (gotdata)
        PrintAndLogEx(NORMAL, "     Block 0  : 0x%08X", block0);
    else
        PrintAndLogEx(NORMAL, "     Block 0  : 0x%08X  %s", block0, sprint_bin(DemodBuffer + config.offset, 32));

    if (((!gotdata) && (!config.Q5)) || (gotdata && (!dataasq5)))
        printT5x7KnownBlock0(block0);

    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");

    return PM3_SUCCESS;
}

static int CmdT55xxDump(const char *Cmd) {

    uint32_t password = 0;
    uint8_t override = 0;
    uint8_t downlink_mode = config.downlink_mode;
    bool usepwd = false;
    bool errors = false;
    uint8_t cmdp = 0;
    char preferredName[FILE_PATH_SIZE] = {0};
    bool success = true;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_dump();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case 'o':
                override = 1;
                cmdp++;
                break;
            case 'f':
                param_getstr(Cmd, cmdp + 1, preferredName, FILE_PATH_SIZE);
                cmdp += 2;
                if (strlen(preferredName) == 0)
                    errors = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_dump();

    // Due to the few different T55xx cards and number of blocks supported
    // will save the dump file if ALL page 0 is OK
    printT5xxHeader(0);
    for (uint8_t i = 0; i < 8; ++i) {
        if (T55xxReadBlock(i, 0, usepwd, override, password, downlink_mode) != PM3_SUCCESS)
            success = false;
        // idea for better user experience and display.
        // only show override warning on the first block read
        if (override == 1) override++; // flag not to show safty for 2nd and on.
    }
    printT5xxHeader(1);
    for (uint8_t i = 0; i < 4; i++)
        if (T55xxReadBlock(i, 1, usepwd, override, password, downlink_mode) != PM3_SUCCESS)
            T55x7_SaveBlockData(8 + i, 0x00);


    if (success) { // all ok save dump to file
        // saveFileEML will add .eml extension to filename
        // saveFile (binary) passes in the .bin extension.
        if (strcmp(preferredName, "") == 0) { // Set default filename, if not set by user
            strcpy(preferredName, "lf-t55xx");
            for (uint8_t i = 1; i <= 7; i++) {
                if ((cardmem[i].blockdata != 0x00) && (cardmem[i].blockdata != 0xFFFFFFFF))
                    sprintf(preferredName + strlen(preferredName), "-%08X", cardmem[i].blockdata);
                else
                    break;
            }
            strcat(preferredName, "-dump");
        }

        // Swap endian so the files match the txt display
        uint32_t data[T55x7_BLOCK_COUNT];

        for (int i = 0; i < T55x7_BLOCK_COUNT; i++)
            data[i] = BSWAP_32(cardmem[i].blockdata);

        saveFileJSON(preferredName, jsfT55x7, (uint8_t *)data, T55x7_BLOCK_COUNT * sizeof(uint32_t), NULL);
        saveFileEML(preferredName, (uint8_t *)data, T55x7_BLOCK_COUNT * sizeof(uint32_t), sizeof(uint32_t));
        saveFile(preferredName, ".bin", data, sizeof(data));
    }

    return PM3_SUCCESS;
}

static int CmdT55xxRestore(const char *Cmd) {
    bool errors = false;
    uint8_t cmdp = 0;
    char preferredName[FILE_PATH_SIZE] = {0};
    char ext[FILE_PATH_SIZE] = {0};
    int success = PM3_ESOFT;
    uint32_t password = 0x00;
    bool usepwd = false;
    uint32_t data[12] = {0};
    size_t datalen = 0;
    uint8_t blockidx;
    uint8_t downlink_mode;
    char writeCmdOpt[100];
    char pwdOpt [11] = {0}; // p XXXXXXXX

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_restore();
            case 'f':
                param_getstr(Cmd, cmdp + 1, preferredName, FILE_PATH_SIZE);
                if (strlen(preferredName) == 0)
                    errors = true;
                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // File name expected to be .eml .bin or .json so sould be at least 4
    if (errors || (strlen(preferredName) == 0)) return usage_t55xx_restore();

    // split file name into prefix and ext.
    int fnLength;

    fnLength = strlen(preferredName);

    success = PM3_ESOFT;
    if (fnLength > 4) { // Holds extension [.bin|.eml]
        memcpy(ext, &preferredName[fnLength - 4], 4);
        ext[5] = 0x00;

        //  check if valid file extension and attempt to load data

        if (memcmp(ext, ".bin", 4) == 0) {
            preferredName[fnLength - 4] = 0x00;
            success = loadFile(preferredName, ".bin", data, sizeof(data), &datalen);

        } else if (memcmp(ext, ".eml", 4) == 0) {
            preferredName[fnLength - 4] = 0x00;
            datalen = 12;
            success = loadFileEML(preferredName, (uint8_t *)data, &datalen);

        } else
            PrintAndLogEx(WARNING, "\nWarning: invalid dump filename "_YELLOW_("%s")" to restore!\n", preferredName);
    }

    if (success == PM3_SUCCESS) { // Got data, so write to cards
        if (datalen == T55x7_BLOCK_COUNT * 4) { // 12 blocks * 4 bytes per block
            if (usepwd)
                sprintf(pwdOpt, "p %08X", password);

            // Restore endien for writing to card
            for (blockidx = 0; blockidx < 12; blockidx++)
                data[blockidx] = BSWAP_32(data[blockidx]);

            // Have data ready, lets write
            // Order
            //    write blocks 1..7 page 0
            //    write blocks 1..3 page 1
            //    update downlink mode (if needed) and write b 0
            downlink_mode = 0;
            if ((((data[11] >> 28) & 0xf) == 6) || (((data[11] >> 28) & 0xf) == 9))
                downlink_mode = (data[11] >> 10) & 3;

            // write out blocks 1-7 page 0
            for (blockidx = 1; blockidx <= 7; blockidx++) {
                sprintf(writeCmdOpt, "b %d d %08X %s", blockidx, data[blockidx], pwdOpt);
                if (CmdT55xxWriteBlock(writeCmdOpt) != PM3_SUCCESS)
                    PrintAndLogEx(WARNING, "Warning: error writing blk %d", blockidx);
            }

            // if password was set on the "blank" update as we may have just changed it
            if (usepwd)
                sprintf(pwdOpt, "p %08X", data[7]);

            // write out blocks 1-3 page 1
            for (blockidx = 9; blockidx <= 11; blockidx++) {
                sprintf(writeCmdOpt, "b %d 1 d %08X %s", blockidx - 8, data[blockidx], pwdOpt);
                if (CmdT55xxWriteBlock(writeCmdOpt) != PM3_SUCCESS)
                    PrintAndLogEx(WARNING, "Warning: error writing blk %d", blockidx);
            }

            // Update downlink mode for the page 0 config write.
            config.downlink_mode = downlink_mode;

            // Write the page 0 config
            sprintf(writeCmdOpt, "b 0 d %08X %s", data[0], pwdOpt);
            if (CmdT55xxWriteBlock(writeCmdOpt) != PM3_SUCCESS)
                PrintAndLogEx(WARNING, "Warning: error writing blk 0");
        }
    }

    return PM3_SUCCESS;
}
/*
static int CmdT55xxRestore(const char *Cmd) {

    uint32_t password = 0;
    uint8_t override = 0;
    uint8_t downlink_mode = config.downlink_mode;
    bool usepwd = false;
    bool errors = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_restore();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case 'o':
                override = 1;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_restore();

    PrintAndLogEx(INFO,  "Work in progress.  To be implemented");
    if (usepwd || password || override ) {

    }
    // load file name  (json/eml/bin)

    // Print dump data?

    uint32_t res = PM3_SUCCESS;

// page0.
//    res = clone_t55xx_tag(blockdata, numblocks);

    return res;
}
*/
bool AcquireData(uint8_t page, uint8_t block, bool pwdmode, uint32_t password, uint8_t downlink_mode) {
    // arg0 bitmodes:
    //  b0 = pwdmode
    //  b1 = page to read from
    //  b2 = brute_mem (armside function)
    // arg1: which block to read
    // arg2: password
    struct p {
        uint32_t password;
        uint8_t  blockno;
        uint8_t  page;
        bool     pwdmode;
        uint8_t  downlink_mode;
    } PACKED;
    struct p payload;
    payload.password      = password;
    payload.blockno       = block;
    payload.page          = page & 0x1;
    payload.pwdmode       = pwdmode;
    payload.downlink_mode = downlink_mode;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_READBL, (uint8_t *)&payload, sizeof(payload));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_READBL, NULL, 2500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    getSamples(12000, false);

    return !getSignalProperties()->isnoise;
}

char *GetPskCfStr(uint32_t id, bool q5) {
    static char buf[40];
    char *retStr = buf;
    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - RF/2", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - RF/4", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - RF/8", id);
            break;
        case 3:
            if (q5)
                snprintf(retStr, sizeof(buf), "%u - RF/8", id);
            else
                snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
            break;
        default:
            snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
            break;
    }
    return buf;
}

char *GetBitRateStr(uint32_t id, bool xmode) {
    static char buf[25];

    char *retStr = buf;
    if (xmode) { //xmode bitrate calc is same as em4x05 calc
        snprintf(retStr, sizeof(buf), "%u - RF/%d", id, EM4x05_GET_BITRATE(id));
    } else {
        switch (id) {
            case 0:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/8"), id);
                break;
            case 1:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/16"), id);
                break;
            case 2:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/32"), id);
                break;
            case 3:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/40"), id);
                break;
            case 4:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/50"), id);
                break;
            case 5:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/64"), id);
                break;
            case 6:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/100"), id);
                break;
            case 7:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/128"), id);
                break;
            default:
                snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
                break;
        }
    }
    return buf;
}

char *GetSaferStr(uint32_t id) {
    static char buf[40];
    char *retStr = buf;

    snprintf(retStr, sizeof(buf), "%u", id);
    if (id == 6) {
        snprintf(retStr, sizeof(buf), "%u - " _YELLOW_("passwd"), id);
    }
    if (id == 9) {
        snprintf(retStr, sizeof(buf), "%u - " _YELLOW_("testmode"), id);
    }

    return buf;
}

char *GetModulationStr(uint32_t id, bool xmode) {
    static char buf[60];
    char *retStr = buf;

    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - DIRECT (ASK/NRZ)", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - PSK 1 phase change when input changes", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - PSK 2 phase change on bitclk if input high", id);
            break;
        case 3:
            snprintf(retStr, sizeof(buf), "%u - PSK 3 phase change on rising edge of input", id);
            break;
        case 4:
            snprintf(retStr, sizeof(buf), "%u - FSK 1 RF/8  RF/5", id);
            break;
        case 5:
            snprintf(retStr, sizeof(buf), "%u - FSK 2 RF/8  RF/10", id);
            break;
        case 6:
            snprintf(retStr, sizeof(buf), "%u - %s RF/5  RF/8", id, (xmode) ? "FSK 1a" : _YELLOW_("FSK 1a"));
            break;
        case 7:
            snprintf(retStr, sizeof(buf), "%u - %s RF/10  RF/8", id, (xmode) ? "FSK 2a" : _YELLOW_("FSK 2a"));
            break;
        case 8:
            snprintf(retStr, sizeof(buf), "%u - Manchester", id);
            break;
        case 16:
            snprintf(retStr, sizeof(buf), "%u - Biphase", id);
            break;
        case 24:
            snprintf(retStr, sizeof(buf), "%u - %s", id, (xmode) ? "Biphase a - AKA Conditional Dephase Encoding(CDP)" : _YELLOW_("Reserved"));
            break;
        default:
            snprintf(retStr, sizeof(buf), "0x%02X " _RED_("(Unknown)"), id);
            break;
    }
    return buf;
}

char *GetDownlinkModeStr(uint8_t downlink_mode) {
    static char buf[30];
    char *retStr = buf;

    switch (downlink_mode) {
        case T55XX_DLMODE_FIXED :
            snprintf(retStr, sizeof(buf), "default/fixed bit length");
            break;
        case T55XX_DLMODE_LLR :
            snprintf(retStr, sizeof(buf), "long leading reference");
            break;
        case T55XX_DLMODE_LEADING_ZERO :
            snprintf(retStr, sizeof(buf), "leading zero reference");
            break;
        case T55XX_DLMODE_1OF4 :
            snprintf(retStr, sizeof(buf), "1 of 4 coding reference");
            break;
        default:
            snprintf(retStr, sizeof(buf), _RED_("(Unknown)"));
            break;
    }
    return buf;
}

char *GetQ5ModulationStr(uint32_t id) {
    static char buf[60];
    char *retStr = buf;

    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - Manchester", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - PSK 1 phase change when input changes", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - PSK 2 phase change on bitclk if input high", id);
            break;
        case 3:
            snprintf(retStr, sizeof(buf), "%u - PSK 3 phase change on rising edge of input", id);
            break;
        case 4:
            snprintf(retStr, sizeof(buf), "%u - FSK 1a RF/5  RF/8", id);
            break;
        case 5:
            snprintf(retStr, sizeof(buf), "%u - FSK 2a RF/10  RF/8", id);
            break;
        case 6:
            snprintf(retStr, sizeof(buf), "%u - Biphase", id);
            break;
        case 7:
            snprintf(retStr, sizeof(buf), "%u - NRZ / Direct", id);
            break;
    }
    return buf;
}

char *GetModelStrFromCID(uint32_t cid) {

    static char buf[10];
    char *retStr = buf;

    if (cid == 1) snprintf(retStr, sizeof(buf), "ATA5577M1");
    if (cid == 2) snprintf(retStr, sizeof(buf), "ATA5577M2");
    if (cid == 3) snprintf(retStr, sizeof(buf), "ATA5577M3");
    return buf;
}

char *GetSelectedModulationStr(uint8_t id) {

    static char buf[20];
    char *retStr = buf;

    switch (id) {
        case DEMOD_FSK:
            snprintf(retStr, sizeof(buf), "FSK");
            break;
        case DEMOD_FSK1:
            snprintf(retStr, sizeof(buf), "FSK1");
            break;
        case DEMOD_FSK1a:
            snprintf(retStr, sizeof(buf), "FSK1a");
            break;
        case DEMOD_FSK2:
            snprintf(retStr, sizeof(buf), "FSK2");
            break;
        case DEMOD_FSK2a:
            snprintf(retStr, sizeof(buf), "FSK2a");
            break;
        case DEMOD_ASK:
            snprintf(retStr, sizeof(buf), "ASK");
            break;
        case DEMOD_NRZ:
            snprintf(retStr, sizeof(buf), "DIRECT/NRZ");
            break;
        case DEMOD_PSK1:
            snprintf(retStr, sizeof(buf), "PSK1");
            break;
        case DEMOD_PSK2:
            snprintf(retStr, sizeof(buf), "PSK2");
            break;
        case DEMOD_PSK3:
            snprintf(retStr, sizeof(buf), "PSK3");
            break;
        case DEMOD_BI:
            snprintf(retStr, sizeof(buf), "BIPHASE");
            break;
        case DEMOD_BIa:
            snprintf(retStr, sizeof(buf), "BIPHASEa - (CDP)");
            break;
        default:
            snprintf(retStr, sizeof(buf), _RED_("(Unknown)"));
            break;
    }
    return buf;
}

/*
static void t55x7_create_config_block(int tagtype) {

    // T55X7_DEFAULT_CONFIG_BLOCK, T55X7_RAW_CONFIG_BLOCK
    // T55X7_EM_UNIQUE_CONFIG_BLOCK, T55X7_FDXB_CONFIG_BLOCK,
    // T55X7_FDXB_CONFIG_BLOCK, T55X7_HID_26_CONFIG_BLOCK, T55X7_INDALA_64_CONFIG_BLOCK, T55X7_INDALA_224_CONFIG_BLOCK
    // T55X7_GUARDPROXII_CONFIG_BLOCK, T55X7_VIKING_CONFIG_BLOCK, T55X7_NORALYS_CONFIG_BLOCK, T55X7_IOPROX_CONFIG_BLOCK
    static char buf[60];
    char *retStr = buf;

    switch (tagtype) {
        case 0:
            snprintf(retStr, sizeof(buf), "%08X - T55X7 Default", T55X7_DEFAULT_CONFIG_BLOCK);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%08X - T55X7 Raw", T55X7_RAW_CONFIG_BLOCK);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%08X - T5555 ( Q5 ) Default", T5555_DEFAULT_CONFIG_BLOCK);
            break;
        default:
            break;
    }
    PrintAndLogEx(NORMAL, buf);
}
*/

static int CmdResetRead(const char *Cmd) {

    uint8_t downlink_mode = config.downlink_mode;
    uint8_t flags = 0;
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_resetread();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_t55xx_resetread();

    flags = downlink_mode << 3;

    PacketResponseNG resp;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_RESET_READ, &flags, sizeof(flags));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_RESET_READ, &resp, 2500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {

        uint16_t gotsize = pm3_capabilities.bigbuf_size - 1;
        uint8_t *got = calloc(gotsize, sizeof(uint8_t));
        if (got == NULL) {
            PrintAndLogEx(WARNING, "failed to allocate memory");
            return PM3_EMALLOC;
        }

        if (!GetFromDevice(BIG_BUF, got, gotsize, 0, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            free(got);
            return PM3_ETIMEOUT;
        }
        setGraphBuf(got, gotsize);
        free(got);
    }
    return PM3_SUCCESS;
}

static int CmdT55xxWipe(const char *Cmd) {

    char writeData[36] = {0};
    char *ptrData = writeData;
    uint32_t password = 0, block0 = 0;
    bool usepwd = false, Q5 = false, gotconf = false;
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_wipe();
            case 'p':
                // password used by handheld cloners
                password = param_get32ex(Cmd, cmdp + 1, 0x51243648, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case 'c':
                block0 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotconf = true;
                cmdp += 2;
                break;
            case 'q':
                Q5 = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_t55xx_wipe();


    PrintAndLogEx(INFO, "\nBegin wiping %s", (Q5) ? "T5555 ( Q5 ) tag" : "T55x7 tag");

    // default config blocks.
    if (gotconf == false) {
        block0 = (Q5) ? 0x6001F004 : 0x000880E0;
    }

    char msg[80] = {0};

    if (gotconf)
        snprintf(msg, sizeof(msg), "User provided configuration block %08X", block0);
    else
        snprintf(msg, sizeof(msg), "Default configation block %08X", block0);

    PrintAndLogEx(INFO, "%s", msg);

    // Creating cmd string for write block :)
    snprintf(ptrData, sizeof(writeData), "b 0 ");

    if (usepwd) {
        snprintf(ptrData + strlen(writeData), sizeof(writeData) - strlen(writeData), "p %08x ", password);
    }
    snprintf(ptrData + strlen(writeData), sizeof(writeData) - strlen(writeData), "d %08X", block0);

    if (CmdT55xxWriteBlock(ptrData) != PM3_SUCCESS)
        PrintAndLogEx(WARNING, "Warning: error writing blk 0");

    for (uint8_t blk = 1; blk < 8; blk++) {

        snprintf(ptrData, sizeof(writeData), "b %d d 0", blk);

        if (CmdT55xxWriteBlock(ptrData) != PM3_SUCCESS)
            PrintAndLogEx(WARNING, "Warning: error writing blk %d", blk);

        memset(writeData, 0x00, sizeof(writeData));
    }

    // Check and rest t55xx downlink mode.
    if (config.downlink_mode != T55XX_DLMODE_FIXED) { // Detect found a different mode so card must support
        snprintf(ptrData, sizeof(writeData), "b 3 1 d 00000000");
        if (CmdT55xxWriteBlock(ptrData) != PM3_SUCCESS)
            PrintAndLogEx(WARNING, "Warning: failed writing block 3 page 1 (config)");
        memset(writeData, 0x00, sizeof(writeData));
    }
    return PM3_SUCCESS;
}

static bool IsCancelled(void) {
    if (kbd_enter_pressed()) {
        PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
        return true;
    }
    return false;
}

// load a default pwd file.
static int CmdT55xxChkPwds(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    bool found = false;
    uint8_t timeout = 0;
    uint8_t *keyBlock = NULL;
    bool from_flash = false;
    bool try_all_dl_modes = false;
    uint8_t downlink_mode = 0;
    bool use_pwd_file = false;
    int dl_mode; // to try each downlink mode for each password
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_chk();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode >= 4) {
                    try_all_dl_modes = true;
                    downlink_mode = 0;
                }
                cmdp += 2;
                break;
            case 'm':
                from_flash = true;
                cmdp++;
                break;
            case 'i':
                if (param_getstr(Cmd, cmdp + 1, filename, sizeof(filename)) == 0) {
                    PrintAndLogEx(ERR, "Error, no filename after 'f' was found");
                    errors = true;
                }
                use_pwd_file = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_t55xx_chk();

    /*
    // block 7,  page1 = false, usepwd = false, override = false, pwd = 00000000
    if ( T55xxReadBlock(7, false, false, false, 0x00000000) == PM3_SUCCESS) {

        // now try to validate it..
        PrintAndLogEx(WARNING, "\n Block 7 was readable");
        return PM3_SUCCESS;
    }
    */

    uint64_t t1 = msclock();
    uint8_t flags = downlink_mode << 3;

    if (from_flash) {
        clearCommandBuffer();
        SendCommandNG(CMD_LF_T55XX_CHK_PWDS, &flags, sizeof(flags));
        PacketResponseNG resp;

        while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            timeout++;
            printf(".");
            fflush(stdout);
            if (timeout > 180) {
                PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
                return PM3_ENODATA;
            }
        }

        if (resp.oldarg[0]) {
            PrintAndLogEx(SUCCESS, "\nFound a candidate [ " _YELLOW_("%08"PRIX64) " ]. Trying to validate", resp.oldarg[1]);

            if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, resp.oldarg[1], downlink_mode)) {
                found = tryDetectModulation(downlink_mode, T55XX_PrintConfig);
                if (found) {
                    PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08"PRIX64) " ]", resp.oldarg[1]);

                } else {
                    PrintAndLogEx(WARNING, "Check pwd failed");
                }
            } else {
                PrintAndLogEx(WARNING, "Check pwd failed");
            }
        } else {
            PrintAndLogEx(WARNING, "Check pwd failed");
        }
        goto out;
    }

    if (use_pwd_file) {
        uint32_t keycount = 0;

        int res = loadFileDICTIONARY_safe(filename, (void **) &keyBlock, 4, &keycount);
        if (res != PM3_SUCCESS || keycount == 0 || keyBlock == NULL) {
            PrintAndLogEx(WARNING, "No keys found in file");
            if (keyBlock != NULL)
                free(keyBlock);

            return PM3_ESOFT;
        }

        for (uint32_t c = 0; c < keycount; ++c) {

            if (!session.pm3_present) {
                PrintAndLogEx(WARNING, "Device offline\n");
                free(keyBlock);
                return PM3_ENODATA;
            }

            if (IsCancelled()) {
                free(keyBlock);
                return PM3_EOPABORTED;
            }

            uint64_t curr_password = bytes_to_num(keyBlock + 4 * c, 4);

            PrintAndLogEx(INFO, "Testing %08"PRIX64, curr_password);
            for (dl_mode = downlink_mode; dl_mode <= 3; dl_mode++) {

                if (!AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, curr_password, dl_mode)) {
                    continue;
                }

                found = tryDetectModulation(dl_mode, T55XX_PrintConfig);
                if (found) {
                    PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08"PRIX64) " ]", curr_password);
                    dl_mode = 4; // Exit other downlink mode checks
                    c = keycount; // Exit loop
                }

                if (!try_all_dl_modes) // Exit loop if not trying all downlink modes
                    dl_mode = 4;
            }
        }
        if (!found) PrintAndLogEx(WARNING, "Check pwd failed");
    }

    free(keyBlock);

out:
    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\nTime in check pwd: %.0f seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

// Bruteforce - incremental password range search
static int CmdT55xxBruteForce(const char *Cmd) {

    uint32_t start_password = 0x00000000; //start password
    uint32_t end_password = 0xFFFFFFFF; //end   password
    uint32_t curr = 0;
    uint8_t downlink_mode = 0;
    uint8_t found = 0; // > 0 if found xx1 xx downlink needed, 1 found
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_bruteforce();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 4)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case 's':
                start_password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'e':
                end_password   = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (start_password >= end_password)
        errors = true;

    if (errors || cmdp == 0) return usage_t55xx_bruteforce();

    uint64_t t1 = msclock();

    curr = start_password;

    PrintAndLogEx(INFO, "Search password range [%08X -> %08X]", start_password, end_password);

    while (found == 0) {

        printf(".");
        fflush(stdout);

        if (IsCancelled()) {
            return PM3_EOPABORTED;
        }

        found = tryOnePassword(curr, downlink_mode);

        if (curr == end_password)
            break;

        curr++;
    }

    PrintAndLogEx(NORMAL, "");

    if (found) {
        PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr - 1);
        T55xx_Print_DownlinkMode((found >> 1) & 3);
    } else
        PrintAndLogEx(WARNING, "Bruteforce failed, last tried: [ " _YELLOW_("%08X") " ]", curr);

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\nTime in bruteforce: %.0f seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

uint8_t tryOnePassword(uint32_t password, uint8_t downlink_mode) {

    bool  try_all_dl_modes = false;
    uint8_t dl_mode          = 0;

    PrintAndLogEx(INFO, "Trying password %08X", password);

    if (downlink_mode == 4) try_all_dl_modes = true;

    downlink_mode = (downlink_mode & 3); // ensure 0-3

    // check if dl mode 4 and loop if needed
    for (dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {

        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, password, dl_mode)) {
            //  if (getSignalProperties()->isnoise == false) {
            //  } else {
            if (tryDetectModulation(dl_mode, T55XX_PrintConfig)) {
                return 1 + (dl_mode << 1);
            }
            //  }
        }
        if (!try_all_dl_modes) dl_mode = 4;
    }
    return 0;
}

static int CmdT55xxRecoverPW(const char *Cmd) {
    int bit = 0;
    uint32_t orig_password = 0x0;
    uint32_t curr_password = 0x0;
    uint32_t prev_password = 0xffffffff;
    uint32_t mask = 0x0;
    uint8_t downlink_mode = 0;
    uint8_t found = 0;
    uint8_t cmdp = 0;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_recoverpw();
            case 'p':
                // password used by handheld cloners
                orig_password = param_get32ex(Cmd, cmdp + 1, 0x51243648, 16);
                cmdp += 2;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 4)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_t55xx_recoverpw();

    // first try fliping each bit in the expected password
    while (bit < 32) {
        curr_password = orig_password ^ (1u << bit);
        found = tryOnePassword(curr_password, downlink_mode);
        if (found > 0) // xx1 for found xx = dl mode used
            goto out;

        bit++;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

    // now try to use partial original password, since block 7 should have been completely
    // erased during the write sequence and it is possible that only partial password has been
    // written
    // not sure from which end the bit bits are written, so try from both ends
    // from low bit to high bit
    bit = 0;
    while (bit < 32) {
        mask += (1u << bit);
        curr_password = orig_password & mask;
        // if updated mask didn't change the password, don't try it again
        if (prev_password == curr_password) {
            bit++;
            continue;
        }

        found = tryOnePassword(curr_password, downlink_mode);
        if (found > 0)
            goto out;

        bit++;
        prev_password = curr_password;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

    // from high bit to low
    bit = 0;
    mask = 0xffffffff;
    while (bit < 32) {
        mask -= (1u << bit);
        curr_password = orig_password & mask;
        // if updated mask didn't change the password, don't try it again
        if (prev_password == curr_password) {
            bit++;
            continue;
        }
        found = tryOnePassword(curr_password, downlink_mode);
        if (found > 0)
            goto out;

        bit++;
        prev_password = curr_password;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

out:

    PrintAndLogEx(NORMAL, "");

    if (found > 0) {
        PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr_password);
        T55xx_Print_DownlinkMode((found >> 1) & 3);
    } else
        PrintAndLogEx(WARNING, "Recover pwd failed");

    return PM3_SUCCESS;
}

// note length of data returned is different for different chips.
// some return all page 1 (64 bits) and others return just that block (32 bits)
// unfortunately the 64 bits makes this more likely to get a false positive...
bool tryDetectP1(bool getData) {
    uint8_t  preamble[] = {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1};
    size_t   startIdx   = 0;
    uint8_t  fc1        = 0, fc2 = 0, ans = 0;
    int      clk        = 0, firstClockEdge = 0;
    bool     st         = true;

    if (getData) {
        if (!AcquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, false, 0, 0))
            return false;
    }

    // try fsk clock detect. if successful it cannot be any other type of modulation...  (in theory...)
    ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);
    if (ans && ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5))) {
        if ((FSKrawDemod("0 0", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }
        if ((FSKrawDemod("0 1", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }
        return false;
    }

    // try ask clock detect.  it could be another type even if successful.
    clk = GetAskClock("", false);
    if (clk > 0) {
        if ((ASKDemod_ext("0 0 1", false, false, 1, &st) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }

        st = true;
        if ((ASKDemod_ext("0 1 1", false, false, 1, &st) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }

        if ((ASKbiphaseDemod("0 0 0 2", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }

        if ((ASKbiphaseDemod("0 0 1 2", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }
    }

    // try NRZ clock detect.  it could be another type even if successful.
    clk = GetNrzClock("", false); //has the most false positives :(
    if (clk > 0) {
        if ((NRZrawDemod("0 0 1", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }
        if ((NRZrawDemod("0 1 1", false) == PM3_SUCCESS)  &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            return true;
        }
    }

    // Fewer card uses PSK
    // try psk clock detect. if successful it cannot be any other type of modulation... (in theory...)
    clk = GetPskClock("", false);
    if (clk > 0) {
        // allow undo
        // save_restoreGB(GRAPH_SAVE);
        // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
        //CmdLtrim("160");
        if ((PSKDemod("0 0 6", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            //save_restoreGB(GRAPH_RESTORE);
            return true;
        }
        if ((PSKDemod("0 1 6", false) == PM3_SUCCESS) &&
                preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                (DemodBufferLen == 32 || DemodBufferLen == 64)) {
            //save_restoreGB(GRAPH_RESTORE);
            return true;
        }
        // PSK2 - needs a call to psk1TOpsk2.
        if (PSKDemod("0 0 6", false) == PM3_SUCCESS) {
            psk1TOpsk2(DemodBuffer, DemodBufferLen);
            if (preambleSearchEx(DemodBuffer, preamble, sizeof(preamble), &DemodBufferLen, &startIdx, false) &&
                    (DemodBufferLen == 32 || DemodBufferLen == 64)) {
                //save_restoreGB(GRAPH_RESTORE);
                return true;
            }
        } // inverse waves does not affect PSK2 demod
        //undo trim samples
        //save_restoreGB(GRAPH_RESTORE);
        // no other modulation clocks = 2 or 4 so quit searching
        if (fc1 != 8) return false;
    }

    return false;
}
//  does this need to be a callable command?
static int CmdT55xxDetectPage1(const char *Cmd) {
    bool errors = false;
    bool useGB = false;
    bool usepwd = false;
    bool try_all_dl_modes = true;
    bool found = false;
    uint8_t found_mode = 0;
    uint32_t password = 0;
    uint8_t cmdp = 0;
    uint8_t downlink_mode = config.downlink_mode;
    uint8_t dl_mode = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_detectP1();
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case '1':
                // use Graphbuffer data
                useGB = true;
                cmdp++;
                break;
            case 'r':
                //ICEMAN STRANGE
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode == 4)
                    try_all_dl_modes = true;
                if (downlink_mode < 4)
                    try_all_dl_modes = false;
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_detectP1();

    if (!useGB) {
        for (dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {
            found = AcquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, usepwd, password, dl_mode);
            if (found == false)
                continue;

            if (tryDetectP1(false)) {
                found = true;
                found_mode = dl_mode;
                dl_mode = 4;
            } else {
                found = false;
            }

            if (!try_all_dl_modes) {
                dl_mode = 4;
            }
        }

    } else {
        found = tryDetectP1(false);
    }

    if (found) {
        PrintAndLogEx(SUCCESS, "T55xx chip found!");
        T55xx_Print_DownlinkMode(found_mode);
    } else
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));

    return PM3_SUCCESS;
}

static int CmdT55xxSetDeviceConfig(const char *Cmd) {
    uint8_t startgap = 0, writegap = 0, readgap = 0;
    uint8_t write0 = 0, write1 = 0, write2 = 0, write3 = 0;
    uint8_t cmdp = 0, downlink_mode = 0;
    bool errors = false, shall_persist = false, set_defaults  = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_deviceconfig();
            case 'a':
                errors |= param_getdec(Cmd, cmdp + 1, &startgap);
                cmdp += 2;
                break;
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &writegap);
                cmdp += 2;
                break;
            case 'c':
                errors |= param_getdec(Cmd, cmdp + 1, &write0);
                cmdp += 2;
                break;
            case 'd':
                errors |= param_getdec(Cmd, cmdp + 1, &write1);
                cmdp += 2;
                break;
            case 'e':
                errors |= param_getdec(Cmd, cmdp + 1, &readgap);
                cmdp += 2;
                break;
            case 'f':
                errors |= param_getdec(Cmd, cmdp + 1, &write2);
                cmdp += 2;
                break;
            case 'g':
                errors |= param_getdec(Cmd, cmdp + 1, &write3);
                cmdp += 2;
                break;
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;
                cmdp += 2;
                break;
            case 'p':
                shall_persist = true;
                cmdp++;
                break;
            case 'z':
                set_defaults = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = 1;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_t55xx_deviceconfig();

    t55xx_configurations_t configurations = {{{0}, {0}, {0}, {0}}};

    if (set_defaults) {
        // fixed bit length
        configurations.m[T55XX_DLMODE_FIXED].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_1    = 47 * 8;
        configurations.m[T55XX_DLMODE_FIXED].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_2    = 0;
        configurations.m[T55XX_DLMODE_FIXED].write_3    = 0;

        // long leading reference
        configurations.m[T55XX_DLMODE_LLR].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_1    = 47 * 8;
        configurations.m[T55XX_DLMODE_LLR].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_2    = 0;
        configurations.m[T55XX_DLMODE_LLR].write_3    = 0;

        // leading zero
        configurations.m[T55XX_DLMODE_LEADING_ZERO].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_1    = 40 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_2    = 0;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_3    = 0;

        // 1 of 4 coding reference
        configurations.m[T55XX_DLMODE_1OF4].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_1    = 31 * 8;
        configurations.m[T55XX_DLMODE_1OF4].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_2    = 47 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_3    = 63 * 8;

    } else {
        configurations.m[downlink_mode].start_gap  = startgap * 8;
        configurations.m[downlink_mode].write_gap  = writegap * 8;
        configurations.m[downlink_mode].write_0    = write0   * 8;
        configurations.m[downlink_mode].write_1    = write1   * 8;
        configurations.m[downlink_mode].read_gap   = readgap  * 8;
        configurations.m[downlink_mode].write_2    = write2   * 8;
        configurations.m[downlink_mode].write_3    = write3   * 8;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_T55XX_SET_CONFIG, shall_persist, 0, 0, &configurations, sizeof(t55xx_configurations_t));
    return PM3_SUCCESS;
}

static int CmdT55xxProtect(const char *Cmd) {
    bool errors = false, usepwd = false, gotnewpwd = false;
    uint32_t password = 0, new_password = 0;
    uint8_t override = 0;
    uint8_t cmdp = 0;
    uint8_t downlink_mode = config.downlink_mode;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_protect();
            case 'o':
                override = 2;
                cmdp++;
                break;
            case 'n':
                new_password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotnewpwd = true;
                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                override = 1;
                cmdp += 2;
                break;
            case 'r':
                //ICEMAN STRANGE
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (gotnewpwd == false)
        return usage_t55xx_protect();

    if (errors || cmdp == 0) return usage_t55xx_protect();

    // sanity check.
    if (SanityOfflineCheck(false) != PM3_SUCCESS)
        return PM3_ESOFT;

    // lock
    if (t55xxProtect(true, usepwd, override, password, downlink_mode, new_password) == false) {
        PrintAndLogEx(WARNING, "Command failed. Did you run " _YELLOW_("`lf t55xx detect`") " before?");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,                 AlwaysAvailable, "This help"},
    {"bruteforce",   CmdT55xxBruteForce,      IfPm3Lf,         "<start password> <end password> Simple bruteforce attack to find password"},
    {"config",       CmdT55xxSetConfig,       AlwaysAvailable, "Set/Get T55XX configuration (modulation, inverted, offset, rate)"},
    {"chk",          CmdT55xxChkPwds,         IfPm3Lf,         "Check passwords from dictionary/flash"},
    {"clonehelp",    CmdT55xxCloneHelp,       IfPm3Lf,         "Shows the available clone commands"},
    {"dangerraw",    CmdT55xxDangerousRaw,    IfPm3Lf,         "Sends raw bitstream. Dangerous, do not use!! b <bitstream> t <timing>"},
    {"detect",       CmdT55xxDetect,          AlwaysAvailable, "[1] Try detecting the tag modulation from reading the configuration block."},
    {"deviceconfig", CmdT55xxSetDeviceConfig, IfPm3Lf,         "Set/Get T55XX device configuration (startgap, writegap, write0, write1, readgap"},
    {"dump",         CmdT55xxDump,            IfPm3Lf,         "[password] [o] Dump T55xx card Page 0 block 0-7. Optional [password], [override]"},
    {"restore",      CmdT55xxRestore,         IfPm3Lf,         "f <filename> [p <password>] Restore T55xx card Page 0 / Page 1 blocks"},
    {"info",         CmdT55xxInfo,            AlwaysAvailable, "[1] Show T55x7 configuration data (page 0/ blk 0)"},
    {"p1detect",     CmdT55xxDetectPage1,     IfPm3Lf,         "[1] Try detecting if this is a t55xx tag by reading page 1"},
    {"protect",      CmdT55xxProtect,         IfPm3Lf,         "Password protect tag"},
    {"read",         CmdT55xxReadBlock,       IfPm3Lf,         "b <block> p [password] [o] [1] -- Read T55xx block data. Optional [p password], [override], [page1]"},
    {"resetread",    CmdResetRead,            IfPm3Lf,         "Send Reset Cmd then lf read the stream to attempt to identify the start of it (needs a demod and/or plot after)"},
//    {"restore",      CmdT55xxRestore,         IfPm3Lf,         "[password] Restore T55xx card Page 0 / Page 1 blocks"},
    {"recoverpw",    CmdT55xxRecoverPW,       IfPm3Lf,         "[password] Try to recover from bad password write from a cloner. Only use on PW protected chips!"},
    {"special",      special,                 IfPm3Lf,         "Show block changes with 64 different offsets"},
    {"trace",        CmdT55xxReadTrace,       AlwaysAvailable, "[1] Show T55x7 traceability data (page 1/ blk 0-1)"},
    {"wakeup",       CmdT55xxWakeUp,          IfPm3Lf,         "Send AOR wakeup command"},
    {"wipe",         CmdT55xxWipe,            IfPm3Lf,         "[q] Wipe a T55xx tag and set defaults (will destroy any data on tag)"},
    {"write",        CmdT55xxWriteBlock,      IfPm3Lf,         "b <block> d <data> p [password] [1] -- Write T55xx block data. Optional [p password], [page1]"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFT55XX(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

