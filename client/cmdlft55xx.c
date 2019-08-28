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
#define T55XX_LONGLEADINGREFERENCE 4 // Value to tell Write Bit to send long reference

// Default configuration
t55xx_conf_block_t config = { .modulation = DEMOD_ASK, .inverted = false, .offset = 0x00, .block0 = 0x00, .Q5 = false };

t55xx_conf_block_t Get_t55xx_Config() {
    return config;
}
void Set_t55xx_Config(t55xx_conf_block_t conf) {
    config = conf;
}

static void print_usage_t55xx_downloadlink(void) {
    PrintAndLogEx(NORMAL, "     r <mode>     - downlink encoding 0|1|2|3");
    PrintAndLogEx(NORMAL, "                       0 - fixed bit length (default)");
    PrintAndLogEx(NORMAL, "                       1 - long leading reference");
    PrintAndLogEx(NORMAL, "                       2 - leading zero");
    PrintAndLogEx(NORMAL, "                       3 - 1 of 4 coding reference");
}

static int usage_t55xx_config() {
    PrintAndLogEx(NORMAL, "Usage: lf t55xx config [d <demodulation>] [i [0/1]] [o <offset>] [Q5 [0/1]] [ST [0/1]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h                                - This help");
    PrintAndLogEx(NORMAL, "       b <8|16|32|40|50|64|100|128>     - Set bitrate");
    PrintAndLogEx(NORMAL, "       d <FSK|FSK1|FSK1a|FSK2|FSK2a|ASK|PSK1|PSK2|NRZ|BI|BIa>  - Set demodulation FSK / ASK / PSK / NRZ / Biphase / Biphase A");
    PrintAndLogEx(NORMAL, "       i [0/1]                          - Set/reset data signal inversion");
    PrintAndLogEx(NORMAL, "       o [offset]                       - Set offset, where data should start decode in bitstream");
    PrintAndLogEx(NORMAL, "       Q5 [0/1]                         - Set/reset as Q5(T5555) chip instead of T55x7");
    PrintAndLogEx(NORMAL, "       ST [0/1]                         - Set/reset Sequence Terminator on");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK          - FSK demodulation");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK i 1      - FSK demodulation, inverse data");
    PrintAndLogEx(NORMAL, "      lf t55xx config d FSK i 1 o 3  - FSK demodulation, inverse data, offset=3,start from position 3 to decode data");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_read() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx read [r <mode>] b <block> [p <password>] <override_safety> <page1>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     b <block>    - block number to read. Between 0-7");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password (8 hex characters)");
    PrintAndLogEx(NORMAL, "     o            - OPTIONAL override safety check");
    PrintAndLogEx(NORMAL, "     1            - OPTIONAL 0|1  read Page 1 instead of Page 0");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "     ****WARNING****");
    PrintAndLogEx(NORMAL, "     Use of read with password on a tag not configured for a pwd");
    PrintAndLogEx(NORMAL, "     can damage the tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0                 - read data from block 0");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0 p feedbeef      - read data from block 0 password feedbeef");
    PrintAndLogEx(NORMAL, "      lf t55xx read b 0 p feedbeef o    - read data from block 0 password feedbeef safety check");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_write() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx write [r <mode>] b <block> d <data> [p <password>] [1] [t]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     b <block>    - block number to write. Between 0-7");
    PrintAndLogEx(NORMAL, "     d <data>     - 4 bytes of data to write (8 hex characters)");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password 4bytes (8 hex characters)");
    PrintAndLogEx(NORMAL, "     1            - OPTIONAL write Page 1 instead of Page 0");
    PrintAndLogEx(NORMAL, "     t            - OPTIONAL test mode write - ****DANGER****");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx write b 3 d 11223344            - write 11223344 to block 3");
    PrintAndLogEx(NORMAL, "      lf t55xx write b 3 d 11223344 p feedbeef - write 11223344 to block 3 password feedbeef");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_trace() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx trace [r mode]");
    PrintAndLogEx(NORMAL, "Options:");
    print_usage_t55xx_downloadlink();
    // Command did not seem to support the 1 option (yet) so have removed the help lines
    // PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx trace");
    // PrintAndLogEx(NORMAL, "      lf t55xx trace 1");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_info() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx info [1] [r <mode>] [d <data> [q]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     (default)    - read data from tag.");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer instead of reading tag.");
    PrintAndLogEx(NORMAL, "     d <data>     - 4 bytes of data (8 hex characters)");
    PrintAndLogEx(NORMAL, "                    if set, use these data instead of reading tag.");
    PrintAndLogEx(NORMAL, "     q            - if set, provided data are interpreted as Q5 config.");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx info");
    PrintAndLogEx(NORMAL, "      lf t55xx info 1");
    PrintAndLogEx(NORMAL, "      lf t55xx info d 00083040");
    PrintAndLogEx(NORMAL, "      lf t55xx info d 6001805A q");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_dump() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx dump [r <mode>] [<password> [o]]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     <password>   - OPTIONAL password 4bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "     o            - OPTIONAL override, force pwd read despite danger to card");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx dump");
    PrintAndLogEx(NORMAL, "      lf t55xx dump feedbeef o");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_detect() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx detect [1] [r <mode>] [p <password>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "     p <password  - OPTIONAL password (8 hex characters)");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx detect");
    PrintAndLogEx(NORMAL, "      lf t55xx detect 1");
    PrintAndLogEx(NORMAL, "      lf t55xx detect p 11223344");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_detectP1() {
    PrintAndLogEx(NORMAL, "Command: Detect Page 1 of a t55xx chip");
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx p1detect [1] [r <mode>] [p <password>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     1            - if set, use Graphbuffer otherwise read data from tag.");
    PrintAndLogEx(NORMAL, "     p <password> - OPTIONAL password (8 hex characters)");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect 1");
    PrintAndLogEx(NORMAL, "      lf t55xx p1detect p 11223344");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_wakup() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx wakeup [h] [r <mode>] p <password>");
    PrintAndLogEx(NORMAL, "This commands sends the Answer-On-Request command and leaves the readerfield ON afterwards.");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    PrintAndLogEx(NORMAL, "     p <password> - password 4bytes (8 hex symbols)");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx wakeup p 11223344  - send wakeup password");
    return PM3_SUCCESS;
}
static int usage_t55xx_chk() {
    PrintAndLogEx(NORMAL, "This command uses a dictionary attack");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, "WARNING: this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try to reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx chk [h] [m] [r <mode>] [i <*.dic>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    PrintAndLogEx(NORMAL, "     m            - use dictionary from flashmemory\n");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "     i <*.dic>    - loads a default keys dictionary file <*.dic>");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx chk m");
    PrintAndLogEx(NORMAL, "       lf t55xx chk i t55xx_default_pwds");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_bruteforce() {
    PrintAndLogEx(NORMAL, "This command uses bruteforce to scan a number range");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, "WARNING: this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx bruteforce [h] [r <mode>] <start password> <end password>");
    PrintAndLogEx(NORMAL, "       password must be 4 bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "     <start_pwd>  - 4 byte hex value to start pwd search at");
    PrintAndLogEx(NORMAL, "     <end_pwd>    - 4 byte hex value to end pwd search at");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx bruteforce r 2 aaaaaa77 aaaaaa99");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_recoverpw() {
    PrintAndLogEx(NORMAL, "This command uses a few tricks to try to recover mangled password");
    PrintAndLogEx(NORMAL, "press " _YELLOW_("'enter'") " to cancel the command");
    PrintAndLogEx(NORMAL, "WARNING: this may brick non-password protected chips!");
    PrintAndLogEx(NORMAL, "Try reading block 7 before\n");
    PrintAndLogEx(NORMAL, "Usage: lf t55xx recoverpw [r <mode>] [password]");
    PrintAndLogEx(NORMAL, "       password must be 4 bytes (8 hex symbols)");
    PrintAndLogEx(NORMAL, "       default password is 51243648, used by many cloners");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h            - this help");
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "     [password]   - 4 byte hex value of password written by cloner");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf t55xx recoverpw");
    PrintAndLogEx(NORMAL, "       lf t55xx r 3 recoverpw 51243648");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
static int usage_t55xx_wipe() {
    PrintAndLogEx(NORMAL, "Usage:  lf t55xx wipe [h] [Q5]");
    PrintAndLogEx(NORMAL, "This commands wipes a tag, fills blocks 1-7 with zeros and a default configuration block");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h   - this help");
    PrintAndLogEx(NORMAL, "     Q5  - indicates to use the T5555 (Q5) default configuration block");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx wipe    -  wipes a t55x7 tag,    config block 0x000880E0");
    PrintAndLogEx(NORMAL, "      lf t55xx wipe Q5 -  wipes a t5555 Q5 tag, config block 0x6001F004");
    return PM3_SUCCESS;
}
static int usage_lf_deviceconfig() {
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
    print_usage_t55xx_downloadlink();
    PrintAndLogEx(NORMAL, "     z            - Set default t55x7 timings (use p to save if required)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf t55xx deviceconfig a 29 b 17 c 15 d 47 e 15   - default T55XX");
    PrintAndLogEx(NORMAL, "      lf t55xx deviceconfig a 55 b 14 c 21 d 30        - default EM4305");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

void printT5xxHeader(uint8_t page) {
    PrintAndLogEx(NORMAL, "Reading Page %d:", page);
    PrintAndLogEx(NORMAL, "blk | hex data | binary                           | ascii");
    PrintAndLogEx(NORMAL, "----+----------+----------------------------------+-------");
}

static int CmdT55xxSetConfig(const char *Cmd) {

    uint8_t offset = 0, bitRate = 0;
    char modulation[6] = {0x00};
    uint8_t rates[9] = {8, 16, 32, 40, 50, 64, 100, 128, 0};
    uint8_t cmdp = 0;
    bool errors = false;
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
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    // No args
    if (cmdp == 0) return printConfiguration(config);

    //Validations
    if (errors) return usage_t55xx_config();

    config.block0 = 0;
    return printConfiguration(config);
}

int T55xxReadBlock(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode) {
    //Password mode
    if (usepwd) {
        // try reading the config block and verify that PWD bit is set before doing this!
        if (!override) {
            if (!AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, false, 0, downlink_mode)) return PM3_ESOFT;

            if (!tryDetectModulation()) {
                PrintAndLogEx(NORMAL, "Safety Check: Could not detect if PWD bit is set in config block. Exits.");
                return 0;
            } else {
                PrintAndLogEx(NORMAL, "Safety Check: PWD bit is NOT set in config block. Reading without password...");
                usepwd = false;
                page1 = false;
            }
        } else {
            // Show only if first for command i.e. override = 1 (override and display) override = 2 (override and dont display)
            if ((override & 2) != 2)
                PrintAndLogEx(NORMAL, "Safety Check Overriden - proceeding despite risk");
        }
    }


    if (!AquireData(page1, block, usepwd, password, downlink_mode)) return PM3_ESOFT;
    if (!DecodeT55xxBlock()) return PM3_ESOFT;

    printT55xxBlock(block);
    return PM3_SUCCESS;
}

static int CmdT55xxReadBlock(const char *Cmd) {
    uint8_t  block         = REGULAR_READ_MODE_BLOCK;
    uint32_t password      = 0; //default to blank Block 7
    bool     usepwd        = false;
    bool     override      = false;
    bool     page1         = false;
    bool     errors        = false;
    uint8_t  cmdp          = 0;
    uint8_t  downlink_mode = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_read();
            case 'b':
                errors |= param_getdec(Cmd, cmdp + 1, &block);
                cmdp += 2;
                break;
            case 'o':
                override = true;
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
            case 'R':
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
                if (downlink_mode > 3) downlink_mode = 0;
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_read();

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
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            save_restoreGB(GRAPH_SAVE);
            CmdLtrim("150");
            snprintf(cmdStr, sizeof(buf), "%d %d 6", bitRate[config.bitrate], config.inverted);
            ans = PSKDemod(cmdStr, false);
            //undo trim samples
            save_restoreGB(GRAPH_RESTORE);
            break;
        case DEMOD_PSK2: //inverted won't affect this
        case DEMOD_PSK3: //not fully implemented
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            save_restoreGB(GRAPH_SAVE);
            CmdLtrim("150");
            snprintf(cmdStr, sizeof(buf), "%d 0 6", bitRate[config.bitrate]);
            ans = PSKDemod(cmdStr, false);
            psk1TOpsk2(DemodBuffer, DemodBufferLen);
            //undo trim samples
            save_restoreGB(GRAPH_RESTORE);
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

void T55xx_Print_DownlinkMode(uint8_t downlink_mode) {
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
//
static int CmdT55xxDetect(const char *Cmd) {

    bool     errors           = false;
    bool     useGB            = false;
    bool     usepwd           = false;
    bool     try_all_dl_modes = false;
    bool     found            = false;
    uint32_t password         = 0;
    uint8_t  cmdp             = 0;
    uint8_t  downlink_mode    = 0;
    uint8_t  dl_mode          = 0;

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
                // use Graphbuffer data
                useGB = true;
                cmdp++;
                break;
            case 'r':
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
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

    // sanity check.
    if (SanityOfflineCheck(useGB) != PM3_SUCCESS) return PM3_ENODATA;

    if (!useGB) {
        for (dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {
            found = AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, dl_mode);

            // found = false if password is supplied but wrong d/l mode
            // so keep trying other modes (if requested)
            /*
            if (!found) {
                printf ("Aquire not found");
                return PM3_ENODATA;
            }
            */
            if (tryDetectModulation()) {
                T55xx_Print_DownlinkMode(dl_mode);
                dl_mode = 4;
                found = true;
            } else found = false;

            if (!try_all_dl_modes) dl_mode = 4;
        }
    }


    if (useGB) found = tryDetectModulation();

    if (!found)
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));


    /*
    if (!useGB) {
        if (!AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password,downlink_mode))
            return PM3_ENODATA;
    }
    if (!tryDetectModulation())
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));
    else
        T55xx_Print_DownlinkMode (downlink_mode);
    */

    return PM3_SUCCESS;
}
// detect configuration?
bool tryDetectModulation(void) {

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
                ++hits;
            }
            if ((ASKbiphaseDemod("0 0 0 2", false) == PM3_SUCCESS) && test(DEMOD_BI, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BI;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
                ++hits;
            }
            if ((ASKbiphaseDemod("0 0 1 2", false) == PM3_SUCCESS) && test(DEMOD_BIa, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BIa;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
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
                ++hits;
            }

            if ((NRZrawDemod("0 1 1", false) == PM3_SUCCESS) && test(DEMOD_NRZ, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_NRZ;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
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
                ++hits;
            }
            if ((PSKDemod("0 1 6", false) == PM3_SUCCESS) && test(DEMOD_PSK1, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, DemodBuffer);
                tests[hits].ST = false;
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
        printConfiguration(config);
        return true;
    }

    bool retval = false;
    if (hits > 1) {
        PrintAndLogEx(SUCCESS, "Found [%d] possible matches for modulation.", hits);
        for (int i = 0; i < hits; ++i) {
            retval = testKnownConfigBlock(tests[i].block0);
            if (retval) {
                PrintAndLogEx(NORMAL, "--[%d]--------------- << selected this", i + 1);
                config.modulation = tests[i].modulation;
                config.bitrate = tests[i].bitrate;
                config.inverted = tests[i].inverted;
                config.offset = tests[i].offset;
                config.block0 = tests[i].block0;
                config.Q5 = tests[i].Q5;
                config.ST = tests[i].ST;
            } else {
                PrintAndLogEx(NORMAL, "--[%d]---------------", i + 1);
            }
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
        PrintAndLogEx(WARNING, "The configured offset %d is too big. Possible offset: %d)", idx, DemodBufferLen - 32);
        return false;
    }

    *blockdata = PackBits(0, 32, DemodBuffer + idx);
    return true;
}

void printT55xxBlock(uint8_t blockNum) {

    uint32_t blockData = 0;
    uint8_t bytes[4] = {0};

    if (GetT55xxBlockData(&blockData) == false)
        return;

    num_to_bytes(blockData, 4, bytes);

    PrintAndLogEx(NORMAL, " %02d | %08X | %s | %s", blockNum, blockData, sprint_bin(DemodBuffer + config.offset, 32), sprint_ascii(bytes, 4));
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
    PrintAndLogEx(NORMAL, "Chip Type  : %s", (b.Q5) ? "T5555(Q5)" : "T55x7");
    PrintAndLogEx(NORMAL, "Modulation : %s", GetSelectedModulationStr(b.modulation));
    PrintAndLogEx(NORMAL, "Bit Rate   : %s", GetBitRateStr(b.bitrate, (b.block0 & T55x7_X_MODE && (b.block0 >> 28 == 6 || b.block0 >> 28 == 9))));
    PrintAndLogEx(NORMAL, "Inverted   : %s", (b.inverted) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(NORMAL, "Offset     : %d", b.offset);
    PrintAndLogEx(NORMAL, "Seq. Term. : %s", (b.ST) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(NORMAL, "Block0     : 0x%08X", b.block0);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdT55xxWakeUp(const char *Cmd) {

    uint32_t password      = 0;
    uint8_t  cmdp          = 0;
    bool     errors        = false;
    uint8_t  downlink_mode = 0;
    uint8_t  flags         = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_wakup();
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                errors = false;
                break;
            case 'r':
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
                if (downlink_mode > 3) downlink_mode = 0;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors) return usage_t55xx_wakup();

    flags = (downlink_mode & 3) << 3;
    clearCommandBuffer();
    SendCommandMIX(CMD_LF_T55XX_WAKEUP, password, flags, 0, NULL, 0);
    PrintAndLogEx(SUCCESS, "Wake up command sent. Try read now");

    return PM3_SUCCESS;
}

static int CmdT55xxWriteBlock(const char *Cmd) {
    uint8_t  block         = 0xFF; //default to invalid block
    uint32_t data          = 0;    //default to blank Block
    uint32_t password      = 0;    //default to blank Block 7
    bool     usepwd        = false;
    bool     page1         = false;
    bool     gotdata       = false;
    bool     testMode      = false;
    bool     errors        = false;
    uint8_t  cmdp          = 0;
    uint32_t downlink_mode = 0;

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
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
                if (downlink_mode > 3) downlink_mode = 0;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || !gotdata) return usage_t55xx_write();

    PacketResponseNG resp;
    uint8_t flags;
    flags  = (usepwd)   ? 0x1 : 0;
    flags |= (page1)    ? 0x2 : 0;
    flags |= (testMode) ? 0x4 : 0;
    flags |= (downlink_mode << 3);

    char pwdStr[16] = {0};
    snprintf(pwdStr, sizeof(pwdStr), "pwd: 0x%08X", password);

    PrintAndLogEx(INFO, "Writing page %d  block: %02d  data: 0x%08X %s", page1, block, data, (usepwd) ? pwdStr : "");

    clearCommandBuffer();

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

    SendCommandNG(CMD_LF_T55XX_WRITEBL, (uint8_t *)&ng, sizeof(ng));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_WRITEBL, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not ACK write operation. (May be due to old firmware)");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

static int CmdT55xxReadTrace(const char *Cmd) {
    uint8_t cmd_len       = 0;
    uint8_t downlink_mode = 0;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'r') {
        downlink_mode = param_getchar(Cmd, 1) - '0';
        if (downlink_mode > 3) downlink_mode = 0;
        cmd_len = 3;
    }
    if ((strlen(Cmd) != cmd_len) || (cmdp == 'h')) return usage_t55xx_trace();

    if (strlen(Cmd) == cmd_len) {
        // sanity check.
        if (SanityOfflineCheck(false) != PM3_SUCCESS) return PM3_ENODATA;

        bool pwdmode = false;
        uint32_t password = 0;
//        REGULAR_READ_MODE_BLOCK - yeilds correct Page 1 Block 2 data i.e. + 32 bit offset.
//        if (!AquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, pwdmode, password,downlink_mode))
        if (!AquireData(T55x7_PAGE1, REGULAR_READ_MODE_BLOCK, pwdmode, password, downlink_mode))
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
            PrintAndLogEx(FAILED, "Invalid Q5 Trace data header (expected 0x1FF, found %X)", hdr);
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
    TRACE - BLOCK O
        Bits    Definition                             HEX
        1-8     ACL Allocation class (ISO/IEC 15963-1) 0xE0
        9-16    MFC Manufacturer ID (ISO/IEC 7816-6)   0x15 Atmel Corporation
        17-21   CID                                    0x1 = Atmel ATA5577M1  0x2 = Atmel ATA5577M2
        22-24   ICR IC revision
        25-28   YEAR (BCD encoded)                     9 (= 2009)
        29-30   QUARTER                                1,2,3,4
        31-32   LOT ID

    TRACE - BLOCK 1
        1-12    LOT ID
        13-17   Wafer number
        18-32   DW,  die number sequential
    */
}

void printT5555Trace(t5555_tracedata_t data, uint8_t repeat) {
    PrintAndLogEx(NORMAL, "-- T5555 (Q5) Trace Information -----------------------------");
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
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "HID 26b ");
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
    bool     frombuff      = false, gotdata = false, dataasq5 = false;
    uint8_t  cmdp          = 0;
    uint8_t  downlink_mode = 0;
    uint32_t block0        = 0;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_info();
            case 'd':
                block0 = param_get32ex(Cmd, cmdp + 1, 0, 16);
                gotdata = true;
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
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
                if (downlink_mode > 3) downlink_mode = 0;
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

        bool pwdmode = false;
        uint32_t password = 0;
        if (!AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, pwdmode, password, downlink_mode))
            return PM3_ENODATA;
    }
    if (!gotdata) {
        if (!DecodeT55xxBlock()) return PM3_ESOFT;

        // too little space to start with
        if (DemodBufferLen < 32 + config.offset) return PM3_ESOFT;

        //PrintAndLogEx(NORMAL, "Offset+32 ==%d\n DemodLen == %d", config.offset + 32, DemodBufferLen);
        block0   = PackBits(config.offset, 32, DemodBuffer);
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
        uint32_t st       = (block0 >> (32 - 32)) & 0x01;
        PrintAndLogEx(NORMAL, "-- Q5 Configuration & Tag Information -----------------------");
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

        PrintAndLogEx(NORMAL, "-- T55x7 Configuration & Tag Information --------------------");
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

    uint32_t password      = 0;
    uint8_t  override      = false;
    uint8_t  cmd_opt_idx   = 0;
    uint8_t  downlink_mode = 0;
    uint8_t  pwd_offset    = 0;
    char     cmdp = tolower(param_getchar(Cmd, 0));


    if (cmdp == 'h') return usage_t55xx_dump();
    if (cmdp == 'r') {
        cmd_opt_idx++;
        downlink_mode = param_getchar(Cmd, cmd_opt_idx++) - '0';
        if (downlink_mode > 3) downlink_mode = 0;
        pwd_offset = 3;
    }
    bool usepwd = (strlen(Cmd) > pwd_offset);
    if (usepwd) {
        password = param_get32ex(Cmd, cmd_opt_idx++, 0, 16);
        if (param_getchar(Cmd, cmd_opt_idx++) == 'o')
            override = true;
    }

    printT5xxHeader(0);
    for (uint8_t i = 0; i < 8; ++i) {
        T55xxReadBlock(i, 0, usepwd, override, password, downlink_mode);
        // idea for better user experience and display.
        // only show override warning on the first block read
        if (override) override |= 2; // flag not to show safty for 2nd and on.
    }
    printT5xxHeader(1);
    for (uint8_t i = 0; i < 4; i++)
        T55xxReadBlock(i, 1, usepwd, override, password, downlink_mode);

    return PM3_SUCCESS;
}

bool AquireData(uint8_t page, uint8_t block, bool pwdmode, uint32_t password, uint8_t downlink_mode) {
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

    getSamples(12000, true);

    return !getSignalProperties()->isnoise;
}

char *GetPskCfStr(uint32_t id, bool q5) {
    static char buf[25];
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
            snprintf(retStr, sizeof(buf), "%08X - T5555 Q5 Default", T5555_DEFAULT_CONFIG_BLOCK);
            break;
        default:
            break;
    }
    PrintAndLogEx(NORMAL, buf);
}
*/

static int CmdResetRead(const char *Cmd) {

    uint8_t downlink_mode = 0;
    uint8_t flags         = 0;


    if (strlen(Cmd) == 3)
        downlink_mode = param_getchar(Cmd, 1) - '0';

    if (downlink_mode > 3) downlink_mode = 0;

    printf("DL : %d\n", downlink_mode);
    flags = downlink_mode << 3;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_RESET_READ, &flags, sizeof(flags));
    if (!WaitForResponseTimeout(CMD_ACK, NULL, 2500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    uint8_t got[BIGBUF_SIZE - 1];
    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    setGraphBuf(got, sizeof(got));
    return PM3_SUCCESS;
}

static int CmdT55xxWipe(const char *Cmd) {
    char writeData[20] = {0};
    char *ptrData = writeData;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_t55xx_wipe();

    bool Q5 = (cmdp == 'q');

    // Try with the default password to reset block 0
    // With a pwd should work even if pwd bit not set
    PrintAndLogEx(INFO, "\nBeginning Wipe of a T55xx tag (assuming the tag is not password protected)\n");

    if (Q5)
        snprintf(ptrData, sizeof(writeData), "b 0 d 6001F004 p 0");
    else
        snprintf(ptrData, sizeof(writeData), "b 0 d 000880E0 p 0");

    if (CmdT55xxWriteBlock(ptrData) != PM3_SUCCESS) PrintAndLogEx(WARNING, "Warning: error writing blk 0");

    for (uint8_t blk = 1; blk < 8; blk++) {

        snprintf(ptrData, sizeof(writeData), "b %d d 0", blk);

        if (CmdT55xxWriteBlock(ptrData) != PM3_SUCCESS) PrintAndLogEx(WARNING, "Warning: error writing blk %d", blk);

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

    char    filename[FILE_PATH_SIZE] = {0};
    bool    found = false;
    uint8_t timeout = 0;
    uint8_t *keyBlock = NULL;
    bool    from_flash = false;
    bool    try_all_dl_modes = false;
    uint8_t downlink_mode = 0;
    int     len;
    char    cmdp;
    bool    use_pwd_file = false;
    int     dl_mode; // to try each downlink mode for each password


    cmdp = tolower(param_getchar(Cmd, 0));

    if (cmdp == 'h') return usage_t55xx_chk();
    if (cmdp == 'm') {
        from_flash = true;
        Cmd += 2;
        cmdp = tolower(param_getchar(Cmd, 0));
    }
    if (cmdp == 'r') {
        Cmd += 2;
        downlink_mode = param_getchar(Cmd, 0) - '0'; // get 2nd option, as this is fixed order.
        if (downlink_mode == 4) try_all_dl_modes = true;
        if (downlink_mode > 3) downlink_mode = 0;
        Cmd += 2;
        cmdp = param_getchar(Cmd, 0);
    }
    if (cmdp == 'i') {
        Cmd += 2;
        len = strlen(Cmd);
        if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
        memcpy(filename, Cmd, len);
        use_pwd_file = true;
    }



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
            PrintAndLogEx(SUCCESS, "\nFound a candidate [ " _YELLOW_("%08X") " ]. Trying to validate", resp.oldarg[1]);

            if (AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, resp.oldarg[1], downlink_mode)) {
                found = tryDetectModulation();
                if (found) {
                    PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", resp.oldarg[1]);
                    T55xx_Print_DownlinkMode(downlink_mode);

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
        uint16_t keycount = 0;

        int res = loadFileDICTIONARY_safe(filename, (void**) &keyBlock, 4, &keycount);
        if (res != PM3_SUCCESS || keycount <= 0 || keyBlock == NULL) {
            PrintAndLogEx(WARNING, "No keys found in file");
            if (keyBlock != NULL) free(keyBlock);
            return PM3_ESOFT;
        }

        // loop
        uint64_t curr_password = 0x00;
        for (uint16_t c = 0; c < keycount; ++c) {

            if (!session.pm3_present) {
                PrintAndLogEx(WARNING, "Device offline\n");
                free(keyBlock);
                return PM3_ENODATA;
            }

            if (IsCancelled()) {
                free(keyBlock);
                return PM3_EOPABORTED;
            }

            curr_password = bytes_to_num(keyBlock + 4 * c, 4);

            PrintAndLogEx(INFO, "Testing %08X", curr_password);
            for (dl_mode = downlink_mode; dl_mode <= 3; dl_mode++) {

                if (!AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, curr_password, dl_mode)) {
                    continue;
                }

                found = tryDetectModulation();
                if (found) {
                    PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr_password);
                    T55xx_Print_DownlinkMode(dl_mode);
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
    uint32_t end_password   = 0xFFFFFFFF; //end   password
    uint32_t curr           = 0;
    uint8_t  downlink_mode  = 0;
    uint8_t  cmd_opt_idx    = 0;
    uint8_t  found          = 0; // > 0 if found xx1 xx downlink needed, 1 found

    char cmdp = tolower(param_getchar(Cmd, cmd_opt_idx));

    if (cmdp == 'h') return usage_t55xx_bruteforce();
    if (cmdp == 'r') { // downlink mode supplied
        cmd_opt_idx++;   // skip over 'r'
        downlink_mode = param_getchar(Cmd, cmd_opt_idx++) - '0';
        if (downlink_mode > 4) downlink_mode = 0;
    }


    uint64_t t1 = msclock();

    start_password = param_get32ex(Cmd, cmd_opt_idx++, 0, 16);
    end_password   = param_get32ex(Cmd, cmd_opt_idx++, 0, 16);

    curr = start_password;

    if (start_password >= end_password) {
        return usage_t55xx_bruteforce();
    }

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
        PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") "]", curr - 1);
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

        AquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, password, dl_mode);

        //  if (getSignalProperties()->isnoise == false) {
        //  } else {
        if (tryDetectModulation()) {
            return 1 + (dl_mode << 1);
        }
        //  }
        if (!try_all_dl_modes) dl_mode = 4;
    }
    return 0;
}

static int CmdT55xxRecoverPW(const char *Cmd) {
    int      bit           = 0;
    uint32_t orig_password = 0x0;
    uint32_t curr_password = 0x0;
    uint32_t prev_password = 0xffffffff;
    uint32_t mask          = 0x0;
    uint8_t  downlink_mode = 0;
    uint8_t  found         = 0;
    uint8_t  cmd_opt_idx   = 0;

    char     cmdp = tolower(param_getchar(Cmd, cmd_opt_idx));

    if (cmdp == 'h') return usage_t55xx_recoverpw();
    if (cmdp == 'r') { // downlink mode supplied
        cmd_opt_idx++; // skip over 'r'
        downlink_mode = param_getchar(Cmd, cmd_opt_idx++) - '0';
        if (downlink_mode > 4) downlink_mode = 0;
    }

    orig_password = param_get32ex(Cmd, cmd_opt_idx++, 0x51243648, 16); //password used by handheld cloners

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
        PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") "]", curr_password);
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
        if (!AquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, false, 0, 0))
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
    bool     errors           = false;
    bool     useGB            = false;
    bool     usepwd           = false;
    bool     try_all_dl_modes = false;
    uint8_t  found            = 0;
    uint32_t password         = 0;
    uint8_t  cmdp             = 0;
    uint8_t  downlink_mode    = 0;
    uint8_t  dl_mode          = 0;

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
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
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
    if (errors) return usage_t55xx_detectP1();

    if (!useGB) {
        for (dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {
            found = AquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, usepwd, password, dl_mode);
            //return PM3_ENODATA;
            if (tryDetectP1(false)) { //tryDetectModulation())
                found = dl_mode;
                dl_mode = 4;
            } else found = false;

            if (!try_all_dl_modes) dl_mode = 4;
        }

    }

    if (useGB) found = tryDetectP1(false);

    if (found) {
        PrintAndLogEx(SUCCESS, "T55xx chip found!");
        T55xx_Print_DownlinkMode(found);
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
                return usage_lf_deviceconfig();
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
                downlink_mode = param_getchar(Cmd, cmdp + 1) - '0';
                if (downlink_mode > 3) downlink_mode = 0;
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
    if (errors || cmdp == 0) return usage_lf_deviceconfig();

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
        configurations.m[T55XX_DLMODE_LLR].start_gap  = 31 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_gap  = 20 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_0    = 18 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_1    = 50 * 8;
        configurations.m[T55XX_DLMODE_LLR].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_2    = 0;
        configurations.m[T55XX_DLMODE_LLR].write_3    = 0;

        // leading zero
        configurations.m[T55XX_DLMODE_LEADING_ZERO].start_gap  = 31 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_gap  = 20 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_0    = 18 * 8;
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
    SendCommandOLD(CMD_LF_T55XX_SET_CONFIG, shall_persist, 0, 0, &configurations, sizeof(t55xx_configurations_t));
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,                 AlwaysAvailable, "This help"},
    {"bruteforce",   CmdT55xxBruteForce,      IfPm3Lf,         "<start password> <end password> Simple bruteforce attack to find password"},
    {"config",       CmdT55xxSetConfig,       AlwaysAvailable, "Set/Get T55XX configuration (modulation, inverted, offset, rate)"},
    {"chk",          CmdT55xxChkPwds,         IfPm3Lf,         "Check passwords from dictionary/flash"},
    {"detect",       CmdT55xxDetect,          AlwaysAvailable, "[1] Try detecting the tag modulation from reading the configuration block."},
    {"deviceconfig", CmdT55xxSetDeviceConfig, IfPm3Lf,         "Set/Get T55XX device configuration (startgap, writegap, write0, write1, readgap"},
    {"p1detect",     CmdT55xxDetectPage1,     IfPm3Lf,         "[1] Try detecting if this is a t55xx tag by reading page 1"},
    {"dump",         CmdT55xxDump,            IfPm3Lf,         "[password] [o] Dump T55xx card block 0-7. Optional [password], [override]"},
    {"info",         CmdT55xxInfo,            AlwaysAvailable, "[1] Show T55x7 configuration data (page 0/ blk 0)"},
    {"read",         CmdT55xxReadBlock,       IfPm3Lf,         "b <block> p [password] [o] [1] -- Read T55xx block data. Optional [p password], [override], [page1]"},
    {"resetread",    CmdResetRead,            IfPm3Lf,         "Send Reset Cmd then lf read the stream to attempt to identify the start of it (needs a demod and/or plot after)"},
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

