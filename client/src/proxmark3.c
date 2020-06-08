//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main binary
//-----------------------------------------------------------------------------

#include "proxmark3.h"

#include <stdlib.h>
#include <stdio.h>         // for Mingw readline
#include <limits.h>
#include <unistd.h>
#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include <ctype.h>
#include "usart_defs.h"
#include "util_posix.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "ui.h"
#include "cmdhw.h"
#include "whereami.h"
#include "comms.h"
#include "fileutils.h"
#include "flash.h"
#include "preferences.h"

// Used to enable/disable use of preferences json file
#define USE_PREFERENCE_FILE

#define BANNERMSG1 "    :snowflake:  iceman@icesql.net"
#define BANNERMSG2 "   https://github.com/rfidresearchgroup/proxmark3/"
#define BANNERMSG3 " bleeding edge :coffee:"

typedef enum LogoMode { UTF8, ANSI, ASCII } LogoMode;

static void showBanner_logo(LogoMode mode) {
    switch (mode) {
        case UTF8: {
            const char *sq = "\xE2\x96\x88"; // square block
            const char *tr = "\xE2\x95\x97"; // top right corner
            const char *tl = "\xE2\x95\x94"; // top left corner
            const char *br = "\xE2\x95\x9D"; // bottom right corner
            const char *bl = "\xE2\x95\x9A"; // bottom left corner
            const char *hl = "\xE2\x95\x90"; // horiz line
            const char *vl = "\xE2\x95\x91"; // vert line
            const char *__ = " ";

            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"),
                          sq, sq, sq, sq, sq, sq, tr, __, sq, sq, sq, tr, __, __, __, sq, sq, sq, tr, sq, sq, sq, sq, sq, tr, __);
            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"),
                          sq, sq, tl, hl, hl, sq, sq, tr, sq, sq, sq, sq, tr, __, sq, sq, sq, sq, vl, bl, hl, hl, hl, sq, sq, tr);
            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"),
                          sq, sq, sq, sq, sq, sq, tl, br, sq, sq, tl, sq, sq, sq, sq, tl, sq, sq, vl, __, sq, sq, sq, sq, tl, br);
            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")" " BANNERMSG1,
                          sq, sq, tl, hl, hl, hl, br, __, sq, sq, vl, bl, sq, sq, tl, br, sq, sq, vl, __, bl, hl, hl, sq, sq, tr);
            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")" " BANNERMSG2,
                          sq, sq, vl, __, __, __, __, __, sq, sq, vl, __, bl, hl, br, __, sq, sq, vl, sq, sq, sq, sq, sq, tl, br);
            PrintAndLogEx(NORMAL, "  " _BLUE_("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")" " BANNERMSG3,
                          bl, hl, br, __, __, __, __, __, bl, hl, br, __, __, __, __, __, bl, hl, br, bl, hl, hl, hl, hl, br, __);
            break;
        }
        case ANSI: {
            PrintAndLogEx(NORMAL, "  " _BLUE_("██████╗ ███╗   ███╗█████╗ "));
            PrintAndLogEx(NORMAL, "  " _BLUE_("██╔══██╗████╗ ████║╚═══██╗"));
            PrintAndLogEx(NORMAL, "  " _BLUE_("██████╔╝██╔████╔██║ ████╔╝"));
            PrintAndLogEx(NORMAL, "  " _BLUE_("██╔═══╝ ██║╚██╔╝██║ ╚══██╗") " " BANNERMSG1);
            PrintAndLogEx(NORMAL, "  " _BLUE_("██║     ██║ ╚═╝ ██║█████╔╝") " " BANNERMSG2);
            PrintAndLogEx(NORMAL, "  " _BLUE_("╚═╝     ╚═╝     ╚═╝╚════╝ ") " " BANNERMSG3);
            break;
        }
        case ASCII: {
            PrintAndLogEx(NORMAL, "  ######. ###.   ###.#####. ");
            PrintAndLogEx(NORMAL, "  ##...##.####. ####. ...##.");
            PrintAndLogEx(NORMAL, "  ######..##.####.##. ####..");
            PrintAndLogEx(NORMAL, "  ##..... ##..##..##.  ..##." " " BANNERMSG1);
            PrintAndLogEx(NORMAL, "  ##.     ##.  .. ##.#####.." " " BANNERMSG2);
            PrintAndLogEx(NORMAL, "   ..      ..      .. ..... " " " BANNERMSG3);
            break;
        }
    }
}

static void showBanner(void) {

    g_printAndLog = PRINTANDLOG_PRINT;
    PrintAndLogEx(NORMAL, "\n");

#if defined(_WIN32)
    if (GetConsoleCP() == 65001) {
        // If on Windows and using UTF-8 then we need utf-8 ascii art for banner.
        showBanner_logo(UTF8);
    } else {
        showBanner_logo(ANSI);
    }
#elif defined(__linux__) || defined(__APPLE__)
    showBanner_logo(ANSI);
#else
    showBanner_logo(ASCII);
#endif
//    PrintAndLogEx(NORMAL, "\nSupport iceman on patreon - https://www.patreon.com/iceman1001/");
//    PrintAndLogEx(NORMAL, "                 on paypal - https://www.paypal.me/iceman1001");
//    printf("\nMonero: 43mNJLpgBVaTvyZmX9ajcohpvVkaRy1kbZPm8tqAb7itZgfuYecgkRF36rXrKFUkwEGeZedPsASRxgv4HPBHvJwyJdyvQuP");
    PrintAndLogEx(NORMAL, "");
    fflush(stdout);
    g_printAndLog = PRINTANDLOG_PRINT | PRINTANDLOG_LOG;
}

static const char *prompt_dev = "";
static const char *prompt_ctx = "";

static void prompt_compose(char *buf, size_t buflen, const char *promptctx, const char *promptdev) {
    snprintf(buf, buflen - 1, PROXPROMPT_COMPOSE, promptdev, promptctx);
}

#ifdef HAVE_READLINE
static int check_comm(void) {
    // If communications thread goes down. Device disconnected then this should hook up PM3 again.
    if (IsCommunicationThreadDead() && session.pm3_present) {
        prompt_dev = PROXPROMPT_DEV_OFFLINE;
        char prompt[PROXPROMPT_MAX_SIZE] = {0};
        prompt_compose(prompt, sizeof(prompt), prompt_ctx, prompt_dev);
        char prompt_filtered[PROXPROMPT_MAX_SIZE] = {0};
        memcpy_filter_ansi(prompt_filtered, prompt, sizeof(prompt_filtered), !session.supports_colors);
        rl_set_prompt(prompt_filtered);
        rl_forced_update_display();
        CloseProxmark();
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") " mode. Use "_YELLOW_("\"hw connect\"") " to reconnect\n");
    }
    return 0;
}
#endif

// first slot is always NULL, indicating absence of script when idx=0
static FILE *cmdscriptfile[MAX_NESTED_CMDSCRIPT + 1] = {0};
static uint8_t cmdscriptfile_idx = 0;
static bool cmdscriptfile_stayafter = false;

int push_cmdscriptfile(char *path, bool stayafter) {
    if (cmdscriptfile_idx == MAX_NESTED_CMDSCRIPT) {
        PrintAndLogEx(ERR, "Too many nested scripts, skipping %s\n", path);
        return PM3_EMALLOC;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return PM3_EFILE;

    if (cmdscriptfile_idx == 0)
        cmdscriptfile_stayafter = stayafter;

    cmdscriptfile[++cmdscriptfile_idx] = f;
    return PM3_SUCCESS;
}

static FILE *current_cmdscriptfile(void) {
    return cmdscriptfile[cmdscriptfile_idx];
}

static bool pop_cmdscriptfile(void) {
    fclose(cmdscriptfile[cmdscriptfile_idx]);
    cmdscriptfile[cmdscriptfile_idx--] = NULL;
    if (cmdscriptfile_idx == 0)
        return cmdscriptfile_stayafter;
    else
        return true;
}

// Main thread of PM3 Client
void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
main_loop(char *script_cmds_file, char *script_cmd, bool stayInCommandLoop) {

    char *cmd = NULL;
    bool execCommand = (script_cmd != NULL);
    uint16_t script_cmd_len = 0;
    if (execCommand) {
        script_cmd_len = strlen(script_cmd);
        strcreplace(script_cmd, script_cmd_len, ';', '\0');
    }
    bool stdinOnPipe = !isatty(STDIN_FILENO);
    char script_cmd_buf[256] = {0x00};  // iceman, needs lua script the same file_path_buffer as the rest

    if (session.pm3_present) {
        // cache Version information now:
        if (execCommand || script_cmds_file || stdinOnPipe)
            pm3_version(false, false);
        else
            pm3_version(true, false);
    }

    if (script_cmds_file) {

        char *path;
        int res = searchFile(&path, CMD_SCRIPTS_SUBDIR, script_cmds_file, ".cmd", false);
        if (res == PM3_SUCCESS) {
            if (push_cmdscriptfile(path, stayInCommandLoop) == PM3_SUCCESS)
                PrintAndLogEx(SUCCESS, "executing commands from file: %s\n", path);
            else
                PrintAndLogEx(ERR, "could not open " _YELLOW_("%s") "...", path);
            free(path);
        }
    }

#ifdef HAVE_READLINE
    char *my_history_path = NULL;
    if (searchHomeFilePath(&my_history_path, NULL, PROXHISTORY, true) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "No history will be recorded");
        my_history_path = NULL;
    } else {
        read_history(my_history_path);
    }
#endif
    // loops every time enter is pressed...
    while (1) {
        bool printprompt = false;
        if (session.pm3_present) {
            if (conn.send_via_fpc_usart == false)
                prompt_dev = PROXPROMPT_DEV_USB;
            else
                prompt_dev = PROXPROMPT_DEV_FPC;
        } else {
            prompt_dev = PROXPROMPT_DEV_OFFLINE;
        }

check_script:
        // If there is a script file
        if (current_cmdscriptfile()) {

            // clear array
            memset(script_cmd_buf, 0, sizeof(script_cmd_buf));

            // read script file
            if (fgets(script_cmd_buf, sizeof(script_cmd_buf), current_cmdscriptfile()) == NULL) {
                if (!pop_cmdscriptfile())
                    break;

                goto check_script;
            } else {
                prompt_ctx = PROXPROMPT_CTX_SCRIPTFILE;
                // remove linebreaks
                strcleanrn(script_cmd_buf, sizeof(script_cmd_buf));

                cmd = str_dup(script_cmd_buf);
                if (cmd != NULL)
                    printprompt = true;
            }
        } else {
            // If there is a script command
            if (execCommand) {
                prompt_ctx = PROXPROMPT_CTX_SCRIPTCMD;

                cmd = str_dup(script_cmd);
                if (cmd != NULL)
                    printprompt = true;

                uint16_t len = strlen(script_cmd) + 1;
                script_cmd += len;

                if (script_cmd_len == len - 1)
                    execCommand = false;

                script_cmd_len -= len;
            } else {
                // exit after exec command
                if (script_cmd && !stayInCommandLoop)
                    break;

                // if there is a pipe from stdin
                if (stdinOnPipe) {
                    prompt_ctx = PROXPROMPT_CTX_STDIN;

                    // clear array
                    memset(script_cmd_buf, 0, sizeof(script_cmd_buf));
                    // get
                    if (fgets(script_cmd_buf, sizeof(script_cmd_buf), stdin) == NULL) {
                        PrintAndLogEx(ERR, "STDIN unexpected end, exit...");
                        break;
                    }
                    // remove linebreaks
                    strcleanrn(script_cmd_buf, sizeof(script_cmd_buf));

                    cmd = str_dup(script_cmd_buf);
                    if (cmd != NULL)
                        printprompt = true;

                } else {
                    prompt_ctx = PROXPROMPT_CTX_INTERACTIVE;
                    char prompt[PROXPROMPT_MAX_SIZE] = {0};
                    prompt_compose(prompt, sizeof(prompt), prompt_ctx, prompt_dev);
                    char prompt_filtered[PROXPROMPT_MAX_SIZE] = {0};
                    memcpy_filter_ansi(prompt_filtered, prompt, sizeof(prompt_filtered), !session.supports_colors);
#ifdef HAVE_READLINE
                    rl_event_hook = check_comm;
                    cmd = readline(prompt_filtered);
#else
                    printf("%s", prompt_filtered);
                    cmd = NULL;
                    size_t len = 0;
                    int ret;
                    if ((ret = getline(&cmd, &len, stdin)) < 0) {
                        // TODO this happens also when kbd_enter_pressed() is used, with a key pressed or not
                        printf("GETLINE ERR %i", ret);
                        free(cmd);
                        cmd = NULL;
                    }
#endif
                    fflush(NULL);
                }
            }
        }

        // execute command
        if (cmd) {

            // rtrim
            size_t l = strlen(cmd);
            while (l > 0 && isspace(cmd[l - 1])) {
                cmd[--l] = '\0';
            }
            // ltrim
            size_t off = 0;
            while ((cmd[off] != '\0') && isspace(cmd[off])) {
                off++;
            }

            for (size_t i = 0; i < strlen(cmd) - off; i++) {
                cmd[i] = cmd[i + off];
            }

            cmd[strlen(cmd) - off] = '\0';

            if (cmd[0] != '\0') {
                if (!printprompt) {
                    g_printAndLog = PRINTANDLOG_LOG;
                }
                char prompt[PROXPROMPT_MAX_SIZE] = {0};
                prompt_compose(prompt, sizeof(prompt), prompt_ctx, prompt_dev);
                // always filter RL magic separators if not using readline
                char prompt_filtered[PROXPROMPT_MAX_SIZE] = {0};
                memcpy_filter_rlmarkers(prompt_filtered, prompt, sizeof(prompt_filtered));
                PrintAndLogEx(NORMAL, "%s%s", prompt_filtered, cmd);
                g_printAndLog = PRINTANDLOG_PRINT | PRINTANDLOG_LOG;

#ifdef HAVE_READLINE
                // add to history if not from a script
                if (!current_cmdscriptfile()) {
                    HIST_ENTRY *entry = history_get(history_length);
                    // add if not identical to latest recorded cmd
                    if ((!entry) || (strcmp(entry->line, cmd) != 0)) {
                        add_history(cmd);
                    }
                }
#endif
                // process cmd
                int ret = CommandReceived(cmd);
                // exit or quit
                if (ret == PM3_EFATAL)
                    break;
            }
            free(cmd);
            cmd = NULL;
        } else {
            PrintAndLogEx(NORMAL, "\n");
            if (script_cmds_file && stayInCommandLoop)
                stayInCommandLoop = false;
            else
                break;
        }
    } // end while

    if (session.pm3_present) {
        clearCommandBuffer();
        SendCommandNG(CMD_QUIT_SESSION, NULL, 0);
        msleep(100); // Make sure command is sent before killing client
    }

    while (current_cmdscriptfile())
        pop_cmdscriptfile();

#ifdef HAVE_READLINE
    if (my_history_path) {
        write_history(my_history_path);
        free(my_history_path);
    }
#endif
    if (cmd) {
        free(cmd);
        cmd = NULL;
    }
}

static void dumpAllHelp(int markdown) {
    session.help_dump_mode = true;
    PrintAndLogEx(NORMAL, "\n%sProxmark3 command dump%s\n\n", markdown ? "# " : "", markdown ? "" : "\n======================");
    PrintAndLogEx(NORMAL, "Some commands are available only if a Proxmark3 is actually connected.%s\n", markdown ? "  " : "");
    PrintAndLogEx(NORMAL, "Check column \"offline\" for their availability.\n");
    PrintAndLogEx(NORMAL, "\n");
    command_t *cmds = getTopLevelCommandTable();
    dumpCommandsRecursive(cmds, markdown);
    session.help_dump_mode = false;
}

static char *my_executable_path = NULL;
static char *my_executable_directory = NULL;

const char *get_my_executable_path(void) {
    return my_executable_path;
}

const char *get_my_executable_directory(void) {
    return my_executable_directory;
}

static void set_my_executable_path(void) {
    int path_length = wai_getExecutablePath(NULL, 0, NULL);
    if (path_length == -1)
        return;

    my_executable_path = (char *)calloc(path_length + 1, sizeof(uint8_t));
    int dirname_length = 0;
    if (wai_getExecutablePath(my_executable_path, path_length, &dirname_length) != -1) {
        my_executable_path[path_length] = '\0';
        my_executable_directory = (char *)calloc(dirname_length + 2, sizeof(uint8_t));
        strncpy(my_executable_directory, my_executable_path, dirname_length + 1);
        my_executable_directory[dirname_length + 1] = '\0';
    }
}

static const char *my_user_directory = NULL;
// static char _cwd_Buffer [FILENAME_MAX] = {0};

const char *get_my_user_directory(void) {
    return my_user_directory;
}

static void set_my_user_directory(void) {
    /*    my_user_directory = getenv("HOME");

        // if not found, default to current directory
        if (my_user_directory == NULL) {
            my_user_directory = GetCurrentDir(_cwd_Buffer, sizeof(_cwd_Buffer));
            // change all slashs to / (windows should not care...
            for (int i = 0; i < strlen(_cwd_Buffer); i++)
                if (_cwd_Buffer[i] == '\\') _cwd_Buffer[i] = '/';
            //      my_user_directory = ".";
        }
    */
    my_user_directory = getenv("HOME");

    // if not found, default to current directory
    if (my_user_directory == NULL) {

        uint16_t pathLen = FILENAME_MAX; // should be a good starting point
        bool error = false;
        char *cwd_buffer = (char *)calloc(pathLen, sizeof(uint8_t));

        while (!error && (GetCurrentDir(cwd_buffer, pathLen) == NULL)) {
            if (errno == ERANGE) {  // Need bigger buffer
                pathLen += 10;      // if buffer was too small add 10 characters and try again
                char *tmp = realloc(cwd_buffer, pathLen);
                if (tmp == NULL) {
                    PrintAndLogEx(WARNING, "failed to allocate memory");
                    free(cwd_buffer);
                    return;
                }
                cwd_buffer = tmp;
            } else {
                free(cwd_buffer);
                return;
            }
            PrintAndLogEx(NORMAL, "Len... %d", pathLen);
        }

        if (!error) {

            for (int i = 0; i < strlen(cwd_buffer); i++) {
                if (cwd_buffer[i] == '\\') {
                    cwd_buffer[i] = '/';
                }
            }

            my_user_directory = cwd_buffer;
        }
    }
}

static void show_help(bool showFullHelp, char *exec_name) {

    PrintAndLogEx(NORMAL, "\nsyntax: %s [-h|-t|-m]", exec_name);
    PrintAndLogEx(NORMAL, "        %s [[-p] <port>] [-b] [-w] [-f] [-c <command>]|[-l <lua_script_file>]|[-s <cmd_script_file>] [-i] [-d <0|1|2>]", exec_name);
    PrintAndLogEx(NORMAL, "        %s [-p] <port> --flash [--unlock-bootloader] [--image <imagefile>]+ [-w] [-f] [-d <0|1|2>]", exec_name);

    if (showFullHelp) {

        PrintAndLogEx(NORMAL, "\nCommon options:");
        PrintAndLogEx(NORMAL, "      -h/--help                           this help");
        PrintAndLogEx(NORMAL, "      -v/--version                        print client version");
        PrintAndLogEx(NORMAL, "      -p/--port                           serial port to connect to");
        PrintAndLogEx(NORMAL, "      -w/--wait                           20sec waiting the serial port to appear in the OS");
        PrintAndLogEx(NORMAL, "      -f/--flush                          output will be flushed after every print");
        PrintAndLogEx(NORMAL, "      -d/--debug <0|1|2>                  set debugmode");
        PrintAndLogEx(NORMAL, "\nOptions in client mode:");
        PrintAndLogEx(NORMAL, "      -t/--text                           dump all interactive command's help at once");
        PrintAndLogEx(NORMAL, "      -m/--markdown                       dump all interactive help at once in markdown syntax");
        PrintAndLogEx(NORMAL, "      -b/--baud                           serial port speed (only needed for physical UART, not for USB-CDC or BT)");
        PrintAndLogEx(NORMAL, "      -c/--command <command>              execute one Proxmark3 command (or several separated by ';').");
        PrintAndLogEx(NORMAL, "      -l/--lua <lua script file>          execute lua script.");
        PrintAndLogEx(NORMAL, "      -s/--script-file <cmd_script_file>  script file with one Proxmark3 command per line");
        PrintAndLogEx(NORMAL, "      -i/--interactive                    enter interactive mode after executing the script or the command");
        PrintAndLogEx(NORMAL, "\nOptions in flasher mode:");
        PrintAndLogEx(NORMAL, "      --flash                             flash Proxmark3, requires at least one --image");
        PrintAndLogEx(NORMAL, "      --unlock-bootloader                 Enable flashing of bootloader area *DANGEROUS* (need --flash or --flash-info)");
        PrintAndLogEx(NORMAL, "      --image <imagefile>                 image to flash. Can be specified several times.");
        PrintAndLogEx(NORMAL, "\nExamples:");
        PrintAndLogEx(NORMAL, "\n  to run Proxmark3 client:\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H"                       -- runs the pm3 client", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -f                    -- flush output everytime", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -w                    -- wait for serial port", exec_name);
        PrintAndLogEx(NORMAL, "      %s                                    -- runs the pm3 client in OFFLINE mode", exec_name);
        PrintAndLogEx(NORMAL, "\n  to execute different commands from terminal:\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -c \"hf mf chk 1* ?\"   -- execute cmd and quit client", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -l hf_read            -- execute lua script " _YELLOW_("`hf_read`")" and quit client", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -s mycmds.txt         -- execute each pm3 cmd in file and quit client", exec_name);
        PrintAndLogEx(NORMAL, "\n  to flash fullimage and bootloader:\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" --flash --unlock-bootloader --image bootrom.elf --image fullimage.elf", exec_name);
#ifdef __linux__
        PrintAndLogEx(NORMAL, "\nNote (Linux):\nif the flasher gets stuck in 'Waiting for Proxmark3 to reappear on <DEVICE>',");
        PrintAndLogEx(NORMAL, "you need to blacklist Proxmark3 for modem-manager - see documentation for more details:");
        PrintAndLogEx(NORMAL, "* https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md");
        PrintAndLogEx(NORMAL, "\nMore info on flashing procedure from the official Proxmark3 wiki:");
        PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/Gentoo%%20Linux");
        PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/Ubuntu%%20Linux");
        PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/OSX\n");
#endif
    }
}

static int flash_pm3(char *serial_port_name, uint8_t num_files, char *filenames[FLASH_MAX_FILES], bool can_write_bl) {

    int ret = PM3_EUNDEF;
    flash_file_t files[FLASH_MAX_FILES];
    memset(files, 0, sizeof(files));
    char *filepaths[FLASH_MAX_FILES] = {0};

    if (serial_port_name == NULL) {
        PrintAndLogEx(ERR, "You must specify a port.\n");
        return PM3_EINVARG;
    }

    for (int i = 0 ; i < num_files; ++i) {
        char *path;
        ret = searchFile(&path, FIRMWARES_SUBDIR, filenames[i], ".elf", true);
        if (ret != PM3_SUCCESS) {
            ret = searchFile(&path, BOOTROM_SUBDIR, filenames[i], ".elf", true);
        }
        if (ret != PM3_SUCCESS) {
            // Last try, let the error msg be displayed if not found
            ret = searchFile(&path, FULLIMAGE_SUBDIR, filenames[i], ".elf", false);
        }
        if (ret != PM3_SUCCESS) {
            goto finish2;
        }
        filepaths[i] = path;
    }

    PrintAndLogEx(SUCCESS, "About to use the following file%s:", num_files > 1 ? "s" : "");
    for (int i = 0 ; i < num_files; ++i) {
        PrintAndLogEx(SUCCESS, "   "_YELLOW_("%s"), filepaths[i]);
    }

    if (OpenProxmark(serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
        PrintAndLogEx(NORMAL, _GREEN_(" found"));
    } else {
        PrintAndLogEx(ERR, "Could not find Proxmark3 on " _RED_("%s") ".\n", serial_port_name);
        ret = PM3_ETIMEOUT;
        goto finish2;
    }

    uint32_t max_allowed = 0;
    ret = flash_start_flashing(can_write_bl, serial_port_name, &max_allowed);
    if (ret != PM3_SUCCESS) {
        goto finish;
    }

    if (num_files == 0)
        goto finish;

    for (int i = 0 ; i < num_files; ++i) {
        ret = flash_load(&files[i], filepaths[i], can_write_bl, max_allowed * ONE_KB);
        if (ret != PM3_SUCCESS) {
            goto finish;
        }
        PrintAndLogEx(NORMAL, "");
    }

    PrintAndLogEx(SUCCESS, _CYAN_("Flashing..."));

    for (int i = 0; i < num_files; i++) {
        ret = flash_write(&files[i]);
        if (ret != PM3_SUCCESS) {
            goto finish;
        }
        flash_free(&files[i]);
        PrintAndLogEx(NORMAL, "");
    }

finish:
    ret = flash_stop_flashing();
    CloseProxmark();
finish2:
    for (int i = 0 ; i < num_files; ++i) {
        if (filepaths[i] != NULL)
            free(filepaths[i]);
    }
    if (ret == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, _CYAN_("All done"));
    else
        PrintAndLogEx(ERR, "Aborted on error");
    PrintAndLogEx(NORMAL, "\nHave a nice day!");
    return ret;
}

#ifndef USE_PREFERENCE_FILE

// Check if windows AnsiColor Support is enabled in the registery
// [HKEY_CURRENT_USER\Console]
//     "VirtualTerminalLevel"=dword:00000001
// 2nd Key needs to be enabled...  This key takes the console out of legacy mode.
// [HKEY_CURRENT_USER\Console]
//     "ForceV2"=dword:00000001

static bool DetectWindowsAnsiSupport(void) {
    bool ret = false;
#if defined(_WIN32)
    HKEY hKey = NULL;
    bool virtualTerminalLevelSet = false;
    bool forceV2Set = false;

    if (RegOpenKeyA(HKEY_CURRENT_USER, "Console", &hKey) == ERROR_SUCCESS) {
        DWORD dwType = REG_SZ;
        BYTE KeyValue[sizeof(dwType)];
        DWORD len = sizeof(KeyValue);

        if (RegQueryValueEx(hKey, "VirtualTerminalLevel", NULL, &dwType, KeyValue, &len) != ERROR_FILE_NOT_FOUND) {
            uint8_t i;
            uint32_t Data = 0;
            for (i = 0; i < 4; i++)
                Data += KeyValue[i] << (8 * i);

            if (Data == 1) { // Reg key is set to 1, Ansi Color Enabled
                virtualTerminalLevelSet = true;
            }
        }
        RegCloseKey(hKey);
    }

    if (RegOpenKeyA(HKEY_CURRENT_USER, "Console", &hKey) == ERROR_SUCCESS) {
        DWORD dwType = REG_SZ;
        BYTE KeyValue[sizeof(dwType)];
        DWORD len = sizeof(KeyValue);

        if (RegQueryValueEx(hKey, "ForceV2", NULL, &dwType, KeyValue, &len) != ERROR_FILE_NOT_FOUND) {
            uint8_t i;
            uint32_t Data = 0;
            for (i = 0; i < 4; i++)
                Data += KeyValue[i] << (8 * i);

            if (Data == 1) { // Reg key is set to 1, Not using legacy Mode.
                forceV2Set = true;
            }
        }
        RegCloseKey(hKey);
    }
    // If both VirtualTerminalLevel and ForceV2 is set, AnsiColor should work
    ret = virtualTerminalLevelSet && forceV2Set;
#endif
    return ret;
}

#endif

int main(int argc, char *argv[]) {
    srand(time(0));

    session.pm3_present = false;
    session.help_dump_mode = false;
    bool waitCOMPort = false;
    bool addLuaExec = false;
    bool stayInCommandLoop = false;
    char *script_cmds_file = NULL;
    char *script_cmd = NULL;
    char *port = NULL;
    uint32_t speed = 0;

#ifdef HAVE_READLINE
    /* initialize history */
    using_history();

#ifdef RL_STATE_READCMD
    rl_extend_line_buffer(1024);
#endif // RL_STATE_READCMD
#endif // HAVE_READLINE

    char *exec_name = argv[0];
#if defined(_WIN32)
    for (int m = strlen(exec_name); m > 0; m--) {
        if (exec_name[m] == '\\') {
            exec_name += (++m);
            break;
        }
    }
#endif

    bool flash_mode = false;
    bool flash_can_write_bl = false;
    bool debug_mode_forced = false;
    int flash_num_files = 0;
    char *flash_filenames[FLASH_MAX_FILES];

    // set global variables soon enough to get the log path
    set_my_executable_path();
    set_my_user_directory();

    for (int i = 1; i < argc; i++) {

        if (argv[i][0] != '-') {
            // For backward compatibility we accept direct port
            if (port != NULL) {
                // We got already one
                PrintAndLogEx(ERR, _RED_("ERROR:") " cannot parse command line. We got " _YELLOW_("%s") " as port and now we got also: " _YELLOW_("%s") "\n", port, argv[i]);
                show_help(false, exec_name);
                return 1;
            }
            port = argv[i];
            continue;
        }

        // port
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing port specification after -p\n");
                show_help(false, exec_name);
                return 1;
            }
            if (port != NULL) {
                // We got already one
                PrintAndLogEx(ERR, _RED_("ERROR:") " cannot parse command line. We got " _YELLOW_("%s") " as port and now we got also: " _YELLOW_("%s") "\n", port, argv[i + 1]);
                show_help(false, exec_name);
                return 1;
            }
            port = argv[++i];
            continue;
        }

        // short help
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            g_printAndLog = PRINTANDLOG_PRINT;
            show_help(true, exec_name);
            return 0;
        }

        // dump help
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--text") == 0) {
            g_printAndLog = PRINTANDLOG_PRINT;
            show_help(false, exec_name);
            dumpAllHelp(0);
            return 0;
        }

        // dump markup
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--markdown") == 0) {
            g_printAndLog = PRINTANDLOG_PRINT;
            dumpAllHelp(1);
            return 0;
        }
        // print client version
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            pm3_version(true, true);
            return 0;
        }

        // set debugmode
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing debugmode specification after -d\n");
                show_help(false, exec_name);
                return 1;
            }
            int demod = atoi(argv[i + 1]);
            if (demod < 0 || demod > 2) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " invalid debugmode: -d " _YELLOW_("%s") "\n", argv[i + 1]);
                return 1;
            }
            g_debugMode = demod;
            debug_mode_forced = true;
            i++;
            continue;
        }

        // flush output
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--flush") == 0) {
            SetFlushAfterWrite(true);
            PrintAndLogEx(INFO, "Output will be flushed after every print.\n");
            continue;
        }

        // set baudrate
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--baud") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing baud specification after -b\n");
                show_help(false, exec_name);
                return 1;
            }
            uint64_t tmpspeed = strtoul(argv[i + 1], NULL, 10);
            if ((tmpspeed == ULONG_MAX) || (tmpspeed == 0)) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " invalid baudrate: -b " _YELLOW_("%s") "\n", argv[i + 1]);
                return 1;
            }
            speed = tmpspeed;
            i++;
            continue;
        }

        // wait for comport
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wait") == 0) {
            waitCOMPort = true;
            continue;
        }

        // execute pm3 command
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--command") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing command specification after -c\n");
                show_help(false, exec_name);
                return 1;
            }
            script_cmd = argv[++i];
            continue;
        }

        // execute pm3 command file
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--script-file") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing script file specification after -s\n");
                show_help(false, exec_name);
                return 1;
            }
            script_cmds_file = argv[++i];
            continue;
        }

        // execute lua script
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--lua") == 0) {
            addLuaExec = true;
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing lua script specification after -l\n");
                show_help(false, exec_name);
                return 1;
            }
            script_cmd = argv[++i];
            continue;
        }

        // go to interactive instead of quitting after a script/command
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            stayInCommandLoop = true;
            continue;
        }

        // go to flash mode
        if (strcmp(argv[i], "--flash") == 0) {
            flash_mode = true;
            continue;
        }

        // unlock bootloader area
        if (strcmp(argv[i], "--unlock-bootloader") == 0) {
            flash_can_write_bl = true;
            continue;
        }

        // flash file
        if (strcmp(argv[i], "--image") == 0) {
            if (flash_num_files == FLASH_MAX_FILES) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " too many --image, please use it max %i times\n", FLASH_MAX_FILES);
                return 1;
            }
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") " missing image specification after --image\n");
                show_help(false, exec_name);
                return 1;
            }
            flash_filenames[flash_num_files++] = argv[++i];
            continue;
        }

        // We got an unknown parameter
        PrintAndLogEx(ERR, _RED_("ERROR:") " invalid parameter: " _YELLOW_("%s") "\n", argv[i]);
        show_help(false, exec_name);
        return 1;
    }

#ifdef USE_PREFERENCE_FILE
    // Load Settings and assign
    // This will allow the command line to override the settings.json values
    preferences_load();
    // quick patch for debug level
    if (! debug_mode_forced)
        g_debugMode = session.client_debug_level;
    // settings_save ();
    // End Settings
#endif

#ifndef USE_PREFERENCE_FILE
    // comment next 2 lines to use session values set from settings_load
    session.supports_colors = DetectWindowsAnsiSupport();
    session.emoji_mode = ALTTEXT;
#endif

    session.stdinOnTTY = isatty(STDIN_FILENO);
    session.stdoutOnTTY = isatty(STDOUT_FILENO);
#if defined(__linux__) || defined(__APPLE__)
    // it's okay to use color if:
    // * Linux or OSX
    // * Not redirected to a file but printed to term
    // For info, grep --color=auto is doing sth like this, plus test getenv("TERM") != "dumb":
    //   struct stat tmp_stat;
    //   if ((fstat (STDOUT_FILENO, &tmp_stat) == 0) && (S_ISCHR (tmp_stat.st_mode)) && isatty(STDIN_FILENO))
#ifdef USE_PREFERENCE_FILE
    if (!session.preferences_loaded) {
        if (session.stdinOnTTY && session.stdoutOnTTY) {
            session.supports_colors = true;
            session.emoji_mode = EMOJI;
        }
    } else {
        // even if prefs, we disable colors if stdin or stdout is not a TTY
        if ((! session.stdinOnTTY) || (! session.stdoutOnTTY)) {
            session.supports_colors = false;
            session.emoji_mode = ALTTEXT;
        }
    }
#else
    if (session.stdinOnTTY && session.stdoutOnTTY) {
        session.supports_colors = true;
        session.emoji_mode = EMOJI;
    }
#endif

#endif
    // Let's take a baudrate ok for real UART, USB-CDC & BT don't use that info anyway
    if (speed == 0)
        speed = USART_BAUD_RATE;

    if (flash_mode) {
        flash_pm3(port, flash_num_files, flash_filenames, flash_can_write_bl);
        exit(EXIT_SUCCESS);
    }

    if (script_cmd) {
        while (script_cmd[strlen(script_cmd) - 1] == ' ')
            script_cmd[strlen(script_cmd) - 1] = 0x00;

        if (strlen(script_cmd) == 0) {
            script_cmd = NULL;
            PrintAndLogEx(ERR, _RED_("ERROR:") " execute command: " _YELLOW_("command not found") ".\n");
            return 2;
        } else {
            if (addLuaExec) {
                // add "script run " to command
                int len = strlen(script_cmd) + 11 + 1;
                char *ctmp = (char *) calloc(len, sizeof(uint8_t));
                if (ctmp != NULL) {
                    memset(ctmp, 0, len);
                    strcpy(ctmp, "script run ");
                    strcpy(&ctmp[11], script_cmd);
                    script_cmd = ctmp;
                }
            }

            PrintAndLogEx(SUCCESS, "execute command from commandline: " _YELLOW_("%s") "\n", script_cmd);
        }
    }

    // try to open USB connection to Proxmark
    if (port != NULL) {
        OpenProxmark(port, waitCOMPort, 20, false, speed);
    }

    if (session.pm3_present && (TestProxmark() != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark\n");
        CloseProxmark();
    }

    if ((port != NULL) && (!session.pm3_present))
        exit(EXIT_FAILURE);

    if (!session.pm3_present)
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") " mode. Check " _YELLOW_("\"%s -h\"") " if it's not what you want.\n", exec_name);

    // ascii art only in interactive client
    if (!script_cmds_file && !script_cmd && session.stdinOnTTY && session.stdoutOnTTY && !flash_mode)
        showBanner();

#ifdef USE_PREFERENCE_FILE
    // Save settings if not loaded from settings json file.
    // Doing this here will ensure other checks and updates are saved to over rule default
    // e.g. Linux color use check
    if (!session.preferences_loaded) {
        PrintAndLogEx(INFO, "Creating initial preferences file");  // json save reports file name, so just info msg here
        preferences_save();  // Save defaults
        session.preferences_loaded = true;
    } /* else {
        // Set device debug level
        PrintAndLogEx(INFO,"setting device debug loglevel");
        if (session.pm3_present) {
           SendCommandNG(CMD_SET_DBGMODE, &session.device_debug_level, 1);
           PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_SET_DBGMODE, &resp, 2000) == false)
                PrintAndLogEx (INFO,"failed to set device debug loglevel");
        }
        else
            PrintAndLogEx(WARNING,"Proxmark3 not ready to set debug level");
    }
    */
#endif

#ifdef HAVE_GUI

#  ifdef _WIN32
    InitGraphics(argc, argv, script_cmds_file, script_cmd, stayInCommandLoop);
    MainGraphics();
#  else
    // for *nix distro's,  check enviroment variable to verify a display
    char *display = getenv("DISPLAY");
    if (display && strlen(display) > 1) {
        InitGraphics(argc, argv, script_cmds_file, script_cmd, stayInCommandLoop);
        MainGraphics();
    } else {
        main_loop(script_cmds_file, script_cmd, stayInCommandLoop);
    }
#  endif

#else
    main_loop(script_cmds_file, script_cmd, stayInCommandLoop);
#endif

    // Clean up the port
    if (session.pm3_present) {
        CloseProxmark();
    }

#ifdef USE_PREFERENCE_FILE
    if (session.window_changed) // Plot/Overlay moved or resized
        preferences_save();
#endif
    exit(EXIT_SUCCESS);
}
