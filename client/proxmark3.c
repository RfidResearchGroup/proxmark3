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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "util_posix.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "ui.h"
#include "util.h"
#include "cmdparser.h"
#include "cmdhw.h"
#include "whereami.h"
#include "comms.h"
#include "usart.h"

static void showBanner(void) {
    printf("\n\n");
#if defined(__linux__) || (__APPLE__)
    printf(_BLUE_("██████╗ ███╗   ███╗ ████╗ ") "    ...iceman fork\n");
    printf(_BLUE_("██╔══██╗████╗ ████║   ══█║") "      ...dedicated to " _BLUE_("RDV40") "\n");
    printf(_BLUE_("██████╔╝██╔████╔██║ ████╔╝") "\n");
    printf(_BLUE_("██╔═══╝ ██║╚██╔╝██║   ══█║") "    iceman@icesql.net\n");
    printf(_BLUE_("██║     ██║ ╚═╝ ██║ ████╔╝") "   https://github.com/rfidresearchgroup/proxmark3/\n");
    printf(_BLUE_("╚═╝     ╚═╝     ╚═╝ ╚═══╝ ") "pre-release v4.0\n");
#else
    printf("======. ===.   ===. ====.     ...iceman fork\n");
    printf("==...==.====. ====.   ..=.      ...dedicated to RDV40\n");
    printf("======..==.====.==. ====..\n");
    printf("==..... ==..==..==.   ..=.    iceman@icesql.net\n");
    printf("==.     ==. ... ==. ====..   https://github.com/rfidresearchgroup/proxmark3/\n");
    printf("...     ...     ... .....  pre-release v4.0\n");
#endif
    printf("\nSupport iceman on patreon,   https://www.patreon.com/iceman1001/");
//    printf("\nMonero: 43mNJLpgBVaTvyZmX9ajcohpvVkaRy1kbZPm8tqAb7itZgfuYecgkRF36rXrKFUkwEGeZedPsASRxgv4HPBHvJwyJdyvQuP");
    printf("\n\n\n");
    fflush(stdout);
}

void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
main_loop(char *script_cmds_file, char *script_cmd, bool pm3_present) {

    char *cmd = NULL;
    bool execCommand = (script_cmd != NULL);
    uint16_t script_cmd_len = 0;
    if (execCommand) {
        script_cmd_len = strlen(script_cmd);
        strcreplace(script_cmd, script_cmd_len, ';', '\0');
    }
    bool stdinOnPipe = !isatty(STDIN_FILENO);
    FILE *sf = NULL;
    char script_cmd_buf[256] = {0x00};  // iceman, needs lua script the same file_path_buffer as the rest

    PrintAndLogEx(DEBUG, "ISATTY/STDIN_FILENO == %s\n", (stdinOnPipe) ? "true" : "false");

    if (pm3_present) {
        SetOffline(false);
        // cache Version information now:
        if (execCommand || script_cmds_file || stdinOnPipe)
            pm3_version(false);
        else
            pm3_version(true);
    } else {
        SetOffline(true);
    }

    if (script_cmds_file) {

        sf = fopen(script_cmds_file, "r");
        if (sf)
            PrintAndLogEx(SUCCESS, "executing commands from file: %s\n", script_cmds_file);
        else
            PrintAndLogEx(ERR, "could not open " _YELLOW_("%s") "...", script_cmds_file);
    }

    read_history(".history");

    // loops every time enter is pressed...
    while (1) {
        bool printprompt = false;
        // this should hook up the PM3 again.
        /*
        if ( IsOffline() ) {

            // sets the global variable, SP and offline)
            pm3_present = hookUpPM3();

            // usb and the reader_thread is NULL,  create a new reader thread.
            if (pm3_present && !IsOffline() ) {
                rarg.run = 1;
                pthread_create(&reader_thread, NULL, &uart_receiver, &rarg);
                // cache Version information now:
                if ( execCommand || script_cmds_file || stdinOnPipe)
                    CmdVersion("s");
                else
                    CmdVersion("");
            }
        }
        */

        // If there is a script file
        if (sf) {

            // clear array
            memset(script_cmd_buf, 0, sizeof(script_cmd_buf));

            // read script file
            if (!fgets(script_cmd_buf, sizeof(script_cmd_buf), sf)) {
                fclose(sf);
                sf = NULL;
            } else {

                // remove linebreaks
                strcleanrn(script_cmd_buf, sizeof(script_cmd_buf));

                if ((cmd = strmcopy(script_cmd_buf)) != NULL)
                    printprompt = true;
            }
        } else {
            // If there is a script command
            if (execCommand) {
                if ((cmd = strmcopy(script_cmd)) != NULL)
                    printprompt = true;
                uint16_t len = strlen(script_cmd) + 1;
                script_cmd += len;
                if (script_cmd_len == len - 1)
                    execCommand = false;
                script_cmd_len -= len;
            } else {
                // exit after exec command
                if (script_cmd)
                    break;

                // if there is a pipe from stdin
                if (stdinOnPipe) {

                    // clear array
                    memset(script_cmd_buf, 0, sizeof(script_cmd_buf));
                    // get
                    if (!fgets(script_cmd_buf, sizeof(script_cmd_buf), stdin)) {
                        PrintAndLogEx(ERR, "STDIN unexpected end, exit...");
                        break;
                    }
                    // remove linebreaks
                    strcleanrn(script_cmd_buf, sizeof(script_cmd_buf));

                    if ((cmd = strmcopy(script_cmd_buf)) != NULL)
                        printprompt = true;

                } else {
                    cmd = readline(PROXPROMPT);
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
            size_t off=0;
            while ((cmd[off] != '\0') && isspace(cmd[off]))
                off++;
            for (size_t i=0; i < strlen(cmd) - off; i++)
                cmd[i] = cmd[i+off];
            cmd[strlen(cmd) - off] = '\0';

            if (cmd[0] != '\0') {
                if (printprompt)
                    PrintAndLogEx(NORMAL, PROXPROMPT"%s", cmd);
                int ret = CommandReceived(cmd);
                HIST_ENTRY *entry = history_get(history_length);
                if ((!entry) || (strcmp(entry->line, cmd) != 0))
                    add_history(cmd);

                // exit or quit
                if (ret == 99)
                    break;
            }
            free(cmd);
            cmd = NULL;
        } else {
            PrintAndLogEx(NORMAL, "\n");
            break;
        }
    } // end while

    if (sf)
        fclose(sf);

    write_history(".history");

    if (cmd) {
        free(cmd);
        cmd = NULL;
    }
}

static void dumpAllHelp(int markdown) {
    PrintAndLogEx(NORMAL, "\n%sProxmark3 command dump%s\n\n", markdown ? "# " : "", markdown ? "" : "\n======================");
    PrintAndLogEx(NORMAL, "Some commands are available only if a Proxmark3 is actually connected.%s\n", markdown ? "  " : "");
    PrintAndLogEx(NORMAL, "Check column \"offline\" for their availability.\n");
    PrintAndLogEx(NORMAL, "\n");
    command_t *cmds = getTopLevelCommandTable();
    dumpCommandsRecursive(cmds, markdown);
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

static void show_help(bool showFullHelp, char *exec_name) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "syntax: %s [-h|-t|-m]\n", exec_name);
    PrintAndLogEx(NORMAL, "        %s [[-p] <port>] [-b] [-w] [-f] [-c <command>]|[-l <lua_script_file>]|[-s <cmd_script_file>]\n", exec_name);

    if (showFullHelp) {
        PrintAndLogEx(NORMAL, "options:");
        PrintAndLogEx(NORMAL, "      -h/--help                           this help");
        PrintAndLogEx(NORMAL, "      -t/--text                           dump all interactive command's help at once");
        PrintAndLogEx(NORMAL, "      -m/--markdown                       dump all interactive help at once in markdown syntax");
        PrintAndLogEx(NORMAL, "      -p/--port                           serial port to connect to");
        PrintAndLogEx(NORMAL, "      -b/--baud                           serial port speed");
        PrintAndLogEx(NORMAL, "      -w/--wait                           20sec waiting the serial port to appear in the OS");
        PrintAndLogEx(NORMAL, "      -f/--flush                          output will be flushed after every print");
        PrintAndLogEx(NORMAL, "      -c/--command <command>              execute one proxmark3 command (or several separated by ';').");
        PrintAndLogEx(NORMAL, "      -l/--lua <lua script file>          execute lua script.");
        PrintAndLogEx(NORMAL, "      -s/--script-file <cmd_script_file>  script file with one proxmark3 command per line");
        PrintAndLogEx(NORMAL, "\nsamples:");
        PrintAndLogEx(NORMAL, "      %s -h\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s -m\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H" -f             -- flush output everytime\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H" -w             -- wait for serial port\n", exec_name);
        PrintAndLogEx(NORMAL, "\n  how to run Proxmark3 client\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H"                -- runs the pm3 client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s                             -- runs the pm3 client in OFFLINE mode\n", exec_name);
        PrintAndLogEx(NORMAL, "\n  how to execute different commands from terminal\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H" -c \"hf mf chk 1* ?\"   -- execute cmd and quit client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H" -l hf_read            -- execute lua script " _YELLOW_("`hf_read`")"and quit client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_H" -s mycmds.txt         -- execute each pm3 cmd in file and quit client\n", exec_name);
    }
}

int main(int argc, char *argv[]) {
    srand(time(0));

    bool pm3_present = false;
    bool waitCOMPort = false;
    bool addLuaExec = false;
    char *script_cmds_file = NULL;
    char *script_cmd = NULL;
    char *port = NULL;
    uint32_t speed = 0;

    /* initialize history */
    using_history();

#ifdef RL_STATE_READCMD
    rl_extend_line_buffer(1024);
#endif

    char *exec_name = argv[0];
#if defined(_WIN32)
    for (int m = strlen(exec_name); m > 0; m--) {
        if (exec_name[m] == '\\') {
            exec_name += (++m);
            break;
        }
    }
#endif

    for (int i = 1; i < argc; i++) {

        if (argv[i][0] != '-') {
            // For backward compatibility we accept direct port
            if (port != NULL) {
                // We got already one
                PrintAndLogEx(ERR, _RED_("ERROR:") "cannot parse command line. We got " _YELLOW_("%s") " as port and now we got also: " _YELLOW_("%s") "\n", port, argv[i]);
                show_help(false, exec_name);
                return 1;
            }
            port = argv[i];
            continue;
        }

        // port
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") "missing port specification after -p\n");
                show_help(false, exec_name);
                return 1;
            }
            if (port != NULL) {
                // We got already one
                PrintAndLogEx(ERR, _RED_("ERROR:") "cannot parse command line. We got " _YELLOW_("%s") " as port and now we got also: " _YELLOW_("%s") "\n", port, argv[i + 1]);
                show_help(false, exec_name);
                return 1;
            }
            port = argv[++i];
            continue;
        }

        // short help
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help(true, exec_name);
            return 0;
        }

        // dump help
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--text") == 0) {
            show_help(false, exec_name);
            dumpAllHelp(0);
            return 0;
        }

        // dump markup
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--markdown") == 0) {
            dumpAllHelp(1);
            return 0;
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
                PrintAndLogEx(ERR, _RED_("ERROR:") "missing baud specification after -b\n");
                show_help(false, exec_name);
                return 1;
            }
            uint32_t tmpspeed = strtoul(argv[i + 1], NULL, 10);
            if ((tmpspeed == ULONG_MAX) || (tmpspeed == 0)) {
                PrintAndLogEx(ERR, _RED_("ERROR:") "invalid baudrate: -b " _YELLOW_("%s") "\n", argv[i + 1]);
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
                PrintAndLogEx(ERR, _RED_("ERROR:") "missing command specification after -c\n");
                show_help(false, exec_name);
                return 1;
            }
            script_cmd = argv[++i];
            continue;
        }

        // execute pm3 command
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--script-file") == 0) {
            if (i + 1 == argc) {
                PrintAndLogEx(ERR, _RED_("ERROR:") "missing script file specification after -s\n");
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
                PrintAndLogEx(ERR, _RED_("ERROR:") "missing lua script specification after -l\n");
                show_help(false, exec_name);
                return 1;
            }
            script_cmd = argv[++i];
            continue;
        }

        // We got an unknown parameter
        PrintAndLogEx(ERR, _RED_("ERROR:") "invalid parameter: " _YELLOW_("%s") "\n", argv[i]);
        show_help(false, exec_name);
        return 1;
    }

    // ascii art
    bool stdinOnPipe = !isatty(STDIN_FILENO);
    if (!script_cmds_file && !stdinOnPipe)
        showBanner();


    // default speed for USB 460800,  USART(FPC serial) 115200 baud
    if (speed == 0)
#ifdef WITH_FPC_HOST
        // Let's assume we're talking by default to pm3 over usart in this mode
        speed = AT91_BAUD_RATE;
#else
        speed = 460800;
#endif

    if (script_cmd) {
        while (script_cmd[strlen(script_cmd) - 1] == ' ')
            script_cmd[strlen(script_cmd) - 1] = 0x00;

        if (strlen(script_cmd) == 0) {
            script_cmd = NULL;
            PrintAndLogEx(ERR, _RED_("ERROR:") "execute command: " _YELLOW_("command not found") ".\n");
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

    // set global variables
    set_my_executable_path();

    // try to open USB connection to Proxmark
    if (port != NULL)
        pm3_present = OpenProxmark(port, waitCOMPort, 20, false, speed);

    if (pm3_present && (TestProxmark() == 0))
        pm3_present = false;
    if (!pm3_present)
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") "mode. Check \"%s -h\" if it's not what you want.\n", exec_name);

#ifdef HAVE_GUI

#  ifdef _WIN32
    InitGraphics(argc, argv, script_cmds_file, script_cmd, pm3_present);
    MainGraphics();
#  else
    // for *nix distro's,  check enviroment variable to verify a display
    char *display = getenv("DISPLAY");
    if (display && strlen(display) > 1) {
        InitGraphics(argc, argv, script_cmds_file, script_cmd, pm3_present);
        MainGraphics();
    } else {
        main_loop(script_cmds_file, script_cmd, pm3_present);
    }
#  endif

#else
    main_loop(script_cmds_file, script_cmd, pm3_present);
#endif

    // Clean up the port
    if (pm3_present) {
        CloseProxmark();
    }

    exit(0);
}
