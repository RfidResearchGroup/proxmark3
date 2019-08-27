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

#include <limits.h>

#include <stdio.h> // for Mingw readline
#include <stdlib.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "usart_defs.h"

#include "util_posix.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "ui.h"
#include "cmdhw.h"
#include "whereami.h"
#include "comms.h"
//#include "usart.h"

static void showBanner(void) {
    PrintAndLogEx(NORMAL, "\n");
#if defined(__linux__) || (__APPLE__) || (_WIN32)
    PrintAndLogEx(NORMAL, _BLUE_("██████╗ ███╗   ███╗ ████╗ ") "    ...iceman fork");
    PrintAndLogEx(NORMAL, _BLUE_("██╔══██╗████╗ ████║   ══█║") "      ...dedicated to " _BLUE_("RDV40"));
    PrintAndLogEx(NORMAL, _BLUE_("██████╔╝██╔████╔██║ ████╔╝"));
    PrintAndLogEx(NORMAL, _BLUE_("██╔═══╝ ██║╚██╔╝██║   ══█║") "    iceman@icesql.net");
    PrintAndLogEx(NORMAL, _BLUE_("██║     ██║ ╚═╝ ██║ ████╔╝") "   https://github.com/rfidresearchgroup/proxmark3/");
    PrintAndLogEx(NORMAL, _BLUE_("╚═╝     ╚═╝     ╚═╝ ╚═══╝ ") "pre-release v4.0");
#else
    PrintAndLogEx(NORMAL, "======. ===.   ===. ====.     ...iceman fork");
    PrintAndLogEx(NORMAL, "==...==.====. ====.   ..=.      ...dedicated to RDV40");
    PrintAndLogEx(NORMAL, "======..==.====.==. ====..");
    PrintAndLogEx(NORMAL, "==..... ==..==..==.   ..=.    iceman@icesql.net");
    PrintAndLogEx(NORMAL, "==.     ==. ... ==. ====..   https://github.com/rfidresearchgroup/proxmark3/");
    PrintAndLogEx(NORMAL, "...     ...     ... .....  pre-release v4.0");
#endif
    PrintAndLogEx(NORMAL, "\nSupport iceman on patreon,   https://www.patreon.com/iceman1001/");
//    printf("\nMonero: 43mNJLpgBVaTvyZmX9ajcohpvVkaRy1kbZPm8tqAb7itZgfuYecgkRF36rXrKFUkwEGeZedPsASRxgv4HPBHvJwyJdyvQuP");
    PrintAndLogEx(NORMAL, "\n");
    fflush(stdout);
}

int check_comm(void) {
    // If communications thread goes down. Device disconnected then this should hook up PM3 again.
    if (IsCommunicationThreadDead() && session.pm3_present) {
        rl_set_prompt(PROXPROMPT_OFFLINE);
        rl_forced_update_display();
        CloseProxmark();
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") "mode. Use \"hw connect\" to reconnect\n");
    }
    return 0;
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
    FILE *sf = NULL;
    char script_cmd_buf[256] = {0x00};  // iceman, needs lua script the same file_path_buffer as the rest

    PrintAndLogEx(DEBUG, "ISATTY/STDIN_FILENO == %s\n", (stdinOnPipe) ? "true" : "false");

    if (session.pm3_present) {
        // cache Version information now:
        if (execCommand || script_cmds_file || stdinOnPipe)
            pm3_version(false, false);
        else
            pm3_version(true, false);
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
                if (script_cmd && !stayInCommandLoop)
                    break;

                // if there is a pipe from stdin
                if (stdinOnPipe) {

                    // clear array
                    memset(script_cmd_buf, 0, sizeof(script_cmd_buf));
                    // get
                    if (fgets(script_cmd_buf, sizeof(script_cmd_buf), stdin) == NULL) {
                        PrintAndLogEx(ERR, "STDIN unexpected end, exit...");
                        break;
                    }
                    // remove linebreaks
                    strcleanrn(script_cmd_buf, sizeof(script_cmd_buf));

                    if ((cmd = strmcopy(script_cmd_buf)) != NULL)
                        printprompt = true;

                } else {
                    rl_event_hook = check_comm;
                    if (session.pm3_present) {
                        if (conn.send_via_fpc_usart == false)
                            cmd = readline(PROXPROMPT_USB);
                        else
                            cmd = readline(PROXPROMPT_FPC);
                    } else
                        cmd = readline(PROXPROMPT_OFFLINE);

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
            while ((cmd[off] != '\0') && isspace(cmd[off]))
                off++;
            for (size_t i = 0; i < strlen(cmd) - off; i++)
                cmd[i] = cmd[i + off];
            cmd[strlen(cmd) - off] = '\0';

            if (cmd[0] != '\0') {
                if (printprompt)
                    PrintAndLogEx(NORMAL, PROXPROMPT"%s", cmd);

                int ret = CommandReceived(cmd);

                HIST_ENTRY *entry = history_get(history_length);
                if ((!entry) || (strcmp(entry->line, cmd) != 0))
                    add_history(cmd);

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

    clearCommandBuffer();
    SendCommandNG(CMD_QUIT_SESSION, NULL, 0);
    msleep(100); // Make sure command is sent before killing client

    if (sf)
        fclose(sf);

    write_history(".history");

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

static void show_help(bool showFullHelp, char *exec_name) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "syntax: %s [-h|-t|-m]\n", exec_name);
    PrintAndLogEx(NORMAL, "        %s [[-p] <port>] [-b] [-w] [-f] [-c <command>]|[-l <lua_script_file>]|[-s <cmd_script_file>] [-i]\n", exec_name);

    if (showFullHelp) {
        PrintAndLogEx(NORMAL, "options:");
        PrintAndLogEx(NORMAL, "      -h/--help                           this help");
        PrintAndLogEx(NORMAL, "      -t/--text                           dump all interactive command's help at once");
        PrintAndLogEx(NORMAL, "      -m/--markdown                       dump all interactive help at once in markdown syntax");
        PrintAndLogEx(NORMAL, "      -p/--port                           serial port to connect to");
        PrintAndLogEx(NORMAL, "      -b/--baud                           serial port speed (only needed for physical UART, not for USB-CDC or BT)");
        PrintAndLogEx(NORMAL, "      -w/--wait                           20sec waiting the serial port to appear in the OS");
        PrintAndLogEx(NORMAL, "      -f/--flush                          output will be flushed after every print");
        PrintAndLogEx(NORMAL, "      -c/--command <command>              execute one Proxmark3 command (or several separated by ';').");
        PrintAndLogEx(NORMAL, "      -l/--lua <lua script file>          execute lua script.");
        PrintAndLogEx(NORMAL, "      -s/--script-file <cmd_script_file>  script file with one Proxmark3 command per line");
        PrintAndLogEx(NORMAL, "      -i/--interactive                    enter interactive mode after executing the script or the command");
        PrintAndLogEx(NORMAL, "      -v/--version                        print client version");
        PrintAndLogEx(NORMAL, "\nsamples:");
        PrintAndLogEx(NORMAL, "      %s -h\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s -m\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -f             -- flush output everytime\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -w             -- wait for serial port\n", exec_name);
        PrintAndLogEx(NORMAL, "\n  how to run Proxmark3 client\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H"                -- runs the pm3 client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s                             -- runs the pm3 client in OFFLINE mode\n", exec_name);
        PrintAndLogEx(NORMAL, "\n  how to execute different commands from terminal\n");
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -c \"hf mf chk 1* ?\"   -- execute cmd and quit client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -l hf_read            -- execute lua script " _YELLOW_("`hf_read`")"and quit client\n", exec_name);
        PrintAndLogEx(NORMAL, "      %s "SERIAL_PORT_EXAMPLE_H" -s mycmds.txt         -- execute each pm3 cmd in file and quit client\n", exec_name);
    }
}

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
        // pritn client version
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            pm3_version(true, true);
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
            uint64_t tmpspeed = strtoul(argv[i + 1], NULL, 10);
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

        // execute pm3 command file
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

        // go to interactive instead of quitting after a script/command
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            stayInCommandLoop = true;
            continue;
        }

        // We got an unknown parameter
        PrintAndLogEx(ERR, _RED_("ERROR:") "invalid parameter: " _YELLOW_("%s") "\n", argv[i]);
        show_help(false, exec_name);
        return 1;
    }

    session.supports_colors = false;
    session.stdinOnTTY = isatty(STDIN_FILENO);
    session.stdoutOnTTY = isatty(STDOUT_FILENO);
#if defined(__linux__) || (__APPLE__)
    // it's okay to use color if:
    // * Linux or OSX
    // * Not redirected to a file but printed to term
    // For info, grep --color=auto is doing sth like this, plus test getenv("TERM") != "dumb":
    //   struct stat tmp_stat;
    //   if ((fstat (STDOUT_FILENO, &tmp_stat) == 0) && (S_ISCHR (tmp_stat.st_mode)) && isatty(STDIN_FILENO))
    if (session.stdinOnTTY && session.stdoutOnTTY)
        session.supports_colors = true;
#endif
    // ascii art only in interactive client
    if (!script_cmds_file && !script_cmd && session.stdinOnTTY && session.stdoutOnTTY)
        showBanner();

    // Let's take a baudrate ok for real UART, USB-CDC & BT don't use that info anyway
    if (speed == 0)
        speed = USART_BAUD_RATE;

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
    if (port != NULL) {
        OpenProxmark(port, waitCOMPort, 20, false, speed);
    }

    if (session.pm3_present && (TestProxmark() != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") "cannot communicate with the Proxmark\n");
        CloseProxmark();
    }

    if ((port != NULL) && (!session.pm3_present))
        exit(EXIT_FAILURE);

    if (!session.pm3_present)
        PrintAndLogEx(INFO, "Running in " _YELLOW_("OFFLINE") "mode. Check \"%s -h\" if it's not what you want.\n", exec_name);

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

    exit(EXIT_SUCCESS);
}
