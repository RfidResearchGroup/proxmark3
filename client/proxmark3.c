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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "proxmark3.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "uart.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhw.h"
#include "whereami.h"

// a global mutex to prevent interlaced printing from different threads
extern pthread_mutex_t print_lock;
static serial_port sp;
static UsbCommand txcmd;
static char comport[255];

volatile static bool txcmd_pending = false;

void SendCommand(UsbCommand *c) {
	#if 0
	pthread_mutex_lock(&print_lock);
	printf("Sending %d bytes\n", sizeof(UsbCommand));
	pthread_mutex_unlock(&print_lock);
	#endif

	if (offline) {
		PrintAndLog("Sending bytes to proxmark failed - offline");
		return;
	}
	/**
	The while-loop below causes hangups at times, when the pm3 unit is unresponsive
	or disconnected. The main console thread is alive, but comm thread just spins here.
	Not good.../holiman
	**/
	while(txcmd_pending);

	txcmd = *c;
	 __atomic_test_and_set(&txcmd_pending, __ATOMIC_SEQ_CST);
}

struct receiver_arg {
	int run;
};

byte_t rx[sizeof(UsbCommand)];
byte_t* prx = rx;

#if defined(__linux__)
static void showBanner(void){
	printf("\n\n");
	printf("\e[34m██████╗ ███╗   ███╗ ████╗\e[0m     ...iceman fork\n");
	printf("\e[34m██╔══██╗████╗ ████║   ══█║\e[0m\n");
	printf("\e[34m██████╔╝██╔████╔██║ ████╔╝\e[0m\n");
	printf("\e[34m██╔═══╝ ██║╚██╔╝██║   ══█║\e[0m    iceman@icesql.net\n");
	printf("\e[34m██║     ██║ ╚═╝ ██║ ████╔╝\e[0m  https://github.com/iceman1001/proxmark3\n");
	printf("\e[34m╚═╝     ╚═╝     ╚═╝ ╚═══╝\e[0m v3.0.0\n");
	printf("\nKeep iceman fork alive with a donation!           https://paypal.me/iceman1001/");
	printf("\nMONERO: 43mNJLpgBVaTvyZmX9ajcohpvVkaRy1kbZPm8tqAb7itZgfuYecgkRF36rXrKFUkwEGeZedPsASRxgv4HPBHvJwyJdyvQuP");
	printf("\n\n\n");
}
#endif

static bool hookUpPM3() {	
	bool ret = false;
	sp = uart_open( comport );
	if (sp == INVALID_SERIAL_PORT) {
		printf("ERROR: invalid serial port\n");
		ret = false;
		offline = 1;
	} else if (sp == CLAIMED_SERIAL_PORT) {
		printf("ERROR: serial port is claimed by another process\n");
		ret = false;
		offline = 1;
	} else {
		//printf("OK: connected to serial port %s\n", comport);
		ret = true;
		offline = 0;
	}
	return ret;
}

// (iceman) if uart_receiver fails a command three times,  we conside the device to be offline.
static void *uart_receiver(void *targ) {
	struct receiver_arg *arg = (struct receiver_arg*)targ;
	size_t rxlen;
	int counter_to_offline = 0;
	
	while (arg->run) {
		rxlen = 0;
		if (uart_receive(sp, prx, sizeof(UsbCommand) - (prx-rx), &rxlen)) {
			
			prx += rxlen;
			if (prx-rx < sizeof(UsbCommand)) {
				continue;
			}
			
			UsbCommandReceived((UsbCommand*)rx);
		}
		prx = rx;

		bool tmpsignal;
		__atomic_load(&txcmd_pending, &tmpsignal, __ATOMIC_SEQ_CST);
		if ( tmpsignal ) {
			bool res = uart_send(sp, (byte_t*) &txcmd, sizeof(UsbCommand));
			if (!res) {
				counter_to_offline++;
				PrintAndLog("Sending bytes to proxmark failed");
			}
			 __atomic_clear(&txcmd_pending, __ATOMIC_SEQ_CST);
			//txcmd_pending = false;
			
			// set offline flag
			if ( counter_to_offline == 3 ) {
				__atomic_test_and_set(&offline, __ATOMIC_SEQ_CST);
				break;
			}			
		}
	}

	// when this reader thread dies, we close the serial port.
	uart_close(sp);
	
	pthread_exit(NULL);
	return NULL;
}

void main_loop(char *script_cmds_file, bool usb_present) {

	struct receiver_arg rarg;
	pthread_t reader_thread;
	char *cmd = NULL;
	
	if (usb_present) {
		rarg.run = 1;
		//
		pthread_create(&reader_thread, NULL, &uart_receiver, &rarg);
		// cache Version information now:
		CmdVersion(NULL);
	}

	FILE *script_file = NULL;
	char script_cmd_buf[256] = {0x00};  // iceman, needs lua script the same file_path_buffer as the rest

	if (script_cmds_file) {
		script_file = fopen(script_cmds_file, "r");
		
		if (script_file)
			printf("using 'scripting' commands file %s\n", script_cmds_file);
	}

	read_history(".history");
	
	// loops everytime enter is pressed...
	while(1) {
		
		// this should hook up the PM3 again.
		if (offline) {
			
			// sets the global variable, SP and offline)
			usb_present = hookUpPM3();
		
			// usb and the reader_thread is NULL,  create a new reader thread.
			if (usb_present && !offline) {
				rarg.run = 1;
				pthread_create(&reader_thread, NULL, &uart_receiver, &rarg);
				// cache Version information now:
				CmdVersion(NULL);
			}
		}

		// If there is a script file
		if (script_file) {
			
			if (!fgets(script_cmd_buf, sizeof(script_cmd_buf), script_file)) {
				fclose(script_file);
				script_file = NULL;
			} else {
				char *nl;
				nl = strrchr(script_cmd_buf, '\r');
				if (nl)
					*nl = '\0';
				
				nl = strrchr(script_cmd_buf, '\n');
				
				if (nl)
					*nl = '\0';
				
				int newlen = strlen(script_cmd_buf);
				if ((cmd = (char*) malloc( newlen + 1)) != NULL) {
					memset(cmd, 0x00, newlen);
					strcpy(cmd, script_cmd_buf);
					
					pthread_mutex_lock(&print_lock);
					printf("%s\n", cmd);
					pthread_mutex_unlock(&print_lock);
				}
			}
		} else {
			cmd = readline(PROXPROMPT);
		}
		
		// this one should pick up all non-null cmd...
		// why is there a 
		if (cmd) {
			if (strlen(cmd) > 0) {
				while(cmd[strlen(cmd) - 1] == ' ')
					cmd[strlen(cmd) - 1] = 0x00;
			}

			if (cmd[0] != 0x00) {
				int ret = CommandReceived(cmd);
				add_history(cmd);
				
				// exit or quit
				if (ret == 99) 
					break;
			}
			free(cmd);
			cmd = 0;
		} else {
			pthread_mutex_lock(&print_lock);
			printf("\n");
			pthread_mutex_unlock(&print_lock);
			break;
		}
	}

	if (script_file)
		fclose(script_file);
	
	write_history(".history");

	free(cmd);
	cmd = 0;
			
	if (usb_present) {
		rarg.run = 0;
		pthread_join(reader_thread, NULL);
	}
}

static void dumpAllHelp(int markdown) {
	printf("\n%sProxmark3 command dump%s\n\n",markdown?"# ":"",markdown?"":"\n======================");
	printf("Some commands are available only if a Proxmark is actually connected.%s\n",markdown?"  ":"");
	printf("Check column \"offline\" for their availability.\n");
	printf("\n");
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
	if (path_length != -1) {
		my_executable_path = (char*)malloc(path_length + 1);
		int dirname_length = 0;
		if (wai_getExecutablePath(my_executable_path, path_length, &dirname_length) != -1) {
			my_executable_path[path_length] = '\0';
			my_executable_directory = (char *)malloc(dirname_length + 2);
			strncpy(my_executable_directory, my_executable_path, dirname_length+1);
			my_executable_directory[dirname_length+1] = '\0';
		}
	}
}

int main(int argc, char* argv[]) {
	srand(time(0));
  
	if (argc < 2) {
		printf("syntax: %s <port>\n\n",argv[0]);
		printf("\tLinux example:'%s /dev/ttyACM0'\n", argv[0]);
		printf("\tWindows example:'%s com3'\n\n", argv[0]);
		printf("help:   %s -h\n\n", argv[0]);
		printf("\tDump all interactive help at once\n");
		printf("markdown:   %s -m\n\n", argv[0]);
		printf("\tDump all interactive help at once in markdown syntax\n");
		return 1;
	}
	if (strcmp(argv[1], "-h") == 0) {
		printf("syntax: %s <port>\n\n",argv[0]);
		printf("\tLinux example:'%s /dev/ttyACM0'\n", argv[0]);
		printf("\tWindows example:'%s com3'\n\n", argv[0]);
		dumpAllHelp(0);
		return 0;
	}
	if (strcmp(argv[1], "-m") == 0) {
		dumpAllHelp(1);
		return 0;
	}

#if defined(__linux__)
// ascii art doesn't work well on mingw :( 
	showBanner();  
#endif
	
	set_my_executable_path();
	
	char *script_cmds_file = NULL;

	// lets copy the comport string.
	memset(comport, 0, sizeof(comport));
	memcpy(comport, argv[1], strlen(argv[1]));
	
	// sets the global variable, SP and offline)
	bool usb_present = hookUpPM3();

	// If the user passed the filename of the 'script' to execute, get it
	if (argc > 2 && argv[2]) {
		
		printf("Num of args: %d   -- %s\n", argc, argv[2]);
		
		if (argv[2][0] == 'f' &&  //buzzy, if a word 'flush' passed, flush the output after every log entry.
			argv[2][1] == 'l' &&
			argv[2][2] == 'u' &&
			argv[2][3] == 's' &&
			argv[2][4] == 'h')
		{
			printf("Output will be flushed after every print.\n");
			flushAfterWrite = 1;
		}
		else {
			script_cmds_file = argv[2];
		}
	}

	// create a mutex to avoid interlacing print commands from our different threads
	pthread_mutex_init(&print_lock, NULL);

#ifdef HAVE_GUI

#  if _WIN32
	InitGraphics(argc, argv, script_cmds_file, usb_present);
	MainGraphics();
#  else
	// for *nix distro's,  check enviroment variable to verify a display
	char* display = getenv("DISPLAY");
	if (display && strlen(display) > 1) {
		InitGraphics(argc, argv, script_cmds_file, usb_present);
		MainGraphics();
	} else {
		main_loop(script_cmds_file, usb_present);
	}
#  endif
	
#else
	main_loop(script_cmds_file, usb_present);
#endif	
 
	// clean up mutex
	pthread_mutex_destroy(&print_lock);
	
	exit(0);
}
