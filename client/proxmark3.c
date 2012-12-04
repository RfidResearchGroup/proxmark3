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
//#include "proxusb.h"
#include "proxmark3.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "uart.h"
#include "messages.h"
#include "ui.h"

static serial_port sp;

void SendCommand(UsbCommand *c) {
#if 0
  printf("Sending %d bytes\n", sizeof(UsbCommand));
#endif
  if (!uart_send(sp,(byte_t*)c,sizeof(UsbCommand))) {
    ERR("Sending bytes to proxmark failed");
  }
}

struct receiver_arg {
  int run;
};

struct main_loop_arg {
  int usb_present;
  char *script_cmds_file;
};

//static void *usb_receiver(void *targ) {
//  struct receiver_arg *arg = (struct receiver_arg*)targ;
//  UsbCommand cmdbuf;
//
//  while (arg->run) {
//    if (ReceiveCommandPoll(&cmdbuf)) {
//      UsbCommandReceived(&cmdbuf);
//      fflush(NULL);
//    }
//  }
//
//  pthread_exit(NULL);
//  return NULL;
//}

byte_t rx[0x1000000];

static void *uart_receiver(void *targ) {
  struct receiver_arg *arg = (struct receiver_arg*)targ;
  size_t rxlen;
  size_t cmd_count;
  
  while (arg->run) {
    if (uart_receive(sp,rx,&rxlen)) {
      if ((rxlen % sizeof(UsbCommand)) != 0) {
        PrintAndLog("ERROR: received %zd bytes, which does not seem to be one or more command(s)\n",rxlen);
        continue;
      }
      cmd_count = rxlen / sizeof(UsbCommand);
//      printf("received %zd bytes, which represents %zd commands\n",rxlen, cmd_count);
      for (size_t i=0; i<cmd_count; i++) {
        UsbCommandReceived((UsbCommand*)(rx+(i*sizeof(UsbCommand))));
      }
    }
  }
  
  pthread_exit(NULL);
  return NULL;
}


static void *main_loop(void *targ) {
  struct main_loop_arg *arg = (struct main_loop_arg*)targ;
  struct receiver_arg rarg;
  char *cmd = NULL;
  pthread_t reader_thread;
  
  if (arg->usb_present == 1) {
    rarg.run=1;
    // pthread_create(&reader_thread, NULL, &usb_receiver, &rarg);
    pthread_create(&reader_thread, NULL, &uart_receiver, &rarg);
  }
  
  FILE *script_file = NULL;
  char script_cmd_buf[256];
  
  if (arg->script_cmds_file)
  {
    script_file = fopen(arg->script_cmds_file, "r");
    if (script_file)
    {
      printf("using 'scripting' commands file %s\n", arg->script_cmds_file);
    }
  }

	read_history(".history");
	while(1)
  {
    // If there is a script file
    if (script_file)
    {
      if (!fgets(script_cmd_buf, sizeof(script_cmd_buf), script_file))
      {
        fclose(script_file);
        script_file = NULL;
      }
      else
      {
        char *nl;
        nl = strrchr(script_cmd_buf, '\r');
        if (nl) *nl = '\0';
        nl = strrchr(script_cmd_buf, '\n');
        if (nl) *nl = '\0';
        
        if ((cmd = (char*) malloc(strlen(script_cmd_buf))) != NULL)
        {
          memset(cmd, 0, strlen(script_cmd_buf));
          strcpy(cmd, script_cmd_buf);
          printf("%s\n", cmd);
        }
      }
    }
		
		if (!script_file)
		{
      cmd = readline(PROXPROMPT);
		}
		
		if (cmd) {
			while(cmd[strlen(cmd) - 1] == ' ')
        cmd[strlen(cmd) - 1] = 0x00;
			
			if (cmd[0] != 0x00) {
				if (strncmp(cmd, "quit", 4) == 0) {
					break;
				}
				
				CommandReceived(cmd);
				add_history(cmd);
			}
			free(cmd);
		} else {
			printf("\n");
			break;
		}
	}
  
	write_history(".history");
  
  if (arg->usb_present == 1) {
    rarg.run = 0;
    pthread_join(reader_thread, NULL);
  }
  
  if (script_file)
  {
    fclose(script_file);
    script_file = NULL;
  }
  
  ExitGraphics();
  pthread_exit(NULL);
  return NULL;
}

int main(int argc, char* argv[]) {
  
  if (argc < 2) {
    printf("syntax: %s <port>\n\n",argv[0]);
    return 1;
  }
  
  // Make sure to initialize
  struct main_loop_arg marg = {
    .usb_present = 0,
    .script_cmds_file = NULL
  };
  pthread_t main_loop_t;

/*
  usb_init();
  if (!OpenProxmark(1)) {
    fprintf(stderr,"PROXMARK3: NOT FOUND!\n");
    marg.usb_present = 0;
    offline = 1;
  } else {
    marg.usb_present = 1;
    offline = 0;
  }
*/
  sp = uart_open(argv[1]);
  if (sp == INVALID_SERIAL_PORT) {
    printf("ERROR: invalid serial port\n");
    marg.usb_present = 0;
    offline = 1;
  } else {
    marg.usb_present = 1;
    offline = 0;
  }

  // If the user passed the filename of the 'script' to execute, get it
  if (argc > 2 && argv[2]) {
    marg.script_cmds_file = argv[2];
  }
  
  pthread_create(&main_loop_t, NULL, &main_loop, &marg);
  InitGraphics(argc, argv);

  MainGraphics();

  pthread_join(main_loop_t, NULL);

//  if (marg.usb_present == 1) {
//    CloseProxmark();
//  }

  // Clean up the port
  uart_close(sp);
  
  return 0;
}
