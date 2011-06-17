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
#include "proxusb.h"
#include "proxmark3.h"
#include "proxgui.h"
#include "cmdmain.h"

struct usb_receiver_arg
{
  int run;
};

struct main_loop_arg
{
  int usb_present;
};

static void *usb_receiver(void *targ)
{
  struct usb_receiver_arg *arg = (struct usb_receiver_arg*)targ;
  UsbCommand cmdbuf;

  while (arg->run) {
    if (ReceiveCommandPoll(&cmdbuf)) {
      for (int i = 0; i < strlen(PROXPROMPT); i++)
        putchar(0x08);
      UsbCommandReceived(&cmdbuf);
			// there is a big bug )
			if (cmdbuf.cmd > 0x0100 && cmdbuf.cmd < 0x0110) { // debug commands
				rl_on_new_line_with_prompt();
				rl_forced_update_display();
			}
      fflush(NULL);
    }
  }

  pthread_exit(NULL);
  return NULL;
}

static void *main_loop(void *targ)
{
  struct main_loop_arg *arg = (struct main_loop_arg*)targ;
  struct usb_receiver_arg rarg;
  char *cmd = NULL;
  pthread_t reader_thread;

  if (arg->usb_present == 1) {
    rarg.run=1;
    pthread_create(&reader_thread, NULL, &usb_receiver, &rarg);
  }

	read_history(".history");
	while(1) {
		cmd = readline(PROXPROMPT);
		if (cmd) {
			while(cmd[strlen(cmd) - 1] == ' ')
			cmd[strlen(cmd) - 1] = 0x00;
			
			if (cmd[0] != 0x00) {
				if (strncmp(cmd, "quit", 4) == 0) {
					write_history(".history");
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

  if (arg->usb_present == 1) {
    rarg.run = 0;
    pthread_join(reader_thread, NULL);
  }

  ExitGraphics();
  pthread_exit(NULL);
  return NULL;
}

int main(int argc, char **argv)
{
  struct main_loop_arg marg;
  pthread_t main_loop_t;
  usb_init();

  if (!OpenProxmark(1)) {
    fprintf(stderr,"PROXMARK3: NOT FOUND!\n");
    marg.usb_present = 0;
    offline = 1;
  } else {
    marg.usb_present = 1;
    offline = 0;
  }

  pthread_create(&main_loop_t, NULL, &main_loop, &marg);
  InitGraphics(argc, argv);

  MainGraphics();

  pthread_join(main_loop_t, NULL);

  if (marg.usb_present == 1) {
    CloseProxmark();
  }
  return 0;
}
