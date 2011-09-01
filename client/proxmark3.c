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
  char *script_cmds_file;
};

static void *usb_receiver(void *targ)
{
  struct usb_receiver_arg *arg = (struct usb_receiver_arg*)targ;
  UsbCommand cmdbuf;

  while (arg->run) {
    if (ReceiveCommandPoll(&cmdbuf)) {
      UsbCommandReceived(&cmdbuf);
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

int main(int argc, char **argv)
{
  // Make sure to initialize
  struct main_loop_arg marg = {
    .usb_present = 0,
    .script_cmds_file = NULL
  };
  pthread_t main_loop_t;
  usb_init();

  // If the user passed the filename of the 'script' to execute, get it
  if (argc > 1 && argv[1])
  {
    marg.script_cmds_file = argv[1];
  }

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
