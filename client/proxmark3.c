#include <usb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <pthread.h>

#include "prox.h"
#include "proxmark3.h"
#include "proxgui.h"

struct usb_receiver_arg {
	int run;
};

struct main_loop_arg {
	int usb_present;
};

static void *usb_receiver(void *targ) {
	struct usb_receiver_arg *arg = (struct usb_receiver_arg*)targ;
	UsbCommand cmdbuf;

	while(arg->run) {
		if (ReceiveCommandPoll(&cmdbuf)) {
			int i;

			for (i=0; i<strlen(PROXPROMPT); i++)
				putchar(0x08);

			UsbCommandReceived(&cmdbuf);
			printf(PROXPROMPT);
			fflush(NULL);
		}
	}

	pthread_exit(NULL);
}

static void *main_loop(void *targ)
{
	struct main_loop_arg *arg = (struct main_loop_arg*)targ;
	char *cmd = NULL;

	while(1) {
		struct usb_receiver_arg rarg;
		pthread_t reader_thread;

		rarg.run=1;
		if (arg->usb_present == 1) {
			pthread_create(&reader_thread, NULL, &usb_receiver, &rarg);
		}
		cmd = readline(PROXPROMPT);
		rarg.run=0;
		if (arg->usb_present == 1) {
			pthread_join(reader_thread, NULL);
		}

		if (cmd) {
			if (cmd[0] != 0x00) {
				CommandReceived(cmd);
				add_history(cmd);
			}
			free(cmd);
		} else {
			printf("\n");
			break;
		}
	}

	ExitGraphics();
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	struct main_loop_arg marg;
	pthread_t main_loop_t;
	usb_init();

	if (!(devh = OpenProxmark(1))) {
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
