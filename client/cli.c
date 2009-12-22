#include <usb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

#include "translate.h"
#include "prox.h"
#include "proxmark3.h"

#define HANDLE_ERROR if (error_occured) { \
	error_occured = 0;\
	break;\
}

int main(int argc, char **argv)
{
	if(argc != 3 && argc != 4)
		{
		printf("\n\tusage: cli <command 1> <command 2> [logfile (default cli.log)]\n");
		printf("\n");
		printf("\texample: cli hi14asnoop hi14alist h14a.log\n");
		printf("\n");
		return -1;
		}

	usb_init();
	if (argc == 4)
		setlogfilename(argv[3]);
	else
		setlogfilename("cli.log");

	return_on_error = 1;

	while(1) {
		while(!(devh=OpenProxmark(0))) { sleep(1); }

		while(1) {
			UsbCommand cmdbuf;
			int i;

			CommandReceived(argv[1]);
			HANDLE_ERROR

			ReceiveCommand(&cmdbuf);
			HANDLE_ERROR
			for (i=0; i<5; i++) {
				ReceiveCommandP(&cmdbuf);
			}
			HANDLE_ERROR

			CommandReceived(argv[2]);
			HANDLE_ERROR
		}
	}

	CloseProxmark();
	return 0;
}
