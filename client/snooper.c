#include <usb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

//#include "translate.h"
#include "prox.h"
#include "proxmark3.h"

#define HANDLE_ERROR if (error_occured) { \
	error_occured = 0;\
	break;\
}

int main()
{
	usb_init();
	setlogfilename("snooper.log");

	return_on_error = 1;

	while(1) {
		while(!(devh=OpenProxmark(0))) { sleep(1); }

		while(1) {
			UsbCommand cmdbuf;
			int i;

			CommandReceived("hi14asnoop");
			HANDLE_ERROR

			ReceiveCommand(&cmdbuf);
			HANDLE_ERROR
			for (i=0; i<5; i++) {
				ReceiveCommandP(&cmdbuf);
			}
			HANDLE_ERROR

			CommandReceived("hi14alist");
			HANDLE_ERROR
		}
	}

	CloseProxmark();
	return 0;
}
