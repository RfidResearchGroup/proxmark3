//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Flasher frontend tool
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "util_posix.h"
#include "proxmark3.h"
#include "flash.h"
#include "uart.h"
#include "usb_cmd.h"

#define MAX_FILES 4

#ifdef _WIN32
# define unlink(x)
#else
# include <unistd.h>
#endif

static serial_port sp;
static char* serial_port_name;

void cmd_debug(UsbCommand* c) {
	//  Debug
	printf("UsbCommand length[len=%zd]\n", sizeof(UsbCommand));
	printf("  cmd[len=%zd]: %016" PRIx64"\n", sizeof(c->cmd), c->cmd);
	printf(" arg0[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[0]), c->arg[0]);
	printf(" arg1[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[1]), c->arg[1]);
	printf(" arg2[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[2]), c->arg[2]);
	printf(" data[len=%zd]: ", sizeof(c->d.asBytes));

	for (size_t i=0; i<16; i++)
		printf("%02x", c->d.asBytes[i]);

	printf("...\n");
}

void SendCommand(UsbCommand* txcmd) {
	//  printf("send: ");
	//  cmd_debug(txcmd);
	if (!uart_send(sp, (byte_t*)txcmd, sizeof(UsbCommand))) {
		printf("Sending bytes to proxmark failed\n");
		exit(1);
	}
}

void ReceiveCommand(UsbCommand* rxcmd) {
	byte_t* prxcmd = (byte_t*)rxcmd;
	byte_t* prx = prxcmd;
	size_t rxlen;
	while (true) {
		if (uart_receive(sp, prx, sizeof(UsbCommand) - (prx-prxcmd), &rxlen)) {
			prx += rxlen;
			if ((prx-prxcmd) >= sizeof(UsbCommand)) {
				return;
			}
		}
	}
}

void CloseProxmark() {
	// Clean up the port
	uart_close(sp);
	// Fix for linux, it seems that it is extremely slow to release the serial port file descriptor /dev/*
	unlink(serial_port_name);
}

int OpenProxmark() {
	sp = uart_open(serial_port_name);

	//poll once a second
	if (sp == INVALID_SERIAL_PORT) {
		return 0;
	} else if (sp == CLAIMED_SERIAL_PORT) {
		fprintf(stderr, "ERROR: serial port is claimed by another process\n");
		return 0;
	} 	
	return 1;
}

static void usage(char *argv0) {
	fprintf(stdout, "Usage:   %s <port> [-b] image.elf [image.elf...]\n\n", argv0);
	fprintf(stdout, "\t-b\tEnable flashing of bootloader area (DANGEROUS)\n\n");
	fprintf(stdout, "\nExample (Linux):\n\n\t %s  /dev/ttyACM0 armsrc/obj/fullimage.elf\n", argv0);
	fprintf(stdout, "\nExample (OSX   :\n\n\t %s  /dev/cu.usbmodem888 armsrc/obj/fullimage.elf\n", argv0);
	fprintf(stdout, "\nExample (WIN)  :\n\n\t %s  com3 armsrc/obj/fullimage.elf\n\n", argv0);
#ifdef __linux__	
	fprintf(stdout, "\nNote (Linux): if the flasher gets stuck in 'Waiting for Proxmark to reappear on <DEVICE>',\n");
	fprintf(stdout, "              you need to blacklist proxmark for modem-manager - see wiki for more details:\n\n");
	fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/Gentoo Linux\n\n");
	fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/Ubuntu Linux\n\n");
	fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/OSX\n\n");
#endif	
}

int main(int argc, char **argv) {
	int can_write_bl = 0;
	int num_files = 0;
	int res;
	flash_file_t files[MAX_FILES];

	memset(files, 0, sizeof(files));

	if (argc < 3) {
		usage(argv[0]);
		return -1;
	}

	for (int i = 2; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp(argv[i], "-b")) {
				can_write_bl = 1;
			} else {
				usage(argv[0]);
				return -1;
			}
		} else {
			res = flash_load(&files[num_files], argv[i], can_write_bl);
			if (res < 0) {
				fprintf(stderr, "Error while loading %s\n", argv[i]);
				return -1;
			}
			fprintf(stderr, "\n");
			num_files++;
		}
	}

	serial_port_name = argv[1];
  
	fprintf(stdout, "Waiting for Proxmark to appear on %s", serial_port_name);
	do {
		msleep(500);
		fprintf(stderr, "."); fflush(stdout);
	} while (!OpenProxmark());

	fprintf(stdout, " Found.\n");

	res = flash_start_flashing(can_write_bl, serial_port_name);
	if (res < 0)
		return -1;

	fprintf(stdout, "\nFlashing...\n");

	for (int i = 0; i < num_files; i++) {
		res = flash_write(&files[i]);
		if (res < 0)
			return -1;
		flash_free(&files[i]);
		fprintf(stdout, "\n");
	}

	fprintf(stdout, "Resetting hardware...\n");

	res = flash_stop_flashing();
	if (res < 0)
		return -1;

	CloseProxmark();

	fprintf(stdout, "All done.\n\n");
	fprintf(stdout, "Have a nice day!\n");
	return 0;
}
