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
#include "sleep.h"
#include "proxmark3.h"
#include "flash.h"
#include "uart.h"
#include "../include/usb_cmd.h"

#ifdef _WIN32
# define unlink(x)
#endif

static serial_port sp;
static char* serial_port_name;

void cmd_debug(UsbCommand* UC) {
  //  Debug
  printf("UsbCommand length[len=%zd]\n",sizeof(UsbCommand));
  printf("  cmd[len=%zd]: %016"llx"\n",sizeof(UC->cmd),UC->cmd);
  printf(" arg0[len=%zd]: %016"llx"\n",sizeof(UC->arg[0]),UC->arg[0]);
  printf(" arg1[len=%zd]: %016"llx"\n",sizeof(UC->arg[1]),UC->arg[1]);
  printf(" arg2[len=%zd]: %016"llx"\n",sizeof(UC->arg[2]),UC->arg[2]);
  printf(" data[len=%zd]: ",sizeof(UC->d.asBytes));
  for (size_t i=0; i<16; i++) {
    printf("%02x",UC->d.asBytes[i]);
  }
  printf("...\n");
}

void SendCommand(UsbCommand* txcmd) {
//  printf("send: ");
//  cmd_debug(txcmd);
  if (!uart_send(sp,(byte_t*)txcmd,sizeof(UsbCommand))) {
    printf("Sending bytes to proxmark failed\n");
    exit(1);
  }
}

void ReceiveCommand(UsbCommand* rxcmd) {
  byte_t* prxcmd = (byte_t*)rxcmd;
  byte_t* prx = prxcmd;
  size_t rxlen;
  while (true) {
    rxlen = sizeof(UsbCommand) - (prx-prxcmd);
    if (uart_receive(sp,prx,&rxlen)) {
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

int OpenProxmark(size_t i) {
  sp = uart_open(serial_port_name);
  if (sp == INVALID_SERIAL_PORT || sp == CLAIMED_SERIAL_PORT) {
    //poll once a second
    return 0;
  }
  return 1;
}

static void usage(char *argv0)
{
	fprintf(stderr, "Usage:   %s <port> [-b] image.elf [image.elf...]\n\n", argv0);
	fprintf(stderr, "\t-b\tEnable flashing of bootloader area (DANGEROUS)\n\n");
	//Is the example below really true? /Martin
	fprintf(stderr, "Example:\n\n\t %s path/to/osimage.elf path/to/fpgaimage.elf\n", argv0);
	fprintf(stderr, "\nExample (Linux):\n\n\t %s  /dev/ttyACM0 armsrc/obj/fullimage.elf\n", argv0);
	fprintf(stderr, "\nNote (Linux): if the flasher gets stuck in 'Waiting for Proxmark to reappear on <DEVICE>',\n");
	fprintf(stderr, "              you need to blacklist proxmark for modem-manager - see wiki for more details:\n");
	fprintf(stderr, "              http://code.google.com/p/proxmark3/wiki/Linux\n\n");
}

#define MAX_FILES 4

int main(int argc, char **argv)
{
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
  
  fprintf(stderr,"Waiting for Proxmark to appear on %s",serial_port_name);
  do {
    sleep(1);
    fprintf(stderr, ".");
  } while (!OpenProxmark(0));
  fprintf(stderr," Found.\n");

	res = flash_start_flashing(can_write_bl,serial_port_name);
	if (res < 0)
		return -1;

	fprintf(stderr, "\nFlashing...\n");

	for (int i = 0; i < num_files; i++) {
		res = flash_write(&files[i]);
		if (res < 0)
			return -1;
		flash_free(&files[i]);
		fprintf(stderr, "\n");
	}

	fprintf(stderr, "Resetting hardware...\n");

	res = flash_stop_flashing();
	if (res < 0)
		return -1;

	CloseProxmark();

	fprintf(stderr, "All done.\n\n");
	fprintf(stderr, "Have a nice day!\n");

	return 0;
}
