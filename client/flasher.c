#include <stdio.h>
#include "proxusb.h"
#include "flash.h"

unsigned int current_command = CMD_UNKNOWN;

extern struct partition partitions[];

static void usage(char **argv)
{
  fprintf(stderr, "Usage:   %s areas image [image [image]]\n", argv[0]);
  fprintf(stderr, "         areas is a comma-separated list of areas to flash, with no spaces\n");
  fprintf(stderr, "               Known areas are:");

  for (int i = 0; partitions[i].name != NULL; ++i) {
    fprintf(stderr, " %s", partitions[i].name);
  }

  fprintf(stderr, "\n");
  fprintf(stderr, "         image is the path to the corresponding image\n\n");
  fprintf(stderr, "Example: %s os,fpga path/to/osimage.elf path/to/fpgaimage.elf\n", argv[0]);
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    usage(argv);
    exit(-1);
  }

  /* Count area arguments */
  int areas = 0, offset=-1, length=0;
  while (find_next_area(argv[1], &offset, &length)) areas++;

  if (areas != argc - 2) {
    usage(argv);
    exit(-1);
  }

  usb_init();

  fprintf(stderr,"Waiting for Proxmark to appear on USB... ");
  while (!OpenProxmark(0)) { sleep(1); }
  fprintf(stderr,"Found.\n");

  do_flash(argv);

  UsbCommand c = {CMD_HARDWARE_RESET};
  SendCommand(&c);

  CloseProxmark();

  fprintf(stderr,"Have a nice day!\n");

  return 0;
}
