#include <usb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "translate.h"
#include "../winsrc/prox.h"
#include "proxmark3.h"

static DWORD ExpectedAddr;
static BYTE QueuedToSend[256];
static BOOL AllWritten;

static void FlushPrevious(void)
{
	UsbCommand c;
	memset(&c, 0, sizeof(c));

	printf("expected = %08x flush, ", ExpectedAddr);

	int i;
	for(i = 0; i < 240; i += 48) {
		c.cmd = CMD_SETUP_WRITE;
		memcpy(c.d.asBytes, QueuedToSend+i, 48);
		c.ext1 = (i/4);
		SendCommand(&c, TRUE);
	}

	c.cmd = CMD_FINISH_WRITE;
	c.ext1 = (ExpectedAddr-1) & (~255);
	printf("c.ext1 = %08x\r", c.ext1);
	memcpy(c.d.asBytes, QueuedToSend+240, 16);
	SendCommand(&c, TRUE);

	AllWritten = TRUE;
}

static void GotByte(DWORD where, BYTE which)
{
	AllWritten = FALSE;

	if(where != ExpectedAddr) {
		printf("bad: got at %08x, expected at %08x\n", where, ExpectedAddr);
		exit(-1);
	}
	QueuedToSend[where & 255] = which;
	ExpectedAddr++;

	if((where & 255) == 255) {
		// we have completed a full page
		FlushPrevious();
	}
}

static int HexVal(int c)
{
	c = tolower(c);
	if(c >= '0' && c <= '9') {
		return c - '0';
	} else if(c >= 'a' && c <= 'f') {
		return (c - 'a') + 10;
	} else {
		printf("bad hex digit '%c'\n", c);
		exit(-1);
	}
}

static BYTE HexByte(char *s)
{
	return (HexVal(s[0]) << 4) | HexVal(s[1]);
}

static void LoadFlashFromSRecords(char *file, int addr)
{
	ExpectedAddr = addr;

	FILE *f = fopen(file, "r");
	if(!f) {
		printf("couldn't open file\n");
		exit(-1);
	}

	char line[512];
	while(fgets(line, sizeof(line), f)) {
		if(memcmp(line, "S3", 2)==0) {
			char *s = line + 2;
			int len = HexByte(s) - 5;
			s += 2;

			char addrStr[9];
			memcpy(addrStr, s, 8);
			addrStr[8] = '\0';
			DWORD addr;
			sscanf(addrStr, "%x", &addr);
			s += 8;

			int i;
			for(i = 0; i < len; i++) {
				while((addr+i) > ExpectedAddr) {
					GotByte(ExpectedAddr, 0xff);
				}
				GotByte(addr+i, HexByte(s));
				s += 2;
			}
		}
	}

	if(!AllWritten) FlushPrevious();

	fclose(f);
	printf("\ndone.\n");
}

int main(int argc, char **argv) {
	unsigned int addr = 0;
	UsbCommand c;

	if (argc != 3) {
		fprintf(stderr,"Usage: %s {bootrom|os|fpga} image.s19\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!strcmp(argv[1],"bootrom")) {
		addr = 0;
	} else if (!strcmp(argv[1],"os")) {
		addr = 0x10000;
	} else if (!strcmp(argv[1],"fpga")) {
		addr = 0x2000;
	} else {
		fprintf(stderr,"Unknown action '%s'!\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	usb_init();

	fprintf(stderr,"Waiting for Proxmark to appear on USB...\n");
	while(!(devh=OpenProxmark(0))) { sleep(1); }
	fprintf(stderr,"Found...\n");

	fprintf(stderr,"Entering flash-mode...\n");
	bzero(&c, sizeof(c));
	c.cmd = CMD_START_FLASH;
	SendCommand(&c, FALSE);
	CloseProxmark();
	sleep(1);

	fprintf(stderr,"Waiting for Proxmark to reappear on USB...\n");
	fprintf(stderr,"(Press and hold down button NOW if your bootloader requires it)\n");
	while(!(devh=OpenProxmark(0))) { sleep(1); }
	fprintf(stderr,"Found...\n");

	LoadFlashFromSRecords(argv[2], addr);

	bzero(&c, sizeof(c));
	c.cmd = CMD_HARDWARE_RESET;
	SendCommand(&c, FALSE);

	CloseProxmark();

	fprintf(stderr,"Have a nice day!\n");

	return 0;
}
