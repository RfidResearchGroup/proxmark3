#include <usb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "translate.h"
#include "prox.h"
#include "proxmark3.h"

static DWORD ExpectedAddr;
static BYTE QueuedToSend[256];
static BOOL AllWritten;
#define PHYSICAL_FLASH_START 0x100000

struct partition {
	int start;
	int end;
	int precious;
	const char *name;
};
struct partition partitions[] = {
		{0x100000, 0x102000, 1, "bootrom"},
		{0x102000, 0x110000, 0, "fpga"},
		{0x110000, 0x140000, 0, "os"},
};

/* If translate is set, subtract PHYSICAL_FLASH_START to translate for old
 * bootroms.
 */
static void FlushPrevious(int translate)
{
	UsbCommand c;
	memset(&c, 0, sizeof(c));

	printf("expected = %08x flush, ", ExpectedAddr);

	int i;
	for(i = 0; i < 240; i += 48) {
		c.cmd = CMD_SETUP_WRITE;
		memcpy(c.d.asBytes, QueuedToSend+i, 48);
		c.arg[0] = (i/4);
		SendCommand(&c, TRUE);
	}

	c.cmd = CMD_FINISH_WRITE;
	c.arg[0] = (ExpectedAddr-1) & (~255);
	if(translate) {
		c.arg[0] -= PHYSICAL_FLASH_START;
	}
	printf("c.arg[0] = %08x\r", c.arg[0]);
	memcpy(c.d.asBytes, QueuedToSend+240, 16);
	SendCommand(&c, TRUE);

	AllWritten = TRUE;
}

/* Where must be between start_addr (inclusive) and end_addr (exclusive).
 */
static void GotByte(DWORD where, BYTE which, int start_addr, int end_addr, int translate)
{
	AllWritten = FALSE;
	
	if(where < start_addr || where >= end_addr) {
		printf("bad: got byte at %08x, outside of range %08x-%08x\n", where, start_addr, end_addr);
		exit(-1);
	}

	if(where != ExpectedAddr) {
		printf("bad: got at %08x, expected at %08x\n", where, ExpectedAddr);
		exit(-1);
	}
	QueuedToSend[where & 255] = which;
	ExpectedAddr++;

	if((where & 255) == 255) {
		// we have completed a full page
		FlushPrevious(translate);
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

static void LoadFlashFromSRecords(const char *file, int start_addr, int end_addr, int translate)
{
	ExpectedAddr = start_addr;
	
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
			
			/* Accept files that are located at PHYSICAL_FLASH_START, and files that are located at 0 */
			if(addr < PHYSICAL_FLASH_START) 
				addr += PHYSICAL_FLASH_START;

			int i;
			for(i = 0; i < len; i++) {
				while((addr+i) > ExpectedAddr) {
					GotByte(ExpectedAddr, 0xff, start_addr, end_addr, translate);
				}
				GotByte(addr+i, HexByte(s), start_addr, end_addr, translate);
				s += 2;
			}
		}
	}

	if(!AllWritten) FlushPrevious(translate);

	fclose(f);
	printf("\ndone.\n");
}

static int PrepareFlash(struct partition *p, const char *filename, unsigned int state)
{
	int translate = 0;
	if(state & DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH) {
		UsbCommand c;
		c.cmd = CMD_START_FLASH;
		c.arg[0] = p->start;
		c.arg[1] = p->end;
		
		/* Only send magic when flashing bootrom */
		if(p->precious) {
			c.arg[2] = START_FLASH_MAGIC;
		} else {
			c.arg[2] = 0;
		}
		SendCommand(&c, TRUE);
		translate = 0;
	} else {
		fprintf(stderr, "Warning: Your bootloader does not understand the new START_FLASH command\n");
		fprintf(stderr, "         It is recommended that you update your bootloader\n\n");
		translate = 1;
	}
	
	LoadFlashFromSRecords(filename, p->start, p->end, translate);
	return 1;
}

static unsigned int GetProxmarkState(void)
{
	unsigned int state = 0;
	
	UsbCommand c;
	c.cmd = CMD_DEVICE_INFO;
	SendCommand(&c, FALSE);
	
	UsbCommand resp;
	ReceiveCommand(&resp);
	/* Three cases: 
	 * 1. The old bootrom code will ignore CMD_DEVICE_INFO, but respond with an ACK
	 * 2. The old os code will respond with CMD_DEBUG_PRINT_STRING and "unknown command"
	 * 3. The new bootrom and os codes will respond with CMD_DEVICE_INFO and flags
	 */
	
	switch(resp.cmd) {
	case CMD_ACK:
		state = DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM;
		break;
	case CMD_DEBUG_PRINT_STRING:
		state = DEVICE_INFO_FLAG_CURRENT_MODE_OS;
		break;
	case CMD_DEVICE_INFO:
		state = resp.arg[0];
		break;
	default:
		fprintf(stderr, "Couldn't get proxmark state, bad response type: 0x%04X\n", resp.cmd);
		exit(-1);
		break;
	}
	
#if 0
	if(state & DEVICE_INFO_FLAG_BOOTROM_PRESENT) printf("New bootrom present\n");
	if(state & DEVICE_INFO_FLAG_OSIMAGE_PRESENT) printf("New osimage present\n");
	if(state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) printf("Currently in bootrom\n");
	if(state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) printf("Currently in OS\n");
#endif
	
	return state;
}

static unsigned int EnterFlashState(void)
{
	unsigned int state = GetProxmarkState();
	
	if(state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) {
		/* Already in flash state, we're done. */
		return state;
	}
	
	if(state & DEVICE_INFO_FLAG_CURRENT_MODE_OS) {
		fprintf(stderr,"Entering flash-mode...\n");
		UsbCommand c;
		bzero(&c, sizeof(c));
		
		if( (state & DEVICE_INFO_FLAG_BOOTROM_PRESENT) && (state & DEVICE_INFO_FLAG_OSIMAGE_PRESENT) ) {
			/* New style handover: Send CMD_START_FLASH, which will reset the board and
			 * enter the bootrom on the next boot.
			 */
			c.cmd = CMD_START_FLASH;
			SendCommand(&c, FALSE);
			fprintf(stderr,"(You don't have to do anything. Press and release the button only if you want to abort)\n");
			fprintf(stderr,"Waiting for Proxmark to reappear on USB... ");
		} else {
			/* Old style handover: Ask the user to press the button, then reset the board */
			c.cmd = CMD_HARDWARE_RESET;
			SendCommand(&c, FALSE);
			fprintf(stderr,"(Press and hold down button NOW if your bootloader requires it)\n");
			fprintf(stderr,"Waiting for Proxmark to reappear on USB... ");
		}
		
		CloseProxmark();
		sleep(1);

		while(!(devh=OpenProxmark(0))) { sleep(1); }
		fprintf(stderr,"Found.\n");

		return GetProxmarkState();
	}
	
	return 0;
}

static void usage(char **argv)
{
	int i;
	fprintf(stderr, "Usage:   %s areas image [image [image]]\n", argv[0]);
	fprintf(stderr, "         areas is a comma-separated list of areas to flash, with no spaces\n");
	fprintf(stderr, "               Known areas are:");
	for(i=0; i<(sizeof(partitions)/sizeof(partitions[0])); i++) {
		fprintf(stderr, " %s", partitions[i].name);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "         image is the path to the corresponding image\n\n");
	fprintf(stderr, "Example: %s os,fpga path/to/osimage.s19 path/to/fpgaimage.s19\n", argv[0]);
}

/* On first call, have *offset = -1, *length = 0; */
static int find_next_area(const char *str, int *offset, int *length)
{
	if(*str == '\0') return 0;
	if((*offset >= 0) && str[*offset + *length] == '\0') return 0;
	*offset += 1 + *length;
	
	char *next_comma = strchr(str + *offset, ',');
	if(next_comma == NULL) {
		*length = strlen(str) - *offset;
	} else {
		*length = next_comma-(str+*offset);
	}
	return 1;
}

int main(int argc, char **argv) {
	if(argc < 2) {
		usage(argv);
		exit(-1);
	}
	
	/* Count area arguments */
	int areas = 0, offset=-1, length=0;
	while(find_next_area(argv[1], &offset, &length)) areas++;
	
	if(areas != argc - 2) {
		usage(argv);
		exit(-1);
	}
	
	usb_init();

	fprintf(stderr,"Waiting for Proxmark to appear on USB... ");
	while(!(devh=OpenProxmark(0))) { sleep(1); }
	fprintf(stderr,"Found.\n");
	
	unsigned int state = EnterFlashState();
	
	if( !(state & DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM) ) {
		fprintf(stderr, "Proxmark would not enter flash state, abort\n");
		exit(-1);
	}
	
	offset=-1; length=0;
	int current_area = 0;
	while(find_next_area(argv[1], &offset, &length)) {
		int i;
		struct partition *p = NULL;
		for(i=0; i<sizeof(partitions)/sizeof(partitions[0]); i++) {
			if(strncmp(partitions[i].name, argv[1] + offset, length) == 0) {
				/* Check if the name matches the bootrom partition, and if so, require "bootrom" to
				 * be written in full. The other names may be abbreviated.
				 */
				if(!partitions[i].precious || (strlen(partitions[i].name) == length)) {
					p = &partitions[i];
				}
				break;
			}
		}
		
		if(p == NULL) {
			fprintf(stderr, "Warning: area name '");
			fwrite(argv[1]+offset, length, 1, stderr);
			fprintf(stderr, "' unknown, ignored\n");
		} else {
			fprintf(stderr, "Flashing %s from %s\n", p->name, argv[2+current_area]);
			PrepareFlash(p, argv[2+current_area], state);
		}
		current_area++;
	}
	
	UsbCommand c;
	bzero(&c, sizeof(c));
	c.cmd = CMD_HARDWARE_RESET;
	SendCommand(&c, FALSE);

	CloseProxmark();

	fprintf(stderr,"Have a nice day!\n");

	return 0;
}
