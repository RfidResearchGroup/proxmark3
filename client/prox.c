#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
//extern "C" {
#include "include/hidusage.h"
#include "include/hidpi.h"
#include "include/hidsdi.h"
//}

#include "prox.h"

#define OUR_VID 0x9ac4
#define OUR_PID 0x4b8f
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

int offline = 0;
HANDLE UsbHandle;
extern unsigned int current_command;

static void ShowError(void)
{
	char buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0,
		buf, sizeof(buf), NULL);
	printf("ERROR: %s", buf);
}

static BOOL UsbConnect(void)
{
	typedef void (__stdcall *GetGuidProc)(GUID *);
	typedef BOOLEAN (__stdcall *GetAttrProc)(HANDLE, HIDD_ATTRIBUTES *);
	typedef BOOLEAN (__stdcall *GetPreparsedProc)(HANDLE,
										PHIDP_PREPARSED_DATA *);
	typedef NTSTATUS (__stdcall *GetCapsProc)(PHIDP_PREPARSED_DATA, PHIDP_CAPS);
	GetGuidProc			getGuid;
	GetAttrProc			getAttr;
	GetPreparsedProc	getPreparsed;
	GetCapsProc			getCaps;

	HMODULE h		= LoadLibrary("hid.dll");
	getGuid			= (GetGuidProc)GetProcAddress(h, "HidD_GetHidGuid");
	getAttr			= (GetAttrProc)GetProcAddress(h, "HidD_GetAttributes");
	getPreparsed	= (GetPreparsedProc)GetProcAddress(h, "HidD_GetPreparsedData");
	getCaps			= (GetCapsProc)GetProcAddress(h, "HidP_GetCaps");

	GUID hidGuid;
	getGuid(&hidGuid);

	HDEVINFO devInfo;
	devInfo = SetupDiGetClassDevs(&hidGuid, NULL, NULL,
		DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);

	SP_DEVICE_INTERFACE_DATA devInfoData;
	devInfoData.cbSize = sizeof(devInfoData);

	int i;
	for(i = 0;; i++) {
		if(!SetupDiEnumDeviceInterfaces(devInfo, 0, &hidGuid, i, &devInfoData))
		{
			if(GetLastError() != ERROR_NO_MORE_ITEMS) {
//				printf("SetupDiEnumDeviceInterfaces failed\n");
			}
//			printf("done list\n");
			SetupDiDestroyDeviceInfoList(devInfo);
			return FALSE;
		}

//		printf("item %d:\n", i);

		DWORD sizeReqd = 0;
		if(!SetupDiGetDeviceInterfaceDetail(devInfo, &devInfoData,
			NULL, 0, &sizeReqd, NULL))
		{
			if(GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
//				printf("SetupDiGetDeviceInterfaceDetail (0) failed\n");
				continue;
			}
		}

		SP_DEVICE_INTERFACE_DETAIL_DATA *devInfoDetailData =
			(SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(sizeReqd);
		devInfoDetailData->cbSize = sizeof(*devInfoDetailData);

		if(!SetupDiGetDeviceInterfaceDetail(devInfo, &devInfoData,
			devInfoDetailData, 87, NULL, NULL))
		{
//			printf("SetupDiGetDeviceInterfaceDetail (1) failed\n");
			continue;
		}

		char *path = devInfoDetailData->DevicePath;

		UsbHandle = CreateFile(path, /*GENERIC_READ |*/ GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);

		if(UsbHandle == INVALID_HANDLE_VALUE) {
			ShowError();
//			printf("CreateFile failed: for '%s'\n", path);
			continue;
		}

		HIDD_ATTRIBUTES attr;
		attr.Size = sizeof(attr);
		if(!getAttr(UsbHandle, &attr)) {
			ShowError();
//			printf("HidD_GetAttributes failed\n");
			continue;
		}

//		printf("VID: %04x PID %04x\n", attr.VendorID, attr.ProductID);

		if(attr.VendorID != OUR_VID || attr.ProductID != OUR_PID) {
			CloseHandle(UsbHandle);
//			printf("	nope, not us\n");
			continue;
		}

//		printf ("got it!\n");
		CloseHandle(UsbHandle);

		UsbHandle = CreateFile(path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);

		if(UsbHandle == INVALID_HANDLE_VALUE) {
			ShowError();
//			printf("Error, couldn't open our own handle as desired.\n");
			return FALSE;
		}

		PHIDP_PREPARSED_DATA pp;
		getPreparsed(UsbHandle, &pp);
		HIDP_CAPS caps;

		if(getCaps(pp, &caps) != HIDP_STATUS_SUCCESS) {
//			printf("getcaps failed\n");
			return FALSE;
		}

//		printf("input/out report %d/%d\n", caps.InputReportByteLength,
//			caps.OutputReportByteLength);


		return TRUE;
	}
	return FALSE;
}

bool ReceiveCommandPoll(UsbCommand *c)
{
	static BOOL ReadInProgress = FALSE;
	static OVERLAPPED Ov;
	static BYTE Buf[65];
	static DWORD HaveRead;

	if(!ReadInProgress) {
		memset(&Ov, 0, sizeof(Ov));
		ReadFile(UsbHandle, Buf, 65, &HaveRead, &Ov);
		if(GetLastError() != ERROR_IO_PENDING) {
			ShowError();
			exit(-1);
		}
		ReadInProgress = TRUE;
	}

	if(HasOverlappedIoCompleted(&Ov)) {
		ReadInProgress = FALSE;

		if(!GetOverlappedResult(UsbHandle, &Ov, &HaveRead, FALSE)) {
			ShowError();
			exit(-1);
		}

		memcpy(c, Buf+1, 64);

		return TRUE;
	} else {
		return FALSE;
	}
}

void ReceiveCommand(UsbCommand *c)
{
	while(!ReceiveCommandPoll(c)) {
		Sleep(0);
	}
}

void SendCommand(UsbCommand *c)
{
	BYTE buf[65];
	buf[0] = 0;
	memcpy(buf+1, c, 64);

	DWORD written;
	OVERLAPPED ov;

	memset(&ov, 0, sizeof(ov));
	WriteFile(UsbHandle, buf, 65, &written, &ov);
	if(GetLastError() != ERROR_IO_PENDING) {
		ShowError();
		exit(-1);
	}

	while(!HasOverlappedIoCompleted(&ov)) {
		Sleep(0);
	}

	if(!GetOverlappedResult(UsbHandle, &ov, &written, FALSE)) {
		ShowError();
		exit(-1);
	}
	current_command = c->cmd;
}

void WaitForAck(void) {
	UsbCommand ack;
	ReceiveCommand(&ack);
	if(ack.cmd != CMD_ACK) {
		printf("bad ACK\n");
		exit(-1);
	}
}

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

//	printf("expected = %08x flush, ", ExpectedAddr);

	int i;
	for(i = 0; i < 240; i += 48) {
		c.cmd = CMD_SETUP_WRITE;
		memcpy(c.d.asBytes, QueuedToSend+i, 48);
		c.arg[0] = (i/4);
		SendCommand(&c);
		WaitForAck();
	}

	c.cmd = CMD_FINISH_WRITE;
	c.arg[0] = (ExpectedAddr-1) & (~255);
	if(translate) {
		c.arg[0] -= PHYSICAL_FLASH_START;
	}
	printf("Flashing address: %08x\r", c.arg[0]);
	memcpy(c.d.asBytes, QueuedToSend+240, 16);
	SendCommand(&c);
	WaitForAck();
	
	AllWritten = TRUE;
}

/* Where must be between start_addr (inclusive) and end_addr (exclusive).
 */
static void GotByte(int where, BYTE which, int start_addr, int end_addr, int translate)
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
		SendCommand(&c);
		WaitForAck();
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
	SendCommand(&c);

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
			SendCommand(&c);
			fprintf(stderr,"(You don't have to do anything. Press and release the button only if you want to abort)\n");
			fprintf(stderr,"Waiting for Proxmark to reappear on USB... ");
		} else {
			/* Old style handover: Ask the user to press the button, then reset the board */
			c.cmd = CMD_HARDWARE_RESET;
			SendCommand(&c);
			fprintf(stderr,"(Press and hold down button NOW if your bootloader requires it)\n");
			fprintf(stderr,"Waiting for Proxmark to reappear on USB... ");
		}


		Sleep(1000);

		while(!UsbConnect()) { Sleep(1000); }
		fprintf(stderr,"Found.\n");

		return GetProxmarkState();
	}

	return 0;
}

static void usage(char **argv)
{
	int i;
		printf("Usage: %s gui\n", argv[0]);
		printf("       %s offline\n", argv[0]);
		printf("       %s areas file.s19\n", argv[0]);
		printf("               Known areas are:");
		for(i=0; i<(sizeof(partitions)/sizeof(partitions[0])); i++) {
			fprintf(stderr, " %s", partitions[i].name);
		}

		printf("\n");
}

/* On first call, have *offset = -1, *length = 0; */
static int find_next_area(char *str, int *offset, int *length)
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

int main(int argc, char **argv)
{
	int i = 0;

	if(argc < 2) {
		usage(argv);
		exit(-1);
	}

	// Only do this if NOT in offline mode
	if (strcmp(argv[1], "offline"))
	{
		for(;;) {
			if(UsbConnect()) {
				break;
			}
			if(i == 0) {
				printf("...no device connected, polling for it now\n");
			}
			if(i > 50000) {
				printf("Could not connect to USB device; exiting.\n");
				return -1;
			}
			i++;
			Sleep(5);
		}
	}

	if(strcmp(argv[1], "gui")==0) {
		ShowGui();
	} else if(strcmp(argv[1], "offline")==0) {
		offline = 1;
		ShowGui();
	}

	/* Count area arguments */
	int areas = 0, offset=-1, length=0;
	while(find_next_area(argv[1], &offset, &length)) areas++;

	if(areas != argc - 2) {
		usage(argv);
		exit(-1);
	}

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

	return 0;
}
