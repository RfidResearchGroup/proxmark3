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

#include "flash.h"
#include "usb_cmd.h"
#include "ui.h"

#define OUR_VID 0x9ac4
#define OUR_PID 0x4b8f
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

int offline = 0;
HANDLE UsbHandle;
extern unsigned int current_command;
extern struct partition partitions[];

static void ShowError(void)
{
	char buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0,
		buf, sizeof(buf), NULL);
	printf("ERROR: %s", buf);
}

BOOL UsbConnect(void)
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

static void usage(char **argv)
{
	int i;
		printf("Usage: %s gui\n", argv[0]);
		printf("       %s offline\n", argv[0]);
		printf("       %s areas file.elf\n", argv[0]);
		printf("               Known areas are:");
		for(i=0; partitions[i].name != NULL; i++) {
			fprintf(stderr, " %s", partitions[i].name);
		}

		printf("\n");
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

	do_flash(argv);
	return 0;
}
