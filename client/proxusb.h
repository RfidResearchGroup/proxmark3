#ifndef PROXUSB_H__
#define PROXUSB_H__

#ifdef _MSC_VER
typedef DWORD uint32_t;
typedef BYTE uint8_t;
typedef WORD uint16_t;
#define bool BOOL
#else
#include <stdint.h>
#include <stdbool.h>
#endif
#include <usb.h>
#include "usb_cmd.h"

extern unsigned char return_on_error;
extern unsigned char error_occured;

void SendCommand(UsbCommand *c);
bool ReceiveCommandPoll(UsbCommand *c);
void ReceiveCommand(UsbCommand *c);
usb_dev_handle* FindProxmark(int verbose, unsigned int *iface);
usb_dev_handle* OpenProxmark(int verbose);
usb_dev_handle* OpenProxmark(int verbose);
void CloseProxmark(void);

#endif
