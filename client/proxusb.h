#ifndef PROXUSB_H__
#define PROXUSB_H__

#include <stdint.h>
#include <stdbool.h>
#include <usb.h>
#include "usb_cmd.h"

extern unsigned char return_on_error;
extern unsigned char error_occured;

void SendCommand(UsbCommand *c);
bool ReceiveCommandPoll(UsbCommand *c);
void ReceiveCommand(UsbCommand *c);
struct usb_dev_handle* FindProxmark(int verbose, unsigned int *iface);
struct usb_dev_handle* OpenProxmark(int verbose);
void CloseProxmark(void);

#endif
