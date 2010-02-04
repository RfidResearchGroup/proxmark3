#ifndef CMDMAIN_H__
#define CMDMAIN_H__

#include "usb_cmd.h"

void UsbCommandReceived(UsbCommand *UC);
void CommandReceived(char *Cmd);
void WaitForResponse(uint32_t response_type);

#endif
