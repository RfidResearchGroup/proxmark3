#ifndef _USB_HID_H_
#define _USB_HID_H_

#include <common.h>
#include <proxmark3.h>

//--------------------------------
// USB defines

#define USB_D_PLUS_PULLUP_ON() { \
HIGH(GPIO_USB_PU); \
AT91C_BASE_PIOA->PIO_OER = GPIO_USB_PU; \
}
#define USB_D_PLUS_PULLUP_OFF() AT91C_BASE_PIOA->PIO_ODR = GPIO_USB_PU

//--------------------------------
// USB declarations

void UsbSendPacket(uint8_t *packet, int len);
int UsbConnected();
int UsbPoll(int blinkLeds);
void UsbStart(void);

// This function is provided by the apps/bootrom, and called from UsbPoll
// if data are available.
void UsbPacketReceived(uint8_t *packet, int len);

#endif // _USB_HID_H_

