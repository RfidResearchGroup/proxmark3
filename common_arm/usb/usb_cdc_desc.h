#ifndef USB_CDC_DESC_H
#define USB_CDC_DESC_H

#include <stdint.h>

// Please define USB-CDC configurations related to specific platforms here, such as endpoint size.

/**
 * Power mode: Bit4-0 reserved, D7: bus power supply, D6: self power supply, D5: remote wake-up
 */
#define USB_CDC_DESC_CFG_POWER_MODE     (0x01 << 7)

/**
  * usb cdc use endpoint define
  */
#ifdef PM5

#define USB_CDC_DESC_INT_EPT            0x82
#define USB_CDC_DESC_BULK_IN_EPT        0x81
#define USB_CDC_DESC_BULK_OUT_EPT       0x01

#else

#define USB_CDC_DESC_INT_EPT            0x83
#define USB_CDC_DESC_BULK_IN_EPT        0x82
#define USB_CDC_DESC_BULK_OUT_EPT       0x01

#endif

/**
 * endpoint buffer size
 */
#ifdef PM5

#define USB_CDC_DESC_MAX_EP0_SIZE       64
#define USB_CDC_DESC_IN_PACKET_SIZE     0x40
#define USB_CDC_DESC_OUT_PACKET_SIZE    0x40

#else

#define USB_CDC_DESC_MAX_EP0_SIZE       8
#define USB_CDC_DESC_IN_PACKET_SIZE     0x40
#define USB_CDC_DESC_OUT_PACKET_SIZE    0x40

#endif


// Fixed value. To support WCID, the device needs to respond to a special string descriptor request and return a special character descriptor.
// The Windows system will initiate a manufacturer customized request to obtain the WCID of the device based on the parameters in this character descriptor.
// After obtaining the WCID, match and install the driver based on the WCID./
//   NOTE: There are no special specifications, so the relevant definitions cannot be found on the Internet.
// https://www.usbzh.com/article/detail-625.html
#define  USB_CDC_DESC_MS_VENDOR_CODE    0x1C

// exported all desc.
extern const char devDescriptor[18];
extern const char cfgDescriptor[67];
extern const char bosDescriptor[12];
extern const char StrLanguageCodes[4];
extern const char StrManufacturer[26];
extern const char StrProduct[20];

// If the device has FLASH, the USB serial number is dynamically generated(NOT const).
#ifndef WITH_FLASH
extern const char StrSerialNumber[14];
#else
extern char StrSerialNumber[50];
#endif

// WCID, for DRIVER auto install on windows platform.
//  DOCS: https://www.usbzh.com/article/detail-625.html
extern const char StrMS_OSDescriptor[18];

#endif
