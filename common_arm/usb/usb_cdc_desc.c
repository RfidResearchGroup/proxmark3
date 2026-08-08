#include <stdbool.h>
#include <stdint.h>
#include "usb_cdc_desc.h"
#include "usb_cdc_apis.h"

#ifndef LBYTE
#define LBYTE(x)  ((uint8_t)(x & 0x00FF))        /*!< low byte define */
#endif
#ifndef HBYTE
#define HBYTE(x)  ((uint8_t)((x & 0xFF00) >>8))  /*!< high byte define*/
#endif

const char devDescriptor[18] = {
    /* Device descriptor */
    0x12,                          // Length
    0x01,                          // Descriptor Type (DEVICE)
    0x00, 0x02,                    // Complies with USB Spec. Release (0200h = release 2.00)  0210 == release 2.10
    2,                             // Device Class:    Communication Device Class
    0,                             // Device Subclass: CDC class sub code ACM [ice 0x02 = win10 virtual comport ]
    0,                             // Device Protocol: CDC Device protocol (unused)
    USB_CDC_DESC_MAX_EP0_SIZE,     // MaxPacketSize0: The maximum packet size for endpoint 0
    0xc4, 0x9a,                    // Vendor ID  [0x9ac4 = J. Westhues]
    0x8f, 0x4b,                    // Product ID [0x4b8f = Proxmark-3 RFID Instrument]
    0x00, 0x01,                    // BCD Device release number (1.00)
    1,                             // index Manufacturer
    2,                             // index Product
    3,                             // index SerialNumber
    1                              // Number of Configs
};

const char cfgDescriptor[67] = {

    /* Configuration 1 descriptor */
    // -----------------------------
    9,                                          // Length
    0x02,                                       // Descriptor Type
    (9 + 9 + 5 + 5 + 4 + 5 + 7 + 9 + 7 + 7), 0, // Total Length 2 EP + Control
    2,                                          // Number of Interfaces
    1,                                          // Index value of this Configuration (used in SetConfiguration from Host)
    0,                                          // Configuration string index
    USB_CDC_DESC_CFG_POWER_MODE,                // Attributes 0xA0
    0xFA,                                       // Max Power consumption

    // IAD to associate the one CDC interface
    // --------------------------------------
    /*
        8,         // Length
        USB_DESCRIPTOR_IAD, // IAD_DESCRIPTOR (0x0B)
        0,         // CDC_INT_INTERFACE NUMBER  (
        2,         // IAD INTERFACE COUNT (two interfaces)
        2,         // Function Class: CDC_CLASS
        2,         // Function SubClass: ACM
        1,         // Function Protocol: v.25term
        0,         // iInterface
    */

    /* Interface 0 Descriptor */
    /* CDC Communication Class Interface Descriptor Requirement for Notification*/
    // -----------------------------------------------------------
    9,         // Length
    0x04,      // Descriptor Type
    0,         // Interface Number
    0,         // Alternate Setting
    1,         // Number of Endpoints in this interface
    2,         // Interface Class code    (Communication Interface Class)
    2,         // Interface Subclass code (Abstract Control Model)
    1,         // InterfaceProtocol       (Common AT Commands, V.25term)
    0,         // iInterface

    /* Header Functional Descriptor */
    5,         // Function Length
    0x24,      // Descriptor type:    CS_INTERFACE
    0,         // Descriptor subtype: Header Functional Descriptor
    0x10, 0x01, // bcd CDC:1.1

    /* ACM Functional Descriptor */
    4,         // Function Length
    0x24,      // Descriptor Type:    CS_INTERFACE
    2,         // Descriptor Subtype: Abstract Control Management Functional Descriptor
    2,         // Capabilities        D1, Device supports the request combination of Set_Line_Coding, Set_Control_Line_State, Get_Line_Coding, and the notification Serial_State

    /* Union Functional Descriptor */
    5,         // Function Length
    0x24,      // Descriptor Type:    CS_INTERFACE
    6,         // Descriptor Subtype: Union Functional Descriptor
    0,         // MasterInterface:    Communication Class Interface
    1,         // SlaveInterface0:    Data Class Interface

    /* Call Management Functional Descriptor */
    5,         // Function Length
    0x24,      // Descriptor Type:    CS_INTERFACE
    1,         // Descriptor Subtype: Call Management Functional Descriptor
    0,         // Capabilities:       Device sends/receives call management information only over the Communication Class interface. Device does not handle call management itself
    1,         // Data Interface:     Data Class Interface

    /* Protocol Functional Descriptor */
    /*
    6,
    0x24,      // Descriptor Type: CS_INTERFACE
    0x0B,      // Descriptor Subtype: Protocol Unit functional Descriptor
    0xDD,      // constant uniq ID of unit
    0xFE,      // protocol
    */

    /* CDC Notification Endpoint descriptor */
    // ---------------------------------------
    7,                           // Length
    0x05,                        // Descriptor Type
    USB_CDC_DESC_INT_EPT,             // EndpointAddress:   Endpoint x - IN
    0x03,                        // Attributes, Interrupt Transfer
    // TODO: why set to  ep0 size?
    LBYTE(USB_CDC_DESC_MAX_EP0_SIZE), HBYTE(USB_CDC_DESC_MAX_EP0_SIZE), // MaxPacket Size
    0xFF,                        // Interval polling


    /* Interface 1 Descriptor */
    /* CDC Data Class Interface 1 Descriptor Requirement */
    9,                           // Length
    0x04,                        // Descriptor Type
    1,                           // Interface Number
    0,                           // Alternate Setting
    2,                           // Number of Endpoints
    0x0A,                        // Interface Class:     CDC Data interface class
    0,                           // Interface Subclass:  not used
    0,                           // Interface Protocol:  No class specific protocol required (usb spec)
    0,                           // Interface

    /* Endpoint descriptor */
    7,                           // Length
    0x05,                        // Descriptor Type
    USB_CDC_DESC_BULK_OUT_EPT,        // Endpoint Address:    Endpoint 01 - OUT
    0x02,                        // Attributes:          BULK
    LBYTE(USB_CDC_DESC_OUT_PACKET_SIZE), HBYTE(USB_CDC_DESC_OUT_PACKET_SIZE), // MaxPacket Size
    0,                           // Interval:            ignored for bulk

    /* Endpoint descriptor */
    7,                           // Length
    0x05,                        // Descriptor Type
    USB_CDC_DESC_BULK_IN_EPT,         // Endpoint Address:    Endpoint 02 - IN
    0x02,                        // Attribute:           BULK
    LBYTE(USB_CDC_DESC_IN_PACKET_SIZE), HBYTE(USB_CDC_DESC_IN_PACKET_SIZE), // MaxPacket Size
    0                            // Interval:            ignored for bulk
};

// BOS descriptor
const char bosDescriptor[12] = {
    0x5,
    0x0F, // DescriptorType for a BOS Descriptor.
    0xC,
    0x0,
    0x1,  // 1 device capability
    0x7,
    0x10, // USB_DEVICE_CAPABITY_TYPE,
    0x2,
    0x2,  // LPM capability bit set
    0x0,
    0x0,
    0x0
};

// Microsoft OS Extended Configuration Compatible ID Descriptor
/*
const char CompatIDFeatureDescriptor[] = {
        0x28, 0x00, 0x00, 0x00,                         // Descriptor Length 40bytes (0x28)
        0x00, 0x01,                                     // Version ('1.0')
        MS_EXTENDED_COMPAT_ID, 0x00,                    // Compatibility ID Descriptor Index  0x0004
        0x01,                                           // Number of sections. 0x1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // Reserved (7bytes)
        // -----function section 1------
        0x00,                                           // Interface Number #0
        0x01,                                           // reserved (0x1)
        0x57, 0x49, 0x4E, 0x55, 0x53, 0x42, 0x00, 0x00, // Compatible ID  ('WINUSB\0\0')  (8bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sub-Compatible ID (8byte)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00              // Reserved (6bytes)
};
*/

// Microsoft Extended Properties Feature Descriptor
/*
const char OSprop[] = {
        // u32 Descriptor Length (10+132+64+102 == 308
        0x34, 0x01, 0, 0,
        // u16 Version ('1.0')
        0, 1,
        // u16 wIndex
        MS_EXTENDED_PROPERTIES, 0,
        // u16 wCount  -- three section
        3, 0,

        // -----property section 1------
        // u32 size  ( 14+40+78 == 132)
        132, 0, 0, 0,
        // u32 type
        1, 0, 0, 0,  // unicode string
        // u16 namelen  (20*2 = 40)
        40, 0,
        // name  DeviceInterfaceGUID
        'D',0,'e',0,'v',0,'i',0,'c',0,'e',0,'I',0,'n',0,'t',0,'e',0,'r',0,'f',0,'a',0,'c',0,'e',0,'G',0,'U',0,'I',0,'D',0,0,0,
        // u32 datalen  (39*2 = 78)
        78, 0, 0, 0,
        // data {4D36E978-E325-11CE-BFC1-08002BE10318}
        '{',0,'4',0,'d',0,'3',0,'6',0,'e',0,'9',0,'7',0,'8',0,'-',0,'e',0,'3',0,'2',0,'5',0,
        '-',0,'1',0,'1',0,'c',0,'e',0,'-',0,'b',0,'f',0,'c',0,'1',0,'-',0,'0',0,'8',0,'0',0,
        '0',0,'2',0,'b',0,'e',0,'1',0,'0',0,'3',0,'1',0,'8',0,'}',0,0,0,

        // -----property section 2------
        // u32 size  ( 14+12+38 == 64)
        64, 0, 0, 0,
        // u32 type
        1, 0, 0, 0,  // unicode string
        // u16 namelen (12)
        12, 0,
        // name Label
        'L',0,'a',0,'b',0,'e',0,'l',0,0,0,
        // u32 datalen ( 19*2 = 38 )
        38, 0, 0, 0,
        // data 'Awesome PM3 Device'
        'A',0,'w',0,'e',0,'s',0,'o',0,'m',0,'e',0,' ',0,'P',0,'M',0,'3',0,' ',0,'D',0,'e',0,'v',0,'i',0,'c',0,'e',0,0,0,

        // -----property section 3------
        // u32 size ( 14+12+76 == 102)
        102, 0, 0, 0,
        // u32 type
        2, 0, 0, 0,  //Unicode string with environment variables
        // u16 namelen (12)
        12, 0,
        // name Icons
        'I',0,'c',0,'o',0,'n',0,'s',0,0,0,
        // u32 datalen ( 38*2 ==  76)
        76, 0, 0, 0,
        // data '%SystemRoot%\\system32\\Shell32.dll,-13'
        '%',0,'S',0,'y',0,'s',0,'t',0,'e',0,'m',0,'R',0,'o',0,'o',0,'t',0,'%',0,
        '\\',0,'s',0,'y',0,'s',0,'t',0,'e',0,'m',0,'3',0,'2',0,'\\',0,
        'S',0,'h',0,'e',0,'l',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,',',0,
        '-',0,'1',0,'3',0,0,0
};

*/

const char StrLanguageCodes[4] = {
    4,          // Length
    0x03,       // Type is string
    0x09, 0x04  // supported language Code 0 = 0x0409 (English)
};

// Note: ModemManager (Linux) ignores Proxmark3 devices by matching the
// manufacturer string "proxmark.org". Don't change this.
// or use the blacklisting file.
const char StrManufacturer[26] = {
    26,         // Length
    0x03,       // Type is string
    'p', 0, 'r', 0, 'o', 0, 'x', 0, 'm', 0, 'a', 0, 'r', 0, 'k', 0, '.', 0, 'o', 0, 'r', 0, 'g', 0,
};

const char StrProduct[20] = {
    20,         // Length
    0x03,       // Type is string
    'p', 0, 'r', 0, 'o', 0, 'x', 0, 'm', 0, 'a', 0, 'r', 0, 'k', 0, '3', 0
};

#ifndef WITH_FLASH  // If there is no flash, then use a fixed(const) serial number.

const char StrSerialNumber[14] = {
    14,         // Length
    0x03,       // Type is string
    'i', 0, 'c', 0, 'e', 0, 'm', 0, 'a', 0, 'n', 0
};

#else // WITH_FLASH is defined

// Manually calculated size of descriptor with unique ID:
// offset  0, lengt h 1: total length field
// offset  1, length  1: descriptor type field
// offset  2, length 12: 6x unicode chars (original string)
// offset 14, length  4: 2x unicode chars (underscores)      [[ to avoid descriptor being (size % 8) == 0, OS bug workaround ]]
// offset 18, length 32: 16x unicode chars (8-byte serial as hex characters)
// ============================
// total: 50 bytes
#define USB_STRING_DESCRIPTOR_SERIAL_NUMBER_LENGTH  50
char StrSerialNumber[50] = {
    14,         // Length is initially identical to non-unique version ... The length updated at boot, if unique serial is available
    0x03,       // Type is string
    'i', 0, 'c', 0, 'e', 0, 'm', 0, 'a', 0, 'n', 0,
    '_', 0, '_', 0,
    'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0,
    'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0, 'x', 0,
};
void usb_update_serial(uint64_t newSerialNumber) {
    static bool configured = false; // TODO: enable by setting to false here...
    if (configured) {
        return;
    }
    // run this only once per boot... even if it fails to find serial number
    configured = true;
    // reject serial number if all-zero or all-ones
    if ((newSerialNumber == 0x0000000000000000) || (newSerialNumber == 0xFFFFFFFFFFFFFFFF)) {
        return;
    }
    // Descriptor is, effectively, initially identical to non-unique serial
    // number because it reports the shorter length in the first byte.
    // Convert uniqueID's eight bytes to 16 unicode characters in the
    // descriptor and, finally, update the descriptor's length, which
    // causes the serial number to become visible.
    for (uint8_t i = 0; i < 8; i++) {
        // order of nibbles chosen to match display order from `hw status`
        uint8_t nibble1 = (newSerialNumber >> ((8 * i) + 4)) & 0xFu; // bitmasks [0xF0, 0xF000, 0xF00000, ... 0xF000000000000000]
        uint8_t nibble2 = (newSerialNumber >> ((8 * i) + 0)) & 0xFu; // bitmasks [0x0F, 0x0F00, 0x0F0000, ... 0x0F00000000000000]
        char c1 = nibble1 < 10 ? '0' + nibble1 : 'A' + (nibble1 - 10);
        char c2 = nibble2 < 10 ? '0' + nibble2 : 'A' + (nibble2 - 10);
        StrSerialNumber[18 + (4 * i) + 0] = c1; // [ 18, 22, .., 42, 46 ]
        StrSerialNumber[18 + (4 * i) + 2] = c2; // [ 20, 24, .., 44, 48 ]
    }
    StrSerialNumber[0] = USB_STRING_DESCRIPTOR_SERIAL_NUMBER_LENGTH;
}

#endif


// size includes their own field.
const char StrMS_OSDescriptor[18] = {
    18,         // length 0x12
    0x03,       // Type is string
    'M', 0, 'S', 0, 'F', 0, 'T', 0, '1', 0, '0', 0, '0', 0, USB_CDC_DESC_MS_VENDOR_CODE, 0
};
