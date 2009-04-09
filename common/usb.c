//-----------------------------------------------------------------------------
// My USB driver. This has to be common, because it exists in both the
// bootrom and the application.
// Jonathan Westhues, split Aug 14 2005
//-----------------------------------------------------------------------------
#include <proxmark3.h>

#define min(a, b) (((a) > (b)) ? (b) : (a))

#define USB_REPORT_PACKET_SIZE 64

typedef struct PACKED {
	BYTE	bmRequestType;
	BYTE	bRequest;
	WORD	wValue;
	WORD	wIndex;
	WORD	wLength;
} UsbSetupData;

#define USB_REQUEST_GET_STATUS					0
#define USB_REQUEST_CLEAR_FEATURE				1
#define USB_REQUEST_SET_FEATURE					3
#define USB_REQUEST_SET_ADDRESS					5
#define USB_REQUEST_GET_DESCRIPTOR				6
#define USB_REQUEST_SET_DESCRIPTOR				7
#define USB_REQUEST_GET_CONFIGURATION			8
#define USB_REQUEST_SET_CONFIGURATION			9
#define USB_REQUEST_GET_INTERFACE				10
#define USB_REQUEST_SET_INTERFACE				11
#define USB_REQUEST_SYNC_FRAME					12

#define USB_DESCRIPTOR_TYPE_DEVICE				1
#define USB_DESCRIPTOR_TYPE_CONFIGURATION		2
#define USB_DESCRIPTOR_TYPE_STRING				3
#define USB_DESCRIPTOR_TYPE_INTERFACE			4
#define USB_DESCRIPTOR_TYPE_ENDPOINT			5
#define USB_DESCRIPTOR_TYPE_DEVICE_QUALIFIER	6
#define USB_DESCRIPTOR_TYPE_OTHER_SPEED_CONF	7
#define USB_DESCRIPTOR_TYPE_INTERFACE_POWER		8
#define USB_DESCRIPTOR_TYPE_HID					0x21
#define USB_DESCRIPTOR_TYPE_HID_REPORT			0x22

#define USB_DEVICE_CLASS_HID					0x03

static const BYTE HidReportDescriptor[] = {
	0x06,0xA0,0xFF,	// Usage Page (vendor defined) FFA0
	0x09,0x01,		// Usage (vendor defined)
	0xA1,0x01,	 	// Collection (Application)
	0x09,0x02,   	// Usage (vendor defined)
	0xA1,0x00,   	// Collection (Physical)
	0x06,0xA1,0xFF,	// Usage Page (vendor defined)

	//The,input report
	0x09,0x03,   	// usage - vendor defined
	0x09,0x04,   	// usage - vendor defined
	0x15,0x80,   	// Logical Minimum (-128)
	0x25,0x7F,   	// Logical Maximum (127)
	0x35,0x00,   	// Physical Minimum (0)
	0x45,0xFF,   	// Physical Maximum (255)
	0x75,0x08,   	// Report Size (8)  (bits)
	0x95,0x40,   	// Report Count (64)  (fields)
	0x81,0x02,   	// Input (Data,Variable,Absolute)

	//The,output report
	0x09,0x05,   	// usage - vendor defined
	0x09,0x06,   	// usage - vendor defined
	0x15,0x80,   	// Logical Minimum (-128)
	0x25,0x7F,   	// Logical Maximum (127)
	0x35,0x00,   	// Physical Minimum (0)
	0x45,0xFF,   	// Physical Maximum (255)
	0x75,0x08,   	// Report Size (8)  (bits)
	0x95,0x40,   	// Report Count (64)  (fields)
	0x91,0x02,   	// Output (Data,Variable,Absolute)

	0xC0,			// End Collection

	0xC0,			// End Collection
};

static const BYTE DeviceDescriptor[] = {
	0x12,			// Descriptor length (18 bytes)
	0x01,			// Descriptor type (Device)
	0x10,0x01,		// Complies with USB Spec. Release (0110h = release 1.10)
	0x00,			// Class code (0)
	0x00,			// Subclass code (0)
	0x00,			// Protocol (No specific protocol)
	0x08,			// Maximum packet size for Endpoint 0 (8 bytes)
	0xc4,0x9a,		// Vendor ID (random numbers)
	0x8f,0x4b,		// Product ID (random numbers)
	0x01,0x00,		// Device release number (0001)
	0x01,			// Manufacturer string descriptor index
	0x02,			// Product string descriptor index
	0x00,			// Serial Number string descriptor index (None)
	0x01,			// Number of possible configurations (1)
};

static const BYTE ConfigurationDescriptor[] = {
	0x09,			// Descriptor length (9 bytes)
	0x02,			// Descriptor type (Configuration)
	0x29,0x00,		// Total data length (41 bytes)
	0x01,			// Interface supported (1)
	0x01,			// Configuration value (1)
	0x00,			// Index of string descriptor (None)
	0x80,			// Configuration (Bus powered)
	250,			// Maximum power consumption (500mA)

	//interface
	0x09,			// Descriptor length (9 bytes)
	0x04,			// Descriptor type (Interface)
	0x00,			// Number of interface (0)
	0x00,			// Alternate setting (0)
	0x02,			// Number of interface endpoint (2)
	0x03,			// Class code (HID)
	0x00,			// Subclass code ()
	0x00,			// Protocol code ()
	0x00,			// Index of string()

	// class
	0x09,			// Descriptor length (9 bytes)
	0x21,			// Descriptor type (HID)
	0x00,0x01,		// HID class release number (1.00)
	0x00,			// Localized country code (None)
	0x01,			// # of HID class dscrptr to follow (1)
	0x22,			// Report descriptor type (HID)
	// Total length of report descriptor
	sizeof(HidReportDescriptor),0x00,

	// endpoint 1
	0x07,			// Descriptor length (7 bytes)
	0x05,			// Descriptor type (Endpoint)
	0x01,			// Encoded address (Respond to OUT)
	0x03,			// Endpoint attribute (Interrupt transfer)
	0x08,0x00,		// Maximum packet size (8 bytes)
	0x01,			// Polling interval (1 ms)

	// endpoint 2
	0x07,			// Descriptor length (7 bytes)
	0x05,			// Descriptor type (Endpoint)
	0x82,			// Encoded address (Respond to IN)
	0x03,			// Endpoint attribute (Interrupt transfer)
	0x08,0x00,		// Maximum packet size (8 bytes)
	0x01,			// Polling interval (1 ms)
};

static const BYTE StringDescriptor0[] = {
	0x04,			// Length
	0x03,			// Type is string
	0x09,			// English
	0x04,			//  US
};

static const BYTE StringDescriptor1[] = {
	24,				// Length
	0x03,			// Type is string
	'J', 0x00,
	'.', 0x00,
	' ', 0x00,
	'W', 0x00,
	'e', 0x00,
	's', 0x00,
	't', 0x00,
	'h', 0x00,
	'u', 0x00,
	'e', 0x00,
	's', 0x00,
};

static const BYTE StringDescriptor2[] = {
	54,				// Length
	0x03,			// Type is string
	'P', 0x00,
	'r', 0x00,
	'o', 0x00,
	'x', 0x00,
	'M', 0x00,
	'a', 0x00,
	'r', 0x00,
	'k', 0x00,
	'-', 0x00,
	'3', 0x00,
	' ', 0x00,
	'R', 0x00,
	'F', 0x00,
	'I', 0x00,
	'D', 0x00,
	' ', 0x00,
	'I', 0x00,
	'n', 0x00,
	's', 0x00,
	't', 0x00,
	'r', 0x00,
	'u', 0x00,
	'm', 0x00,
	'e', 0x00,
	'n', 0x00,
	't', 0x00,
};

static const BYTE * const StringDescriptors[] = {
	StringDescriptor0,
	StringDescriptor1,
	StringDescriptor2,
};


static BYTE UsbBuffer[64];
static int  UsbSoFarCount;

static BYTE CurrentConfiguration;

static void UsbSendEp0(const BYTE *data, int len)
{
	int thisTime, i;

	do {
		thisTime = min(len, 8);
		len -= thisTime;

		for(i = 0; i < thisTime; i++) {
			UDP_ENDPOINT_FIFO(0) = *data;
			data++;
		}

		if(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED) {
			UDP_ENDPOINT_CSR(0) &= ~UDP_CSR_TX_PACKET_ACKED;
			while(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED)
				;
		}

		UDP_ENDPOINT_CSR(0) |= UDP_CSR_TX_PACKET;

		do {
			if(UDP_ENDPOINT_CSR(0) & UDP_CSR_RX_PACKET_RECEIVED_BANK_0) {
				// This means that the host is trying to write to us, so
				// abandon our write to them.
				UDP_ENDPOINT_CSR(0) &= ~UDP_CSR_RX_PACKET_RECEIVED_BANK_0;
				return;
			}
		} while(!(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED));
	} while(len > 0);

	if(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED) {
		UDP_ENDPOINT_CSR(0) &= ~UDP_CSR_TX_PACKET_ACKED;
		while(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED)
			;
	}
}

static void UsbSendZeroLength(void)
{
	UDP_ENDPOINT_CSR(0) |= UDP_CSR_TX_PACKET;

	while(!(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED))
		;

	UDP_ENDPOINT_CSR(0) &= ~UDP_CSR_TX_PACKET_ACKED;

	while(UDP_ENDPOINT_CSR(0) & UDP_CSR_TX_PACKET_ACKED)
		;
}

static void HandleRxdSetupData(void)
{
	int i;
	UsbSetupData usd;

	for(i = 0; i < sizeof(usd); i++) {
		((BYTE *)&usd)[i] = UDP_ENDPOINT_FIFO(0);
	}

	if(usd.bmRequestType & 0x80) {
		UDP_ENDPOINT_CSR(0) |= UDP_CSR_CONTROL_DATA_DIR;
		while(!(UDP_ENDPOINT_CSR(0) & UDP_CSR_CONTROL_DATA_DIR))
			;
	}

	UDP_ENDPOINT_CSR(0) &= ~UDP_CSR_RX_HAVE_READ_SETUP_DATA;
	while(UDP_ENDPOINT_CSR(0) & UDP_CSR_RX_HAVE_READ_SETUP_DATA)
		;

	switch(usd.bRequest) {
		case USB_REQUEST_GET_DESCRIPTOR:
			if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_DEVICE) {
				UsbSendEp0((BYTE *)&DeviceDescriptor,
					min(sizeof(DeviceDescriptor), usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_CONFIGURATION) {
				UsbSendEp0((BYTE *)&ConfigurationDescriptor,
					min(sizeof(ConfigurationDescriptor), usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_STRING) {
				const BYTE *s = StringDescriptors[usd.wValue & 0xff];
				UsbSendEp0(s, min(s[0], usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_HID_REPORT) {
				UsbSendEp0((BYTE *)&HidReportDescriptor,
					min(sizeof(HidReportDescriptor), usd.wLength));
			} else {
				*((DWORD *)0x00200000) = usd.wValue;
			}
			break;

		case USB_REQUEST_SET_ADDRESS:
			UsbSendZeroLength();
			UDP_FUNCTION_ADDR = UDP_FUNCTION_ADDR_ENABLED | usd.wValue ;
			if(usd.wValue != 0) {
				UDP_GLOBAL_STATE = UDP_GLOBAL_STATE_ADDRESSED;
			} else {
				UDP_GLOBAL_STATE = 0;
			}
			break;

		case USB_REQUEST_GET_CONFIGURATION:
			UsbSendEp0(&CurrentConfiguration, sizeof(CurrentConfiguration));
			break;

		case USB_REQUEST_GET_STATUS: {
			if(usd.bmRequestType & 0x80) {
				WORD w = 0;
				UsbSendEp0((BYTE *)&w, sizeof(w));
			}
			break;
		}
		case USB_REQUEST_SET_CONFIGURATION:
			CurrentConfiguration = usd.wValue;
			if(CurrentConfiguration) {
				UDP_GLOBAL_STATE = UDP_GLOBAL_STATE_CONFIGURED;
				UDP_ENDPOINT_CSR(1) = UDP_CSR_ENABLE_EP |
					UDP_CSR_EPTYPE_INTERRUPT_OUT;
				UDP_ENDPOINT_CSR(2) = UDP_CSR_ENABLE_EP |
					UDP_CSR_EPTYPE_INTERRUPT_IN;
			} else {
				UDP_GLOBAL_STATE = UDP_GLOBAL_STATE_ADDRESSED;
				UDP_ENDPOINT_CSR(1) = 0;
				UDP_ENDPOINT_CSR(2) = 0;
			}
			UsbSendZeroLength();
			break;

		case USB_REQUEST_GET_INTERFACE: {
			BYTE b = 0;
			UsbSendEp0(&b, sizeof(b));
			break;
		}

		case USB_REQUEST_SET_INTERFACE:
			UsbSendZeroLength();
			break;

		case USB_REQUEST_CLEAR_FEATURE:
		case USB_REQUEST_SET_FEATURE:
		case USB_REQUEST_SET_DESCRIPTOR:
		case USB_REQUEST_SYNC_FRAME:
		default:
			break;
	}
}

void UsbSendPacket(BYTE *packet, int len)
{
	int i, thisTime;

	while(len > 0) {
		thisTime = min(len, 8);

		for(i = 0; i < thisTime; i++) {
			UDP_ENDPOINT_FIFO(2) = packet[i];
		}
		UDP_ENDPOINT_CSR(2) |= UDP_CSR_TX_PACKET;

		while(!(UDP_ENDPOINT_CSR(2) & UDP_CSR_TX_PACKET_ACKED))
			;
		UDP_ENDPOINT_CSR(2) &= ~UDP_CSR_TX_PACKET_ACKED;

		while(UDP_ENDPOINT_CSR(2) & UDP_CSR_TX_PACKET_ACKED)
			;

		len -= thisTime;
		packet += thisTime;
	}
}

static void HandleRxdData(void)
{
	int i, len;

	if(UDP_ENDPOINT_CSR(1) & UDP_CSR_RX_PACKET_RECEIVED_BANK_0) {
		len = UDP_CSR_BYTES_RECEIVED(UDP_ENDPOINT_CSR(1));

		for(i = 0; i < len; i++) {
			UsbBuffer[UsbSoFarCount] = UDP_ENDPOINT_FIFO(1);
			UsbSoFarCount++;
		}

		UDP_ENDPOINT_CSR(1) &= ~UDP_CSR_RX_PACKET_RECEIVED_BANK_0;
		while(UDP_ENDPOINT_CSR(1) & UDP_CSR_RX_PACKET_RECEIVED_BANK_0)
			;

		if(UsbSoFarCount >= 64) {
			UsbPacketReceived(UsbBuffer, UsbSoFarCount);
			UsbSoFarCount = 0;
		}
	}

	if(UDP_ENDPOINT_CSR(1) & UDP_CSR_RX_PACKET_RECEIVED_BANK_1) {
		len = UDP_CSR_BYTES_RECEIVED(UDP_ENDPOINT_CSR(1));

		for(i = 0; i < len; i++) {
			UsbBuffer[UsbSoFarCount] = UDP_ENDPOINT_FIFO(1);
			UsbSoFarCount++;
		}

		UDP_ENDPOINT_CSR(1) &= ~UDP_CSR_RX_PACKET_RECEIVED_BANK_1;
		while(UDP_ENDPOINT_CSR(1) & UDP_CSR_RX_PACKET_RECEIVED_BANK_1)
			;

		if(UsbSoFarCount >= 64) {
			UsbPacketReceived(UsbBuffer, UsbSoFarCount);
			UsbSoFarCount = 0;
		}
	}
}

void UsbStart(void)
{
	volatile int i;

	UsbSoFarCount = 0;

	USB_D_PLUS_PULLUP_OFF();

	for(i = 0; i < 1000000; i++)
		;

	USB_D_PLUS_PULLUP_ON();

	if(UDP_INTERRUPT_STATUS & UDP_INTERRUPT_END_OF_BUS_RESET) {
		UDP_INTERRUPT_CLEAR = UDP_INTERRUPT_END_OF_BUS_RESET;
	}
}

BOOL UsbPoll(BOOL blinkLeds)
{
	BOOL ret = FALSE;

	if(UDP_INTERRUPT_STATUS & UDP_INTERRUPT_END_OF_BUS_RESET) {
		UDP_INTERRUPT_CLEAR = UDP_INTERRUPT_END_OF_BUS_RESET;

		// following a reset we should be ready to receive a setup packet
		UDP_RESET_ENDPOINT = 0xf;
		UDP_RESET_ENDPOINT = 0;

		UDP_FUNCTION_ADDR = UDP_FUNCTION_ADDR_ENABLED;

		UDP_ENDPOINT_CSR(0) = UDP_CSR_EPTYPE_CONTROL | UDP_CSR_ENABLE_EP;

		CurrentConfiguration = 0;

		ret = TRUE;
	}

	if(UDP_INTERRUPT_STATUS & UDP_INTERRUPT_ENDPOINT(0)) {
		if(UDP_ENDPOINT_CSR(0) & UDP_CSR_RX_HAVE_READ_SETUP_DATA) {
			HandleRxdSetupData();
			ret = TRUE;
		}
	}

	if(UDP_INTERRUPT_STATUS & UDP_INTERRUPT_ENDPOINT(1)) {
		HandleRxdData();
		ret = TRUE;
	}

	return ret;
}
