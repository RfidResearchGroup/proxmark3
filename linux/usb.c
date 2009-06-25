#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <usb.h>
#include <strings.h>
#include <errno.h>

#include "translate.h"
#include "../winsrc/prox.h"
#include "proxmark3.h"

usb_dev_handle *devh = NULL;
static unsigned int claimed_iface = 0;
unsigned char return_on_error = 0;
unsigned char error_occured = 0;

void SendCommand(UsbCommand *c, BOOL wantAck) {
	int ret;

#if 0
	printf("Sending %d bytes\n", sizeof(UsbCommand));
#endif
	ret = usb_bulk_write(devh, 0x01, (char*)c, sizeof(UsbCommand), 1000);
	if (ret<0) {
		error_occured = 1;
		if (return_on_error)
			return;

		fprintf(stderr, "write failed: %s!\nTrying to reopen device...\n",
			usb_strerror());

		if (devh) {
			usb_close(devh);
			devh = NULL;
		}
		while(!(devh=OpenProxmark(0))) { sleep(1); }
		printf(PROXPROMPT);
		fflush(NULL);
		
		return;
	}

	if(wantAck) {
		UsbCommand ack;
		ReceiveCommand(&ack);
		if(ack.cmd != CMD_ACK) {
			printf("bad ACK\n");
			exit(-1);
		}
	}
}

int ReceiveCommandP(UsbCommand *c) {
	int ret;

	bzero(c, sizeof(UsbCommand));
	ret = usb_bulk_read(devh, 0x82, (char*)c, sizeof(UsbCommand), 500);
	if (ret<0) {
		if (ret != -ETIMEDOUT) {
			error_occured = 1;
			if (return_on_error)
				return 0;

			fprintf(stderr, "read failed: %s(%d)!\nTrying to reopen device...\n",
				usb_strerror(), ret);

			if (devh) {
				usb_close(devh);
				devh = NULL;
			}
			while(!(devh=OpenProxmark(0))) { sleep(1); }
			printf(PROXPROMPT);
			fflush(NULL);

			return 0;
		}
	} else {
		if (ret && (ret < sizeof(UsbCommand))) {
			fprintf(stderr, "Read only %d instead of requested %d bytes!\n",
				ret, (int)sizeof(UsbCommand));
		}

#if 0
		{
			int i;

			printf("Read %d bytes\n", ret);
			for (i = 0; i < ret; i++) {
				printf("0x%02X ", ((unsigned char*)c)[i]);
				if (!((i+1)%8))
					printf("\n");
			}
			printf("\n");
		}
#endif
	}

	return ret;
}

void ReceiveCommand(UsbCommand *c) {
	while(ReceiveCommandP(c)<0) {}
}

usb_dev_handle* findProxmark(int verbose, unsigned int *iface) {
	struct usb_bus *busses, *bus;
	usb_dev_handle *handle = NULL;

	usb_find_busses();
	usb_find_devices();

	busses = usb_get_busses();

	for (bus = busses; bus; bus = bus->next) {
		struct usb_device *dev;

		for (dev = bus->devices; dev; dev = dev->next) {
			struct usb_device_descriptor *desc = &(dev->descriptor);

			if ((desc->idProduct == 0x4b8f) && (desc->idVendor == 0x9ac4)) {
				handle = usb_open(dev);
				if (!handle) {
					if (verbose)
						fprintf(stderr, "open failed: %s!\n", usb_strerror());
					return NULL;
				}

				*iface = dev->config[0].interface[0].altsetting[0].bInterfaceNumber;

				return handle;
			}
		}
	}

	return NULL;
}

usb_dev_handle* OpenProxmark(int verbose) {
	int ret;
	usb_dev_handle *handle = NULL;
	unsigned int iface;

#ifndef __APPLE__
	handle = findProxmark(verbose, &iface);
	if (!handle)
		return NULL;

	/* Whatever... */
	usb_reset(handle);
#endif

	handle = findProxmark(verbose, &iface);
	if (!handle)
		return NULL;

	/* detach kernel driver first */
	ret = usb_detach_kernel_driver_np(handle, iface);
	/* don't complain if no driver attached */
	if (ret<0 && ret != -61 && verbose)
		fprintf(stderr, "detach kernel driver failed: (%d) %s!\n", ret, usb_strerror());
	ret = usb_claim_interface(handle, iface);
	if (ret<0) {
		if (verbose)
			fprintf(stderr, "claim failed: %s!\n", usb_strerror());
		return NULL;
	}

	claimed_iface = iface;
	devh = handle;
	return handle;
}

void CloseProxmark(void) {
	usb_release_interface(devh, claimed_iface);
	usb_close(devh);
}
