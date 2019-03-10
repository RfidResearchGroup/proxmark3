//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// USB utilities
//-----------------------------------------------------------------------------
#include "proxusb.h"

// It seems to be missing for mingw
#ifndef ETIMEDOUT
#define ETIMEDOUT 116
#endif

usb_dev_handle *devh = NULL;
static unsigned int claimed_iface = 0;
unsigned char return_on_error = 0;
unsigned char error_occured = 0;

void SendCommand(UsbCommand *c) {
    int ret;

#if 0
    printf("Sending %d bytes\n", sizeof(UsbCommand));
#endif

    ret = usb_bulk_write(devh, 0x01, (char *)c, sizeof(UsbCommand), 1000);
    if (ret < 0) {
        error_occured = 1;
        if (return_on_error)
            return;

        fprintf(stderr, "write failed: %s!\nTrying to reopen device...\n",
                usb_strerror());

        if (devh) {
            usb_close(devh);
            devh = NULL;
        }
        while (!OpenProxmark(0)) { msleep(1000); }
        printf(PROXPROMPT);
        fflush(NULL);

        return;
    }
}

bool ReceiveCommandPoll(UsbCommand *c) {
    int ret;

    memset(c, 0, sizeof(UsbCommand));
    ret = usb_bulk_read(devh, 0x82, (char *)c, sizeof(UsbCommand), 500);
    if (ret < 0) {
        if (ret != -ETIMEDOUT) {
            error_occured = 1;
            if (return_on_error)
                return false;

            fprintf(stderr, "read failed: %s(%d)!\nTrying to reopen device...\n",
                    usb_strerror(), ret);

            if (devh) {
                usb_close(devh);
                devh = NULL;
            }
            while (!OpenProxmark(0)) { msleep(1000); }
            printf(PROXPROMPT);
            fflush(NULL);

            return false;
        }
    } else {
        if (ret && (ret < sizeof(UsbCommand))) {
            fprintf(stderr, "Read only %d instead of requested %d bytes!\n",
                    ret, (int)sizeof(UsbCommand));
        }
    }

    return ret > 0;
}

void ReceiveCommand(UsbCommand *c) {
//  printf("%s()\n", __FUNCTION__);
    int retval = 0;
    do {
        retval = ReceiveCommandPoll(c);
        if (retval != 1) printf("ReceiveCommandPoll returned %d\n", retval);
    } while (retval < 0);
//  printf("recv %x\n", c->cmd);
}

usb_dev_handle *findProxmark(int verbose, unsigned int *iface) {
    struct usb_bus *busses, *bus;
    usb_dev_handle *handle = NULL;
    struct prox_unit units[50];
    int iUnit = 0;

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
                        fprintf(stderr, "open fabiled: %s!\n", usb_strerror());
                    //return NULL;
                    continue;
                }
                *iface = dev->config[0].interface[0].altsetting[0].bInterfaceNumber;

                struct prox_unit unit = {handle, {0}};
                usb_get_string_simple(handle, desc->iSerialNumber, unit.serial_number, sizeof(unit.serial_number));
                units[iUnit++] = unit;

                //return handle;
            }
        }
    }

    if (iUnit > 0) {
        int iSelection = 0;

        fprintf(stdout, "\nConnected units:\n");

        for (int i = 0; i < iUnit; i++) {
            struct usb_device *dev = usb_device(units[i].handle);
            fprintf(stdout, "\t%d. SN: %s [%s/%s]\n", i + 1, units[i].serial_number, dev->bus->dirname, dev->filename);
        }
        if (iUnit > 1) {
            while (iSelection < 1 || iSelection > iUnit) {
                fprintf(stdout, "Which unit do you want to connect to? ");
                int res = fscanf(stdin, "%d", &iSelection);
                if (res != 1) {
                    fprintf(stderr, "Input parse error");
                    fflush(stderr);
                    abort();
                }
            }
        } else {
            iSelection = 1;
        }

        iSelection --;

        for (int i = 0; i < iUnit; i++) {
            if (iSelection == i) continue;
            usb_close(units[i].handle);
            units[i].handle = NULL;
        }

        return units[iSelection].handle;
    }
    return NULL;
}

usb_dev_handle *OpenProxmark(int verbose) {
    int ret;
    usb_dev_handle *handle = NULL;
    unsigned int iface;

    handle = findProxmark(verbose, &iface);
    if (!handle)
        return NULL;

#ifdef __linux__
    /* detach kernel driver first */
    ret = usb_detach_kernel_driver_np(handle, iface);
    /* don't complain if no driver attached */
    if (ret < 0 && ret != -61 && verbose)
        fprintf(stderr, "detach kernel driver failed: (%d) %s!\n", ret, usb_strerror());
#endif

    // Needed for Windows. Optional for Mac OS and Linux
    ret = usb_set_configuration(handle, 1);
    if (ret < 0) {
        if (verbose)
            fprintf(stderr, "configuration set failed: %s!\n", usb_strerror());
        return NULL;
    }

    ret = usb_claim_interface(handle, iface);
    if (ret < 0) {
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
    devh = NULL;
}
