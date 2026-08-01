#ifndef __CDC_CLASS_H
#define __CDC_CLASS_H

#ifdef __cplusplus
extern "C" {

#endif

#include "usb_std.h"
#include "usbd_core.h"

/**
  * @brief usb cdc use endpoint define
  */
#define USBD_CDC_INT_EPT                 0x82
#define USBD_CDC_BULK_IN_EPT             0x81
#define USBD_CDC_BULK_OUT_EPT            0x01

/**
  * @brief usb cdc in and out max packet size define
  */
#define USBD_CDC_IN_MAXPACKET_SIZE        0x40
#define USBD_CDC_OUT_MAXPACKET_SIZE       0x40
#define USBD_CDC_CMD_MAXPACKET_SIZE       0x08

/**
  * @brief usb cdc class struct
  */
typedef struct {
    uint32_t alt_setting;
    uint8_t g_rx_buff[USBD_CDC_OUT_MAXPACKET_SIZE];
    uint8_t g_cmd[USBD_CDC_CMD_MAXPACKET_SIZE];
    uint8_t g_req;
    uint16_t g_len, g_rxlen;
    __IO uint8_t g_tx_completed, g_rx_completed;
    linecoding_type linecoding;
} cdc_struct_type;


/**
  * @}
  */

/** @defgroup USB_cdc_class_exported_functions
  * @{
  */

extern usbd_class_handler cdc_class_handler;

// packet send & recv
uint16_t usb_vcp_get_rxdata(void *udev, uint8_t *recv_data, uint16_t buflen);

error_status usb_vcp_send_data(void *udev, uint8_t *send_data, uint16_t len);

// buffer send
error_status usb_vcp_buffer_send_start(void *udev);

void usb_vcp_buffer_send_push(void *udev, uint8_t b);

void usb_vcp_buffer_send_flush(void *udev);

error_status usb_vcp_buffer_send_stop(void *udev);

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */
#ifdef __cplusplus
}
#endif

#endif
