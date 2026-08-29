#ifndef USB_READ_NG_H
#define USB_READ_NG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// --------------------- HAL BY DXL ---------------------
// We need to consider whether it will affect the reading performance of USB in order to optimize it.
// The HAL layer should not contain any code related the platform.

#ifdef __cplusplus
extern "C" {
#endif

// Callbacks, implement functions on platform related.
typedef bool (*usb_link_ready_cb_t)(void);               // is usb link ready?
typedef bool (*usb_data_ready_cb_t)(void);               // is data received ready?
typedef uint16_t (*usb_get_byte_count_cb_t)(void);       // how length of data received?
typedef uint8_t (*usb_read_fifo_cb_t)(void);             // read byte from fifo
typedef void (*usb_clear_rx_ready_cb_t)(void);           // clear

// Configs, instance of platform.
typedef struct {
    usb_link_ready_cb_t      is_link_ready;
    usb_data_ready_cb_t      is_data_ready;
    usb_get_byte_count_cb_t  get_byte_count;
    usb_read_fifo_cb_t       read_fifo;
    usb_clear_rx_ready_cb_t  clear_ready;

    uint8_t *buffer;        // buffer for read ng of platform.
    size_t   buffer_size;   // buffer size
    uint16_t timeout;       // read timeout if no data ready.
} usb_read_ng_config_t;

// setup usb read ng, implement all usb related function for platform.
// @param: config - the module will use this point on global, so don't instance in function stack!
void usb_read_ng_init(const usb_read_ng_config_t *config);

// exported api, not platform related, for check data available of local usb ng buffer(not usb ep buffer)
// nonblocking api
bool usb_read_ng_has_buffered_data(void);

// exported api, not platform related, for read data from local buffer or usb device online.
// nonblocking api
uint32_t usb_read_ng(uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
