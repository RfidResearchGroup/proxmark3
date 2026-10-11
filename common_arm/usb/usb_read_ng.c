#include "string.h"
#include "usb_read_ng.h"

static const usb_read_ng_config_t *g_config = NULL;
static size_t g_buf_len = 0;
static size_t g_buf_offset = 0;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

void usb_read_ng_init(const usb_read_ng_config_t *config) {
    if (!config || !config->is_link_ready || !config->is_data_ready ||
            !config->get_byte_count || !config->read_fifo ||
            !config->clear_ready || !config->buffer || config->buffer_size == 0) {
        return;
    }
    g_config = config;
    g_buf_len = 0;
    g_buf_offset = 0;
}

bool usb_read_ng_has_buffered_data(void) {
    return g_buf_len > 0;
}

uint32_t usb_read_ng(uint8_t *data, size_t len) {
    if (!g_config || !data || len == 0) {
        return 0;
    }

    uint32_t nbBytesRcv = 0;
    uint16_t time_out = 0;
    const uint16_t timeout_limit = g_config->timeout; // Timeout value of platform

    // First from buffer of this module.
    if (len <= g_buf_len) {
        memcpy(data, g_config->buffer + g_buf_offset, len);
        g_buf_len -= len;
        g_buf_offset = g_buf_len ? g_buf_offset + len : 0;
        return len;
    }

    if (g_buf_len > 0) {
        memcpy(data, g_config->buffer + g_buf_offset, g_buf_len);
        nbBytesRcv = g_buf_len;
        len -= g_buf_len;
        g_buf_len = 0;
        g_buf_offset = 0;
    }

    while (len > 0) {
        // 1. if usb status is disconnected or unopened, exit read for device side.
        if (!g_config->is_link_ready()) {
            break;
        }

        // 2. check if data ready for usb device, if not, skip read and check timeout.
        if (g_config->is_data_ready()) {
            uint16_t available = g_config->get_byte_count();
            uint16_t packetSize = MIN(available, len);

            for (uint16_t i = 0; i < packetSize; i++) {
                data[nbBytesRcv++] = g_config->read_fifo(); // read from device fifo.
            }
            available -= packetSize;
            len -= packetSize;

            size_t to_buffer = (available < g_config->buffer_size) ? available : g_config->buffer_size;
            for (size_t i = 0; i < to_buffer; i++) {
                g_config->buffer[i] = g_config->read_fifo();
            }
            g_buf_len = to_buffer;
            g_buf_offset = 0;

            // gc gc gc gc !!!
            g_config->clear_ready();
            time_out = 0; // Timeout reset.
        } else {
            // usb link ready but no data. to check simple timeout.
            if (timeout_limit > 0) {
                time_out++;
                if (time_out >= timeout_limit) {
                    break; // exit if timeout.
                }
            } else {
                break; // no timeout. exit immediately.
            }
        }
    }

    return nbBytesRcv;
}
