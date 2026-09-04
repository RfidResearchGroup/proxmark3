#include "pm3_cmd.h"
#include "ticks_apis.h"
#include "usb_cdc_apis.h"
#include "usb_read_ng.h"
#include "usb_cdc_desc.h"

#include "at32f435_437_crm.h"
#include "at32f435_437_acc.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_misc.h"
#include "usb_conf.h"
#include "usb_core.h"
#include "usbd_int.h"
#include "cdc_class.h"

static otg_core_type otg_core_struct;
static usbd_core_type *udev = &(otg_core_struct.dev);
static usbd_desc_t vp_desc;

/**
  * @brief  get device descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_descriptor(void) {
    // Must be static !!!!!!
    static usbd_desc_t device_descriptor = {
        .length = sizeof(devDescriptor),
        .descriptor = (uint8_t *) devDescriptor
    };
    return &device_descriptor;
}

/**
  * @brief  get device qualifier
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_qualifier(void) {
    return NULL;
}

/**
  * @brief  get config descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_configuration(void) {
    // Must be static !!!!!!
    static usbd_desc_t config_descriptor = {
        .length = sizeof(cfgDescriptor),
        .descriptor = (uint8_t *) cfgDescriptor
    };
    return &config_descriptor;
}

/**
  * @brief  get other speed descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_other_speed(void) {
    return NULL;
}

/**
  * @brief  get lang id descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_lang_id(void) {
    // Must be static !!!!!!
    static usbd_desc_t langid_descriptor = {
        .length = sizeof(StrLanguageCodes),
        .descriptor = (uint8_t *) StrLanguageCodes
    };
    return &langid_descriptor;
}


/**
  * @brief  get manufacturer descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_manufacturer_string(void) {
    vp_desc.length = StrManufacturer[0];
    vp_desc.descriptor = (uint8_t *) StrManufacturer;
    return &vp_desc;
}

/**
  * @brief  get product descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_product_string(void) {
    vp_desc.length = StrProduct[0];
    vp_desc.descriptor = (uint8_t *) StrProduct;
    return &vp_desc;
}

/**
  * @brief  get serial descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_serial_string(void) {
    // Must be static !!!!!!
    static usbd_desc_t serial_descriptor = {
        .length = sizeof(StrSerialNumber),
        .descriptor = (uint8_t *) StrSerialNumber
    };
    return &serial_descriptor;
}

/**
  * @brief  get interface descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_interface_string(void) {
    return NULL;
}

/**
  * @brief  get device config descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_config_string(void) {
    return NULL;
}

/**
  * @brief  get device config descriptor
  * @retval usbd_desc
  */
static usbd_desc_t *get_winusb_os_string(void) {
    vp_desc.length = StrMS_OSDescriptor[0];
    vp_desc.descriptor = (uint8_t *) StrMS_OSDescriptor;
    return &vp_desc;
}

/**
  * @brief device descriptor handler structure
  */
static usbd_desc_handler cdc_desc_handler = {
    .get_device_descriptor = get_device_descriptor,
    .get_device_qualifier = get_device_qualifier,
    .get_device_configuration = get_device_configuration,
    .get_device_other_speed = get_device_other_speed,
    .get_device_lang_id = get_device_lang_id,
    // ---
    .get_device_manufacturer_string = get_device_manufacturer_string,
    .get_device_product_string = get_device_product_string,
    .get_device_serial_string = get_device_serial_string,
    .get_device_interface_string = get_device_interface_string,
    .get_device_config_string = get_device_config_string,
    // ---
    .get_device_winusb_os_string = get_winusb_os_string,
    .get_device_winusb_os_feature = NULL,
    .get_device_winusb_os_property = NULL
};


/**
  * @brief  usb 48M clock select
  * @param  clk_s:USB_CLK_HICK, USB_CLK_HEXT
  * @retval none
  */
static void usb_clock48m_select(usb_clk48_s clk_s) {
    if (clk_s == USB_CLK_HICK) {
        /* UNUSED!!!

        crm_usb_clock_source_select(CRM_USB_CLOCK_SOURCE_HICK);

        // enable the acc calibration ready interrupt
        crm_periph_clock_enable(CRM_ACC_PERIPH_CLOCK, TRUE);

        // update the c1\c2\c3 value
        acc_write_c1(7980);
        acc_write_c2(8000);
        acc_write_c3(8020);
        #if (USB_ID == 0)
        acc_sof_select(ACC_SOF_OTG1);
        #else
        acc_sof_select(ACC_SOF_OTG2);
        #endif
        // open acc calibration
        acc_calibration_mode_enable(ACC_CAL_HICKTRIM, TRUE);

        */
    } else {
        switch (system_core_clock) {
            /* 48MHz */
            case 48000000:
                crm_usb_clock_div_set(CRM_USB_DIV_1);
                break;

            /* 72MHz */
            case 72000000:
                crm_usb_clock_div_set(CRM_USB_DIV_1_5);
                break;

            /* 96MHz */
            case 96000000:
                crm_usb_clock_div_set(CRM_USB_DIV_2);
                break;

            /* 120MHz */
            case 120000000:
                crm_usb_clock_div_set(CRM_USB_DIV_2_5);
                break;

            /* 144MHz */
            case 144000000:
                crm_usb_clock_div_set(CRM_USB_DIV_3);
                break;

            /* 168MHz */
            case 168000000:
                crm_usb_clock_div_set(CRM_USB_DIV_3_5);
                break;

            /* 192MHz */
            case 192000000:
                crm_usb_clock_div_set(CRM_USB_DIV_4);
                break;

            /* 216MHz */
            case 216000000:
                crm_usb_clock_div_set(CRM_USB_DIV_4_5);
                break;

            /* 240MHz */
            case 240000000:
                crm_usb_clock_div_set(CRM_USB_DIV_5);
                break;

            /* 264MHz */
            case 264000000:
                crm_usb_clock_div_set(CRM_USB_DIV_5_5);
                break;

            /* 288MHz */
            case 288000000:
                crm_usb_clock_div_set(CRM_USB_DIV_6);
                break;

            default:
                break;
        }
    }
}

/**
  * @brief  this function config gpio.
  * @retval none
  */
static void usb_gpio_config(void) {
    gpio_init_type gpio_init_struct;

    crm_periph_clock_enable(OTG_PIN_GPIO_CLOCK, TRUE);
    gpio_default_para_init(&gpio_init_struct);

    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;

    /* dp and dm */
    gpio_init_struct.gpio_pins = OTG_PIN_DP | OTG_PIN_DM;
    gpio_init(OTG_PIN_GPIO, &gpio_init_struct);

    gpio_pin_mux_config(OTG_PIN_GPIO, OTG_PIN_DP_SOURCE, OTG_PIN_MUX);
    gpio_pin_mux_config(OTG_PIN_GPIO, OTG_PIN_DM_SOURCE, OTG_PIN_MUX);

#ifdef USB_SOF_OUTPUT_ENABLE
    crm_periph_clock_enable(OTG_PIN_SOF_GPIO_CLOCK, TRUE);
    gpio_init_struct.gpio_pins = OTG_PIN_SOF;
    gpio_init(OTG_PIN_SOF_GPIO, &gpio_init_struct);
    gpio_pin_mux_config(OTG_PIN_SOF_GPIO, OTG_PIN_SOF_SOURCE, OTG_PIN_MUX);
#endif

    /* otgfs use vbus pin */
#ifndef USB_VBUS_IGNORE
    gpio_init_struct.gpio_pins = OTG_PIN_VBUS;
    gpio_init_struct.gpio_pull = GPIO_PULL_DOWN;
    gpio_pin_mux_config(OTG_PIN_GPIO, OTG_PIN_VBUS_SOURCE, OTG_PIN_MUX);
    gpio_init(OTG_PIN_GPIO, &gpio_init_struct);
#endif
}

// predefine, resolve compiler warning.
void OTG_IRQ_HANDLER(void);

/**
  * @brief  this function handles otgfs interrupt.
  * @retval none
  */
void OTG_IRQ_HANDLER(void) {
    usbd_irq_handler(&otg_core_struct);
}

/**
  * @brief  usb delay millisecond function.
  * @param  ms: number of millisecond delay
  * @retval none
  */
void usb_delay_ms(uint32_t ms) {
    // Did not use !!!! ANY delay if bootrom unsupported !!!! see: ticks.h -> AS_BOOTROM macro
    SpinDelayUs(ms * 1000);
}

// unused, don't need to implement.
// /**
//   * @brief  usb delay microsecond function.
//   * @param  us: number of microsecond delay
//   * @retval none
//   */
// void usb_delay_us(uint32_t us) {
//     delay_us(us);
// }

#ifndef AS_BOOTROM

static uint8_t usb_read_ng_buffer[64] = {0};
static uint8_t usb_read_ng_fifo_pos = 0;

// Implemented for read_ng
static bool usb_read_ng_link_ready(void) {
    return usb_check(); // reuse 'usb_check()'
}

// Implemented for read_ng
static bool usb_read_ng_data_ready(void) {
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    return pcdc->g_rx_completed;
}

// Implemented for read_ng
static uint16_t usb_read_ng_data_available(void) {
    return usb_available_length();
}

// Implemented for read_ng
static uint8_t usb_read_ng_data_read(void) {
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    return pcdc->g_rx_buff[usb_read_ng_fifo_pos++];
}

// Implemented for read_ng
static void usb_read_ng_clear(void) {
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    // When receiving data from USB device is completed, the flag bit of receiving completion must be cleared,
    //  otherwise, it will enter the endless cycle of receiving completion and may repeatedly execute an instruction.
    pcdc->g_rx_completed = 0;
    // usb_read_ng_data_read() will increment position when read, so we need reset on read finished.
    //  if reset forgot, usb_read_ng_data_read() will read wrong data(cause by overflow).
    usb_read_ng_fifo_pos = 0;
    // receive enable
    usbd_ept_recv(udev, USBD_CDC_BULK_OUT_EPT, pcdc->g_rx_buff, USBD_CDC_OUT_MAXPACKET_SIZE);
}

// Instance for 'read_ng' apis
static const usb_read_ng_config_t g_usb_read_ng_config = {
    .is_link_ready = usb_read_ng_link_ready,
    .is_data_ready = usb_read_ng_data_ready,
    .get_byte_count = usb_read_ng_data_available,
    .read_fifo = usb_read_ng_data_read,
    .clear_ready = usb_read_ng_clear,
    .buffer = usb_read_ng_buffer,
    .buffer_size = sizeof(usb_read_ng_buffer),
    .timeout = 0x1FFF
};
#endif

/**
 * This function Activates the USB device
 */
void usb_enable(void) {
    usb_gpio_config();

    crm_periph_clock_enable(OTG_CLOCK, TRUE); // enable otgfs clock
    usb_clock48m_select(USB_CLK_HEXT); // select usb 48m clcok source
    nvic_irq_enable(OTG_IRQ, 0, 0); // enable otgfs irq
    usbd_init(&otg_core_struct, USB_FULL_SPEED_CORE_ID, USB_ID, &cdc_class_handler, &cdc_desc_handler); // init usb

#ifndef AS_BOOTROM
    usb_read_ng_init(&g_usb_read_ng_config);
#endif
}

/**
 * This function deactivates the USB device
 */
void usb_disable(void) {
    nvic_irq_disable(OTG_IRQ); // disable otgfs irq
    NVIC_ClearPendingIRQ(OTG_IRQ); // clear otgfs irq if pedding
    crm_periph_clock_enable(OTG_CLOCK, FALSE); // disable otgfs clock
}

/**
 * Test if the device is configured and handle enumeration
 * @return true if configured, otherwise fasle.
 */
bool usb_check(void) {
    return udev->conn_state == USB_CONN_STATE_CONFIGURED;
}

/**
 * Test if the device link ok and data received.
 * @return true if link ok and data received, otherwise fasle.
 */
bool usb_poll(void) {
    if (usb_check() == false) {
        return false;
    }
    // g_rx_completed will set to 1 when irq event: USB_OTG_DOEPINT_XFERC_FLAG
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    return pcdc->g_rx_completed;
}

/**
 *  Get data received length of out endpoint.
 * @return data length, if no data received, return 0.
 */
uint16_t usb_available_length(void) {
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    // Only when g_rx_completed is set, the g_rxlen is valid, otherwise, it may be 0 or invalid.
    if (pcdc->g_rx_completed) {
        return pcdc->g_rxlen;
    }
    return 0;
}

/**
 * Test if the device link ok and data received.
 *   note: this function will check data length > 0
 * @return
 */
bool usb_poll_validate_length(void) {
    if (usb_poll() == false) {
        return false;
    }
    return usb_available_length() > 0;
}

/**
 * Read available data from Endpoint 1 OUT (host to device, blocking read.)
 * @param data the data buffer read into.
 * @param len the max length of data.
 * @return
 */
uint32_t usb_read(uint8_t *data, size_t len) {
    if (len == 0) return 0; // invalid length

    uint16_t nbBytesRcv = 0;
    uint16_t time_out = 0;
    uint16_t packetSize = 0;

    while (len) {
        if (usb_check() == false) {
            break;
        }

        // example: 150bytes receive from HOST
        //  OUT endpoint buffer size is 64.
        // so, usb controller will split to 3 packet for send.
        // 1. 64 -> packetSize(64) = usb_vcp_get_rxdata(udev, data + nbBytesRcv(0), len(150));
        // 2. 64 -> packetSize(64) = usb_vcp_get_rxdata(udev, data + nbBytesRcv(64), len(86));
        // 3. 22 -> packetSize(22) = usb_vcp_get_rxdata(udev, data + nbBytesRcv(128), len(22));
        // after the third time received, the len -= 22 get 0. loop end.

        packetSize = usb_vcp_get_rxdata(udev, data + nbBytesRcv, len);
        if (packetSize != 0) {
            len -= packetSize;
            nbBytesRcv += packetSize;
        }

        // simple timeout.
        if (time_out++ == 0x1FFF) {
            break;
        }
    }

    return nbBytesRcv;
}

/**
 * Send through endpoint 2 (device to host, blocking write.)
 * @param data the data will send
 * @param len the data length
 * @return result value
 */
int usb_write(const uint8_t *data, const size_t len) {
    if (len == 0) {
        return PM3_EINVARG;
    }

    if (usb_check() == false) {
        return PM3_EIO;
    }

    // 'usb_vcp_send_data()' will auto split packet.
    if (usb_vcp_send_data(udev, (uint8_t *) data, len) != SUCCESS) {
        return PM3_EIO;
    }

    // wait for send complete
    cdc_struct_type *pcdc = (cdc_struct_type *)(udev->class_handler->pdata);
    while (pcdc->g_tx_completed != 1) {
        if (usb_check() == false) {
            return PM3_EIO;
        }
        // working for send to HOST...
        //  Have a cup of tea?
    }

    return PM3_SUCCESS;
}

// --------------------------------- ASYNC WRITE APIS ---------------------------------

static uint8_t async_write_buffer[2][USBD_CDC_IN_MAXPACKET_SIZE]; // double buffer, like at91 double bank.
static uint8_t async_write_buf_select = 0;
static uint8_t async_write_index = 0;

/**
 * Check is write data finished.
 * @return
 */
static uint8_t is_write_completed(otg_eptin_type *ept_in) {
    if (ept_in->dieptsiz_bit.xfersize != 0) {
        return FALSE;
    }
    return TRUE;
}

/**
 * Start the buffer write, wait for last send finished and flush fifo.
 * @return error status
 */
int async_usb_write_start(void) {
    otg_eptin_type *ept_in = USB_INEPT(udev->usb_reg, (USBD_CDC_BULK_IN_EPT & 0x7F));
    otg_device_type *dev = OTG_DEVICE(udev->usb_reg);

    // check usb state
    if (!usb_check()) return PM3_EIO;

    // wait for tx end if working...
    while (!is_write_completed(ept_in)) if (!usb_check()) return PM3_EIO;

    // disable fifo empty irq.
    dev->diepempmsk &= ~(1 << (USBD_CDC_BULK_IN_EPT & 0x7F));
    // check fifo status before async write.
    usbd_ept_in_check_fifo(udev, USBD_CDC_BULK_IN_EPT & 0x7F);

    // reset flag
    async_write_buf_select = 0;
    async_write_index = 0;

    // AT32 和 CH32 的USB功能区别挺大，注意不要陷入惯性思维的陷阱。
    //  对于AT32，需要先设置端点控制寄存器中的传输长度和包数目位，并使能端点来传输数据。最后然后再去写FIFO
    //  对于CH32，需要先写入BUFF，然后再设置传输长度，最后再使能发送和ACK。

    return PM3_SUCCESS;
}

/**
 * Push 1 byte data to usb fifo, but no send start.
 * @param b the byte will push to usb fifo
 */
void async_usb_write_pushByte(uint8_t b) {
    if (async_write_index >= USBD_CDC_IN_MAXPACKET_SIZE) {
        return; // !!! WARN !!! Can't to here, will memory overflow.
    }
    async_write_buffer[async_write_buf_select][async_write_index] = b;
    async_write_index++;
}

/**
 * Flush the send buffer, next IN event will trans to HOST
 */
bool async_usb_write_requestWrite(void) {
    // get reg
    otg_eptin_type *ept_in = USB_INEPT(udev->usb_reg, (USBD_CDC_BULK_IN_EPT & 0x7F));

    // check last transmit is finish? cond: trans remain length not 0 or fifo have data.
    if (!is_write_completed(ept_in)) return FALSE;

    // set transfer length and packet count.
    ept_in->dieptsiz_bit.xfersize = async_write_index;
    ept_in->dieptsiz_bit.pktcnt = 1;
    // dieptsiz_bit register must set before 'eptena' set. it will lock after 'eptena' = TRUE
    // clear endpoint nak
    ept_in->diepctl_bit.cnak = TRUE;
    // IN endpoint enable
    ept_in->diepctl_bit.eptena = TRUE;

    // write data to fifo.
    usb_write_packet(
        udev->usb_reg,
        async_write_buffer[async_write_buf_select],
        USBD_CDC_BULK_IN_EPT & 0x7F,
        async_write_index
    );
    async_write_buf_select = ~async_write_buf_select; // after data write, we can change buffer, 0 or 1
    async_write_index = 0; // don't forget reset write index, next write will write to other buffer and from 0 start.

    return TRUE;
}

/**
 * Stop send and wait finish.
 * @return SUCCESS if send stop success, otherwise ERROR
 */
int async_usb_write_stop(void) {
    otg_eptin_type *ept_in = USB_INEPT(udev->usb_reg, (USBD_CDC_BULK_IN_EPT & 0x7F));

    // Wait for the end of transfer
    while (!is_write_completed(ept_in)) if (!usb_check()) return PM3_EIO;

    // still have data on local buffer, we need send before write stop.
    if (async_write_index != 0) {
        if (!async_usb_write_requestWrite()) {
            return PM3_EIO;
        }
    }

    // Wait for the end of fifo flush transfer.
    while (!is_write_completed(ept_in)) if (!usb_check()) return PM3_EIO;

    return PM3_SUCCESS;
}

/**
 * Get endpoint buffer size.
 */
void usb_get_ep_size(uint32_t *epCtl, uint32_t *epIn, uint32_t *epOut) {
    if (epCtl) *epCtl = USBD_CDC_CMD_MAXPACKET_SIZE;
    if (epIn) *epIn = USBD_CDC_IN_MAXPACKET_SIZE;
    if (epOut) *epOut = USBD_CDC_OUT_MAXPACKET_SIZE;
}
