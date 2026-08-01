#include "stdio.h"
#include "usbd_core.h"
#include "usb_cdc_desc.h"


static usbd_desc_t *get_device_descriptor(void);

static usbd_desc_t *get_device_qualifier(void);

static usbd_desc_t *get_device_configuration(void);

static usbd_desc_t *get_device_other_speed(void);

static usbd_desc_t *get_device_lang_id(void);

static usbd_desc_t *get_device_manufacturer_string(void);

static usbd_desc_t *get_device_product_string(void);

static usbd_desc_t *get_device_serial_string(void);

static usbd_desc_t *get_device_interface_string(void);

static usbd_desc_t *get_device_config_string(void);

static usbd_desc_t *get_winusb_os_string(void);

/**
  * @brief device descriptor handler structure
  */
usbd_desc_handler cdc_desc_handler =
{
    get_device_descriptor,
    get_device_qualifier,
    get_device_configuration,
    get_device_other_speed,
    get_device_lang_id,
    // ---
    get_device_manufacturer_string,
    get_device_product_string,
    get_device_serial_string,
    get_device_interface_string,
    get_device_config_string,
    // ---
    get_winusb_os_string,
    NULL,
    NULL
};


/* device descriptor */
static usbd_desc_t device_descriptor =
{
    sizeof(devDescriptor),
    (uint8_t *) devDescriptor
};

/* config descriptor */
static usbd_desc_t config_descriptor =
{
    sizeof(cfgDescriptor),
    (uint8_t *) cfgDescriptor
};

/* langid descriptor */
static usbd_desc_t langid_descriptor =
{
    sizeof(StrLanguageCodes),
    (uint8_t *) StrLanguageCodes
};

/* serial descriptor */
static usbd_desc_t serial_descriptor =
{
    sizeof(StrSerialNumber),
    (uint8_t *) StrSerialNumber
};

static usbd_desc_t vp_desc;

/**
  * @brief  get device descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_descriptor(void) {
    return &device_descriptor;
}

/**
  * @brief  get device qualifier
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_qualifier(void) {
    return NULL;
}

/**
  * @brief  get config descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_configuration(void) {
    return &config_descriptor;
}

/**
  * @brief  get other speed descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_other_speed(void) {
    return NULL;
}

/**
  * @brief  get lang id descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_lang_id(void) {
    return &langid_descriptor;
}


/**
  * @brief  get manufacturer descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_manufacturer_string(void) {
    vp_desc.length = StrManufacturer[0];
    vp_desc.descriptor = (uint8_t *) StrManufacturer;
    return &vp_desc;
}

/**
  * @brief  get product descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_product_string(void) {
    vp_desc.length = StrProduct[0];
    vp_desc.descriptor = (uint8_t *) StrProduct;
    return &vp_desc;
}

/**
  * @brief  get serial descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_serial_string(void) {
    return &serial_descriptor;
}

/**
  * @brief  get interface descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_interface_string(void) {
    return NULL;
}

/**
  * @brief  get device config descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_device_config_string(void) {
    return NULL;
}

/**
  * @brief  get device config descriptor
  * @param  none
  * @retval usbd_desc
  */
static usbd_desc_t *get_winusb_os_string(void) {
    vp_desc.length = StrMS_OSDescriptor[0];
    vp_desc.descriptor = (uint8_t *) StrMS_OSDescriptor;
    return &vp_desc;
}
