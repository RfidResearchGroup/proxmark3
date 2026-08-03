if (PM5 AND NOT TARGET pm5_at32_armlib)
    add_library(pm5_at32_armlib STATIC
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/cmsis/cm4/device_support/system_at32f435_437.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_crm.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_misc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_gpio.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_usb.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_qspi.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_tmr.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_ertc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_pwc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_spi.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_i2c.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_dma.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_adc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_usart.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_exint.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_scfg.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_crc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_wdt.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_wwdt.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_can.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_dac.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_debug.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_dvp.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_edma.c
        # ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_emac.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_sdio.c
        # ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_xmc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/src/at32f435_437_acc.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usb_drivers/src/usb_core.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usb_drivers/src/usbd_core.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usb_drivers/src/usbd_int.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usb_drivers/src/usbd_sdr.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usbd_class/cdc/cdc_class.c
        ${CMAKE_CURRENT_LIST_DIR}/at32_i2c/at32f435_437_i2c_app.c
    )

    target_compile_options(pm5_at32_armlib
        PRIVATE ${CROSS_CFLAGS}
        PUBLIC -mcpu=cortex-m4 -Wno-missing-prototypes -Wno-missing-declarations
    )
    target_compile_definitions(pm5_at32_armlib PUBLIC
        PM5
        AT32F435RGT7
        USE_STDPERIPH_DRIVER
        AT_START_F435_V1
        CRM_MODULE_ENABLED
        MISC_MODULE_ENABLED
        GPIO_MODULE_ENABLED
        USB_MODULE_ENABLED
        QSPI_MODULE_ENABLED
        TMR_MODULE_ENABLED
        ERTC_MODULE_ENABLED
        PWC_MODULE_ENABLED
        SPI_MODULE_ENABLED
        I2C_MODULE_ENABLED
        DMA_MODULE_ENABLED
        ADC_MODULE_ENABLED
        USART_MODULE_ENABLED
        EXINT_MODULE_ENABLED
        SCFG_MODULE_ENABLED
        FLASH_MODULE_ENABLED
        CRC_MODULE_ENABLED
        WDT_MODULE_ENABLED
        WWDT_MODULE_ENABLED
        CAN_MODULE_ENABLED
        DAC_MODULE_ENABLED
        DEBUG_MODULE_ENABLED
        DVP_MODULE_ENABLED
        EDMA_MODULE_ENABLED
        # EMAC_MODULE_ENABLED
        SDIO_MODULE_ENABLED
        # XMC_MODULE_ENABLED
        ACC_MODULE_ENABLED
        USBD_SUPPORT_WINUSB=1
    )
    target_include_directories(pm5_at32_armlib PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/cmsis/cm4/core_support
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/cmsis/cm4/device_support
        ${CMAKE_CURRENT_LIST_DIR}/at32_sys/drivers/inc
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usb_drivers/inc
        ${CMAKE_CURRENT_LIST_DIR}/at32_usb/usbd_class/cdc
        ${CMAKE_CURRENT_LIST_DIR}/at32_i2c
    )
    set_property(TARGET pm5_at32_armlib PROPERTY POSITION_INDEPENDENT_CODE ON)
endif ()
