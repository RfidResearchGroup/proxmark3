#include "rssi_apis.h"
#include "config_gpio.h"

uint16_t g_adc_vref_value;

/**
  * @brief  gpio configuration.
  * Note: view the 'Datasheet' not 'Reference Manual' for pin maping get.
  */
static void gpio_config(void) {
    gpio_init_type gpio_initstructure;
    gpio_default_para_init(&gpio_initstructure);
    crm_periph_clock_enable(AT32_GPIO_ADC_RSSI_CLK, TRUE);
    // config adc pin as analog input mode
    gpio_initstructure.gpio_mode = GPIO_MODE_ANALOG;
    gpio_initstructure.gpio_pins = AT32_GPIO_ADC_RSSI_LF_PIN | AT32_GPIO_ADC_RSSI_HF_PIN;
    gpio_init(AT32_GPIO_ADC_RSSI, &gpio_initstructure);
}

void AdcSetupRssiChannel(adc_rssi_ch_t ch) {
    adc_common_config_type adc_common_struct;
    adc_base_config_type adc_base_struct;

    adc_common_default_para_init(&adc_common_struct);
    crm_periph_clock_enable(AT32_RSSI_ADC_PERIPH_CLK, TRUE);
    gpio_config();
    adc_reset();

    adc_common_struct.combine_mode = ADC_INDEPENDENT_MODE; // config combine mode
    adc_common_struct.div = ADC_HCLK_DIV_10; // config division,adcclk is division by hclk
    adc_common_struct.common_dma_mode = ADC_COMMON_DMAMODE_DISABLE; // config common dma mode,it's not useful in independent mode
    adc_common_struct.common_dma_request_repeat_state = FALSE; // config common dma request repeat
    adc_common_struct.sampling_interval = ADC_SAMPLING_INTERVAL_5CYCLES; // config adjacent adc sampling interval,it's useful for ordinary shifting mode
    adc_common_struct.tempervintrv_state = TRUE; // config inner temperature sensor and vintrv, connect to ADC1_IN16 & ADC1_IN17, we need to detect vref

    /* config voltage battery */
    adc_common_struct.vbat_state = FALSE;
    adc_common_config(&adc_common_struct);

    adc_base_default_para_init(&adc_base_struct);
    adc_base_struct.sequence_mode = FALSE; // Disable sequence mode, acquire a channel once.
    adc_base_struct.repeat_mode = FALSE;
    adc_base_struct.data_align = ADC_RIGHT_ALIGNMENT;
    adc_base_struct.ordinary_channel_length = 1;
    adc_base_config(AT32_RSSI_ADC, &adc_base_struct);
    adc_resolution_set(AT32_RSSI_ADC, ADC_RESOLUTION_12B);

    // adc_ordinary_conversion_trigger_set(AT32_RSSI_RSSI_ADC, ADC_ORDINARY_TRIG_TMR1CH1, ADC_ORDINARY_TRIG_EDGE_NONE); // config ordinary trigger source and trigger edge
    adc_dma_mode_enable(AT32_RSSI_ADC, FALSE); // config dma mode,it's not useful when common dma mode is use
    adc_dma_request_repeat_enable(AT32_RSSI_ADC, FALSE); // config dma request repeat,it's not useful when common dma mode is use
    adc_occe_each_conversion_enable(AT32_RSSI_ADC, TRUE); // each ordinary channel conversion set occe flag
    adc_interrupt_enable(AT32_RSSI_ADC, ADC_OCCO_INT, FALSE); // disable adc overflow interrupt

    // adc enable and wait ready
    adc_enable(AT32_RSSI_ADC, TRUE);
    while (adc_flag_get(AT32_RSSI_ADC, ADC_RDY_FLAG) == RESET);

    // adc calibration and wait finish
    adc_calibration_init(AT32_RSSI_ADC);
    while (adc_calibration_init_status_get(AT32_RSSI_ADC));
    adc_calibration_start(AT32_RSSI_ADC);
    while (adc_calibration_status_get(AT32_RSSI_ADC));

    // get vref value, ADC_CHANNEL_17 is fixed, don't change!!!
    adc_ordinary_channel_set(AT32_RSSI_ADC, ADC_CHANNEL_17, 1, ADC_SAMPLETIME_640_5);
    AdcRssiConversionStart();
    while (adc_flag_get(AT32_RSSI_ADC, ADC_OCCE_FLAG) == RESET); // Waiting for adc conversion done.
    // printf("vref_value = %f V\r\n", ((double)1.2 * 4095) / adc1_ordinary_value);
    g_adc_vref_value = adc_ordinary_conversion_data_get(AT32_RSSI_ADC);

    // config ordinary channel and start first time conversion.
    if (ch == ADC_RSSI_CH_HF) {
        adc_ordinary_channel_set(AT32_RSSI_ADC, AT32_RSSI_ADC_HF_CHANNEL, 1, ADC_SAMPLETIME_640_5);
    } else {
        adc_ordinary_channel_set(AT32_RSSI_ADC, AT32_RSSI_ADC_LF_CHANNEL, 1, ADC_SAMPLETIME_640_5);
    }
    AdcRssiConversionStart();
}
