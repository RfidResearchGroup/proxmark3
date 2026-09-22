#ifndef ADC_RSSI_HW_AT32_H
#define ADC_RSSI_HW_AT32_H

#include "at32f435_437_adc.h"
#include "at32f435_437_crm.h"

#define AT32_RSSI_ADC_PERIPH_CLK       CRM_ADC1_PERIPH_CLOCK
#define AT32_RSSI_ADC                  ADC1
#define AT32_RSSI_ADC_LF_CHANNEL       ADC_CHANNEL_10 // ADC123_IN10
#define AT32_RSSI_ADC_HF_CHANNEL       ADC_CHANNEL_11 // ADC123_IN11

/**
 * Save the reference voltage values collected each time the AdcSetupRssiChannel() function is called.
 */
extern uint16_t g_adc_vref_value;

STATIC_FORCE_INLINE void AdcRssiConversionStart(void) {
    adc_ordinary_software_trigger_enable(AT32_RSSI_ADC, TRUE);
}

STATIC_FORCE_INLINE bool AdcRssiDataReady(adc_rssi_ch_t ch) {
    return adc_flag_get(AT32_RSSI_ADC, ADC_OCCE_FLAG);
}

STATIC_FORCE_INLINE uint32_t AdcRssiDataRead(adc_rssi_ch_t ch) {
    return adc_ordinary_conversion_data_get(AT32_RSSI_ADC);
}

STATIC_FORCE_INLINE uint32_t AdcRssiDataToMilliVolt(uint16_t data, adc_rssi_ch_t ch) {
    // Analog input voltage (Vin) = (ADC digital value × reference voltage) / full-scale digital value
    // Voltage division ratio: LF = 46.45，HF = 31.3
    if (ch == ADC_RSSI_CH_HF) {
        // VIN = DATA * 1200 / g_adc_vref_value * 31.3
        return ((data * 1200) / g_adc_vref_value) * 313 / 10; // = *31.3
    }
    // VIN = DATA * 1200 / g_adc_vref_value * 46.45
    return ((data * 1200) / g_adc_vref_value) * 4645 / 100; // = *46.45
}

STATIC_FORCE_INLINE uint32_t AdcRssiAvgToMilliVolt(adc_rssi_ch_t ch) {
    return AdcRssiDataToMilliVolt(AdcRssiAvg(ch), ch);
}

STATIC_FORCE_INLINE void AdcRssiSetupFast(adc_rssi_ch_t ch) {
    // Full init first, it also does the calibration and the vref read, then
    // drop the sample time from 640.5 cycles to 47.5. At ADCCLK = HCLK/10 that
    // takes a conversion from ~23 us to ~2 us. The high impedance divider does
    // not settle in that time, so the reading is a fraction of the true
    // voltage -- fine for the shape of a transient.
    AdcSetupRssiChannel(ch);

    if (ch == ADC_RSSI_CH_HF) {
        adc_ordinary_channel_set(AT32_RSSI_ADC, AT32_RSSI_ADC_HF_CHANNEL, 1, ADC_SAMPLETIME_47_5);
    } else {
        adc_ordinary_channel_set(AT32_RSSI_ADC, AT32_RSSI_ADC_LF_CHANNEL, 1, ADC_SAMPLETIME_47_5);
    }
}

STATIC_FORCE_INLINE uint16_t AdcRssiReadFast(adc_rssi_ch_t ch) {
    AdcRssiConversionStart();
    while (adc_flag_get(AT32_RSSI_ADC, ADC_OCCE_FLAG) == RESET) {};
    uint32_t mv = AdcRssiDataToMilliVolt(adc_ordinary_conversion_data_get(AT32_RSSI_ADC), ch);
    return (mv > UINT16_MAX) ? UINT16_MAX : (uint16_t)mv;
}

#endif // ADC_RSSI_HW_AT32_H
