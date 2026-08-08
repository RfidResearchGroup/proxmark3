#ifndef _ADC_RSSI_HW_AT91_H
#define _ADC_RSSI_HW_AT91_H

#include "at91sam7s512.h"
#include "proxmark3_arm.h"

#if defined RDV4 || defined ICOPYX
// ADC Vref = 3300mV, and an (10000k+240k):240k voltage divider on the LF input can measure voltages up to 140800 mV
#define MAX_ADC_HF_VOLTAGE 140800
#else
// ADC Vref = 3300mV, and an (10M+1M):1M voltage divider on the HF input can measure voltages up to 36300 mV
#define MAX_ADC_HF_VOLTAGE 36300
#endif
// ADC Vref = 3300mV,  (240k-10M):240k voltage divider,  140800 mV
#define MAX_ADC_LF_VOLTAGE 140800

STATIC_FORCE_INLINE void AdcRssiConversionStart(void) {
    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
}

STATIC_FORCE_INLINE bool AdcRssiDataReady(adc_rssi_ch_t ch) {
    if (ch == ADC_RSSI_CH_HF) {
        return AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ADC_CHAN_HF);
    }
    return AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ADC_CHAN_LF);
}

STATIC_FORCE_INLINE uint32_t AdcRssiDataRead(adc_rssi_ch_t ch) {
    if (ch == ADC_RSSI_CH_HF) {
        return AT91C_BASE_ADC->ADC_CDR[ADC_CHAN_HF] & 0x3FF;
    }
    return AT91C_BASE_ADC->ADC_CDR[ADC_CHAN_LF] & 0x3FF;
}

STATIC_FORCE_INLINE uint32_t AdcRssiDataToMilliVolt(uint16_t data, adc_rssi_ch_t ch) {
    if (ch == ADC_RSSI_CH_HF) {
        return ((uint32_t)data * MAX_ADC_HF_VOLTAGE) >> 10;
    }
    return ((uint32_t)data * MAX_ADC_LF_VOLTAGE) >> 10;
}

STATIC_FORCE_INLINE uint32_t AdcRssiAvgToMilliVolt(adc_rssi_ch_t ch) {
    /*
     * voltage = (sum_32 / 32) * (MAX_ADC_HF_VOLTAGE / 1024)
     *   = (sum_32 * MAX_ADC_HF_VOLTAGE) / (32 * 1024)
     *   = (sum_32 * MAX_ADC_HF_VOLTAGE) / 32768
     *   = (sum_32 * MAX_ADC_HF_VOLTAGE) >> 15
     */
    if (ch == ADC_RSSI_CH_HF) {
        return (MAX_ADC_HF_VOLTAGE * AdcRssiSum(ADC_RSSI_CH_HF, 32)) >> 15;
    }
    // Moving one bit to the right in advance is to avoid the risk of multiplication overflow.
    return (MAX_ADC_LF_VOLTAGE * (AdcRssiSum(ADC_RSSI_CH_LF, 32) >> 1)) >> 14;
}

#endif
