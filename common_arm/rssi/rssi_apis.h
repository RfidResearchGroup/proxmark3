#ifndef RSSI_APIS_H_
#define RSSI_APIS_H_

#include "common.h"

typedef enum {
    ADC_RSSI_CH_HF,
    ADC_RSSI_CH_LF,
} adc_rssi_ch_t;

void AdcSetupRssiChannel(adc_rssi_ch_t ch);
uint32_t AdcRssiAvg(adc_rssi_ch_t ch);
uint32_t AdcRssiSum(adc_rssi_ch_t ch, uint8_t NbSamples);

STATIC_FORCE_INLINE void AdcRssiConversionStart(void);
STATIC_FORCE_INLINE bool AdcRssiDataReady(adc_rssi_ch_t ch);
STATIC_FORCE_INLINE uint32_t AdcRssiDataRead(adc_rssi_ch_t ch);

//-----------------------------------------------------------------------------
// Function for converting ADC values to millivolt units(cross platforms)
// The ADC sampling results for each platform have different values in millivolts.
// Warn: please use this function for cross platform compatibility.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE uint32_t AdcRssiDataToMilliVolt(uint16_t data, adc_rssi_ch_t ch);

//-----------------------------------------------------------------------------
// After collecting N times, calculate the average value and convert it to millivolts.
// This function calls the AdcRssiSum() function internally, so you don't need to call the setup function in advance.
// And the conversion result is the RSSI value in millivolts, dont need considering compatibility issues for cross platform conversion.
// Warn: please try to call this function as much as possible!
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE uint32_t AdcRssiAvgToMilliVolt(adc_rssi_ch_t ch);

//-----------------------------------------------------------------------------
// Fast burst sampling, for capturing the shape of a transient rather than a
// steady level. A short sample-and-hold against the high impedance divider
// reads only a fraction of the true voltage, so these values are good for
// relative shape and not for absolute measurement.
// Call AdcRssiSetupFast() once, then AdcRssiReadFast() per sample.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE void AdcRssiSetupFast(adc_rssi_ch_t ch);
STATIC_FORCE_INLINE uint16_t AdcRssiReadFast(adc_rssi_ch_t ch);

#ifdef PM5
#include "rssi_hw_at32.h"
#else
#include "rssi_hw_at91.h"
#endif

#endif // RSSI_APIS_H_
