#include "rssi_apis.h"

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to sum up a number of samples and
// return that.
//-----------------------------------------------------------------------------
static uint32_t ReadAdc(adc_rssi_ch_t ch) {
    AdcSetupRssiChannel(ch);
    while (!AdcRssiDataReady(ch)) {};
    return AdcRssiDataRead(ch);
}

// Collect 32 times and calculate the average value
uint32_t AdcRssiAvg(adc_rssi_ch_t ch) {
    return AdcRssiSum(ch, 32) >> 5; // == /32
}

// Sample the specified RF field voltage N times, note that it cannot exceed 255 times.
uint32_t AdcRssiSum(adc_rssi_ch_t ch, uint8_t NbSamples) {
    uint32_t a = 0;
    for (uint8_t i = 0; i < NbSamples; i++)
        a += ReadAdc(ch);
    return (a + (NbSamples >> 1) - 1);
}
