#include "fpga_apis.h"
#include "gpio_apis.h"
#include "fpga_loader.h"
#include "fpga.h"
#include "dbprint.h"
#include "util.h"
#include "BigBuf.h"
#include "appmain.h"

bool FpgaIs16BitMsbMode(uint16_t fpga_mode) {
    if (((fpga_mode & FPGA_MAJOR_MODE_MASK) == FPGA_MAJOR_MODE_HF_READER) &&
            (FpgaGetCurrent() == FPGA_BITSTREAM_HF || FpgaGetCurrent() == FPGA_BITSTREAM_HF_15)) {
        return true;
    }
    return false;
}

void FpgaWriteConfWord(uint16_t v) {
    const int current = FpgaGetCurrent();

    // Keep track of whether or not we should be monitoring the HF field timeout
    if (current == FPGA_BITSTREAM_HF || current == FPGA_BITSTREAM_HF_15 || current == FPGA_BITSTREAM_HF_FELICA) {
        const uint16_t major = v & FPGA_MAJOR_MODE_MASK;
        const uint16_t minor = v & FPGA_MINOR_MODE_MASK;

        switch (major) {
            case FPGA_MAJOR_MODE_HF_READER:
                g_hf_field_timeout_active = true;
                break;
            case FPGA_MAJOR_MODE_HF_ISO14443A:
                g_hf_field_timeout_active = (minor == FPGA_HF_ISO14443A_READER_LISTEN || minor == FPGA_HF_ISO14443A_READER_MOD);
                break;
            case FPGA_MAJOR_MODE_HF_ISO18092:
                g_hf_field_timeout_active = (minor & FPGA_HF_ISO18092_FLAG_READER) != 0;
                break;
            default:
                g_hf_field_timeout_active = false;
                break;
        }
    } else {
        g_hf_field_timeout_active = false;
    }

    FpgaSendCommand(FPGA_CMD_SET_CONFREG, v);
}

void FpgaEnableTracing(void) {
    FpgaSendCommand(FPGA_CMD_TRACE_ENABLE, 1);
}

void FpgaDisableTracing(void) {
    FpgaSendCommand(FPGA_CMD_TRACE_ENABLE, 0);
}

void SetAdcMuxFor(adc_mux_io_t muxTo) {

#ifdef PM5 // fpga_switch pin resue to switch adc mux.
    if ((muxTo == ADC_MUXSEL_LORAW) || (muxTo == ADC_MUXSEL_HIRAW))
        return;

    gpio_adc_mux_setup();

    if (muxTo == ADC_MUXSEL_HIPKD) {
        Gpio_FPGA_SWITCH_High();
    } else {
        Gpio_FPGA_SWITCH_Low();
    }
    return;
#endif

#ifndef WITH_FPC_USART

    gpio_adc_mux_setup();

    Gpio_MUXSEL_HIPKD_Low();
    Gpio_MUXSEL_LOPKD_Low();
    Gpio_MUXSEL_HIRAW_Low();
    Gpio_MUXSEL_LORAW_Low();

    switch (muxTo) {
        case ADC_MUXSEL_HIPKD:
            Gpio_MUXSEL_HIPKD_High();
            break;
        case ADC_MUXSEL_LOPKD:
            Gpio_MUXSEL_LOPKD_High();
            break;
        case ADC_MUXSEL_HIRAW:
            Gpio_MUXSEL_HIRAW_High();
            break;
        case ADC_MUXSEL_LORAW:
            Gpio_MUXSEL_LORAW_High();
            break;
    }

#else
    if ((muxTo == ADC_MUXSEL_LORAW) || (muxTo == ADC_MUXSEL_HIRAW))
        return;

    gpio_adc_mux_setup();

    Gpio_MUXSEL_HIPKD_Low();
    Gpio_MUXSEL_LOPKD_Low();

    if (muxTo == ADC_MUXSEL_HIPKD) {
        Gpio_MUXSEL_HIPKD_High();
    }
    if (muxTo == ADC_MUXSEL_LOPKD) {
        Gpio_MUXSEL_LOPKD_High();
    }
#endif

}

// Turns off the antenna,
// log message
// if HF,  Disable SSC DMA
// turn off trace and leds off.
void switch_off(void) {
    if (g_dbglevel > DBG_DEBUG) {
        Dbprintf("switch_off");
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    if (FpgaGetCurrent() == FPGA_BITSTREAM_HF || FpgaGetCurrent() == FPGA_BITSTREAM_HF_15) {
        FPGA_SSC_DMA_RX_Disable();
    }

    set_tracing(false);
    LEDsoff();
}
