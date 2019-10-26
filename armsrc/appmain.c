//-----------------------------------------------------------------------------
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main application code. This is the first thing called after start.c
// executes.
//-----------------------------------------------------------------------------
#include "appmain.h"

#include "clocks.h"
#include "usb_cdc.h"
#include "proxmark3_arm.h"
#include "dbprint.h"
#include "pmflash.h"
#include "fpga.h"
#include "fpgaloader.h"
#include "string.h"
#include "legicrf.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "iso14443b.h"
#include "iso15693.h"
#include "thinfilm.h"
#include "felica.h"
#include "hitag2.h"
#include "hitagS.h"
#include "iclass.h"
#include "legicrfsim.h"
#include "epa.h"
#include "hfsnoop.h"
#include "lfops.h"
#include "lfsampling.h"
#include "mifarecmd.h"
#include "mifaredesfire.h"
#include "mifaresim.h"
#include "pcf7931.h"
#include "Standalone/standalone.h"
#include "util.h"
#include "ticks.h"

#ifdef WITH_LCD
#include "LCD.h"
#endif

#ifdef WITH_SMARTCARD
#include "i2c.h"
#endif

#ifdef WITH_FPC_USART
#include "usart.h"
#endif

#ifdef WITH_FLASH
#include "flashmem.h"
#include "spiffs.h"
#endif

//=============================================================================
// A buffer where we can queue things up to be sent through the FPGA, for
// any purpose (fake tag, as reader, whatever). We go MSB first, since that
// is the order in which they go out on the wire.
//=============================================================================

#define TOSEND_BUFFER_SIZE (9*MAX_FRAME_SIZE + 1 + 1 + 2)  // 8 data bits and 1 parity bit per payload byte, 1 correction bit, 1 SOC bit, 2 EOC bits
uint8_t ToSend[TOSEND_BUFFER_SIZE];
int ToSendMax = -1;
static int ToSendBit;
struct common_area common_area __attribute__((section(".commonarea")));
int button_status = BUTTON_NO_CLICK;
bool allow_send_wtx = false;

inline void send_wtx(uint16_t wtx) {
    if (allow_send_wtx) {
        reply_ng(CMD_WTX, PM3_SUCCESS, (uint8_t *)&wtx, sizeof(wtx));
    }
}

void ToSendReset(void) {
    ToSendMax = -1;
    ToSendBit = 8;
}

void ToSendStuffBit(int b) {
    if (ToSendBit >= 8) {
        ToSendMax++;
        ToSend[ToSendMax] = 0;
        ToSendBit = 0;
    }

    if (b)
        ToSend[ToSendMax] |= (1 << (7 - ToSendBit));

    ToSendBit++;

    if (ToSendMax >= sizeof(ToSend)) {
        ToSendBit = 0;
        DbpString("ToSendStuffBit overflowed!");
    }
}

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to average 32 samples and
// return that.
//-----------------------------------------------------------------------------
static uint16_t ReadAdc(int ch) {

    // Note: ADC_MODE_PRESCALE and ADC_MODE_SAMPLE_HOLD_TIME are set to the maximum allowed value.
    // AMPL_HI is are high impedance (10MOhm || 1MOhm) output, the input capacitance of the ADC is 12pF (typical). This results in a time constant
    // of RC = (0.91MOhm) * 12pF = 10.9us. Even after the maximum configurable sample&hold time of 40us the input capacitor will not be fully charged.
    //
    // The maths are:
    // If there is a voltage v_in at the input, the voltage v_cap at the capacitor (this is what we are measuring) will be
    //
    //       v_cap = v_in * (1 - exp(-SHTIM/RC))  =   v_in * (1 - exp(-40us/10.9us))  =  v_in * 0,97                   (i.e. an error of 3%)

    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_SWRST;
    AT91C_BASE_ADC->ADC_MR =
        ADC_MODE_PRESCALE(63)          // ADC_CLK = MCK / ((63+1) * 2) = 48MHz / 128 = 375kHz
        | ADC_MODE_STARTUP_TIME(1)       // Startup Time = (1+1) * 8 / ADC_CLK = 16 / 375kHz = 42,7us   Note: must be > 20us
        | ADC_MODE_SAMPLE_HOLD_TIME(15); // Sample & Hold Time SHTIM = 15 / ADC_CLK = 15 / 375kHz = 40us

    AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ch);
    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;

    while (!(AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ch))) {};

    return (AT91C_BASE_ADC->ADC_CDR[ch] & 0x3FF);
}

// was static - merlok
uint16_t AvgAdc(int ch) {
    uint16_t a = 0;
    for (uint8_t i = 0; i < 32; i++)
        a += ReadAdc(ch);

    //division by 32
    return (a + 15) >> 5;
}

void MeasureAntennaTuning(void) {

    uint32_t peak = 0;

    // in mVolt
    struct p {
        uint32_t v_lf134;
        uint32_t v_lf125;
        uint32_t v_lfconf;
        uint32_t v_hf;
        uint32_t peak_v;
        uint32_t peak_f;
        int divisor;
        uint8_t results[256];
    } PACKED payload;

    memset(payload.results, 0, sizeof(payload.results));

    sample_config *sc = getSamplingConfig();
    payload.divisor = sc->divisor;

    LED_B_ON();

    /*
     * Sweeps the useful LF range of the proxmark from
     * 46.8kHz (divisor=255) to 600kHz (divisor=19) and
     * read the voltage in the antenna, the result left
     * in the buffer is a graph which should clearly show
     * the resonating frequency of your LF antenna
     * ( hopefully around 95 if it is tuned to 125kHz!)
     */

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
    SpinDelay(50);

    for (uint8_t i = 255; i >= 19; i--) {
        WDT_HIT();
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, i);
        SpinDelay(20);
        uint32_t adcval = ((MAX_ADC_LF_VOLTAGE * AvgAdc(ADC_CHAN_LF)) >> 10);
        if (i == LF_DIVISOR_125)
            payload.v_lf125 = adcval; // voltage at 125kHz

        if (i == LF_DIVISOR_134)
            payload.v_lf134 = adcval; // voltage at 134kHz

        if (i == sc->divisor)
            payload.v_lfconf = adcval; // voltage at `lf config q`

        payload.results[i] = adcval >> 9; // scale int to fit in byte for graphing purposes

        if (payload.results[i] > peak) {
            payload.peak_v = adcval;
            payload.peak_f = i;
            peak = payload.results[i];
        }
    }

    LED_A_ON();
    // Let the FPGA drive the high-frequency antenna around 13.56 MHz.
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
    SpinDelay(50);

    payload.v_hf = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;

    // RDV40 will hit the roof, try other ADC channel used in that hardware revision.
    if (payload.v_hf > MAX_ADC_HF_VOLTAGE - 300) {
        payload.v_hf = (MAX_ADC_HF_VOLTAGE_RDV40 * AvgAdc(ADC_CHAN_HF_RDV40)) >> 10;
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_MEASURE_ANTENNA_TUNING, PM3_SUCCESS, (uint8_t *)&payload, sizeof(payload));
    LEDsoff();
}

// Measure HF in milliVolt
uint16_t MeasureAntennaTuningHfData(void) {
    uint16_t volt = 0;
    uint16_t avg = AvgAdc(ADC_CHAN_HF);
    volt = (MAX_ADC_HF_VOLTAGE * avg) >> 10;
    bool use_high = (volt > MAX_ADC_HF_VOLTAGE - 300);

    if (use_high) {
        volt = (MAX_ADC_HF_VOLTAGE_RDV40 * AvgAdc(ADC_CHAN_HF_RDV40)) >> 10;
//        volt = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;
    }
    return volt;
}

// Measure LF in milliVolt
uint32_t MeasureAntennaTuningLfData(void) {
    return (MAX_ADC_LF_VOLTAGE * AvgAdc(ADC_CHAN_LF)) >> 10;
}

void ReadMem(int addr) {
    const uint8_t *data = ((uint8_t *)addr);

    Dbprintf("%x: %02x %02x %02x %02x %02x %02x %02x %02x", addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
}

/* osimage version information is linked in */
extern struct version_information version_information;
/* bootrom version information is pointed to from _bootphase1_version_pointer */
extern char *_bootphase1_version_pointer, _flash_start, _flash_end, __data_src_start__;
void SendVersion(void) {
    char temp[PM3_CMD_DATA_SIZE - 12]; /* Limited data payload in USB packets */
    char VersionString[PM3_CMD_DATA_SIZE - 12] = { '\0' };

    /* Try to find the bootrom version information. Expect to find a pointer at
     * symbol _bootphase1_version_pointer, perform slight sanity checks on the
     * pointer, then use it.
     */
    char *bootrom_version = *(char **)&_bootphase1_version_pointer;

    strncat(VersionString, " [ ARM ]\n", sizeof(VersionString) - strlen(VersionString) - 1);

    if (bootrom_version < &_flash_start || bootrom_version >= &_flash_end) {
        strcat(VersionString, "bootrom version information appears invalid\n");
    } else {
        FormatVersionInformation(temp, sizeof(temp), "  bootrom: ", bootrom_version);
        strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
    }

    FormatVersionInformation(temp, sizeof(temp), "       os: ", &version_information);
    strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);

#if defined(__clang__)
    strncat(VersionString, "  compiled with Clang/LLVM "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#elif defined(__GNUC__) || defined(__GNUG__)
    strncat(VersionString, "  compiled with GCC "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#endif

    strncat(VersionString, "\n [ FPGA ]\n ", sizeof(VersionString) - strlen(VersionString) - 1);

    for (int i = 0; i < fpga_bitstream_num; i++) {
        strncat(VersionString, fpga_version_information[i], sizeof(VersionString) - strlen(VersionString) - 1);
        if (i < fpga_bitstream_num - 1) {
            strncat(VersionString, "\n ", sizeof(VersionString) - strlen(VersionString) - 1);
        }
    }
    // Send Chip ID and used flash memory
    uint32_t text_and_rodata_section_size = (uint32_t)&__data_src_start__ - (uint32_t)&_flash_start;
    uint32_t compressed_data_section_size = common_area.arg1;

    struct p {
        uint32_t id;
        uint32_t section_size;
        uint32_t versionstr_len;
        char versionstr[PM3_CMD_DATA_SIZE - 12];
    } PACKED;

    struct p payload;
    payload.id = *(AT91C_DBGU_CIDR);
    payload.section_size = text_and_rodata_section_size + compressed_data_section_size;
    payload.versionstr_len = strlen(VersionString) + 1;
    memcpy(payload.versionstr, VersionString, payload.versionstr_len);

    reply_ng(CMD_VERSION, PM3_SUCCESS, (uint8_t *)&payload, 12 + payload.versionstr_len);
}

void TimingIntervalAcquisition(void) {
    // trigger new acquisition by turning main oscillator off and on
    mck_from_pll_to_slck();
    mck_from_slck_to_pll();
    // wait for MCFR and recompute RTMR scaler
    StartTickCount();
}

// measure the Connection Speed by sending SpeedTestBufferSize bytes to client and measuring the elapsed time.
// Note: this mimics GetFromBigbuf(), i.e. we have the overhead of the PacketCommandNG structure included.
void printConnSpeed(void) {
    DbpString(_BLUE_("Transfer Speed"));
    Dbprintf("  Sending packets to client...");

#define CONN_SPEED_TEST_MIN_TIME 500 // in milliseconds
    uint8_t *test_data = BigBuf_get_addr();
    uint32_t start_time = GetTickCount();
    uint32_t delta_time = 0;
    uint32_t bytes_transferred = 0;

    LED_B_ON();

    while (delta_time < CONN_SPEED_TEST_MIN_TIME) {
        reply_ng(CMD_DOWNLOADED_BIGBUF, PM3_SUCCESS, test_data, PM3_CMD_DATA_SIZE);
        bytes_transferred += PM3_CMD_DATA_SIZE;
        delta_time = GetTickCountDelta(start_time);
    }
    LED_B_OFF();

    Dbprintf("  Time elapsed............%dms", delta_time);
    Dbprintf("  Bytes transferred.......%d", bytes_transferred);
    Dbprintf("  Transfer Speed PM3 -> Client = " _YELLOW_("%d") "bytes/s", 1000 * bytes_transferred / delta_time);
}

/**
  * Prints runtime information about the PM3.
**/
void SendStatus(void) {
    BigBuf_print_status();
    Fpga_print_status();
#ifdef WITH_FLASH
    Flashmem_print_status();
#endif
#ifdef WITH_SMARTCARD
    I2C_print_status();
#endif
#ifdef WITH_LF
    printConfig();      // LF Sampling config
    printT55xxConfig(); // LF T55XX Config
#endif
    printConnSpeed();
    DbpString(_BLUE_("Various"));
    Dbprintf("  DBGLEVEL................%d", DBGLEVEL);
    Dbprintf("  ToSendMax...............%d", ToSendMax);
    Dbprintf("  ToSendBit...............%d", ToSendBit);
    Dbprintf("  ToSend BUFFERSIZE.......%d", TOSEND_BUFFER_SIZE);
    while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
    uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;       // Get # main clocks within 16 slow clocks
    Dbprintf("  Slow clock..............%d Hz", (16 * MAINCK) / mainf);
    uint32_t delta_time = 0;
    uint32_t start_time = GetTickCount();
#define SLCK_CHECK_MS 50
    SpinDelay(SLCK_CHECK_MS);
    delta_time = GetTickCountDelta(start_time);
    if ((delta_time < SLCK_CHECK_MS - 1) || (delta_time > SLCK_CHECK_MS + 1)) {
        // error > 2% with SLCK_CHECK_MS=50
        Dbprintf(_RED_("  Slow Clock speed change detected, TIA needed"));
        Dbprintf(_YELLOW_("  Slow Clock actual speed seems closer to %d kHz"),
                 (16 * MAINCK / 1000) / mainf * delta_time / SLCK_CHECK_MS);
    }
    DbpString(_BLUE_("Installed StandAlone Mode"));
    ModInfo();

#ifdef WITH_FLASH
    Flashmem_print_info();
#endif

    reply_ng(CMD_STATUS, PM3_SUCCESS, NULL, 0);
}

void SendCapabilities(void) {
    capabilities_t capabilities;
    capabilities.version = CAPABILITIES_VERSION;
    capabilities.via_fpc = reply_via_fpc;
    capabilities.via_usb = reply_via_usb;
    capabilities.baudrate = 0; // no real baudrate for USB-CDC
#ifdef WITH_FPC_USART
    if (reply_via_fpc)
        capabilities.baudrate = usart_baudrate;
#endif

#ifdef WITH_FLASH
    capabilities.compiled_with_flash = true;
    capabilities.hw_available_flash = FlashInit();
#else
    capabilities.compiled_with_flash = false;
    capabilities.hw_available_flash = false;
#endif
#ifdef WITH_SMARTCARD
    capabilities.compiled_with_smartcard = true;
    uint8_t maj, min;
    capabilities.hw_available_smartcard = I2C_get_version(&maj, &min) == PM3_SUCCESS;
#else
    capabilities.compiled_with_smartcard = false;
    capabilities.hw_available_smartcard = false;
#endif
#ifdef WITH_FPC_USART
    capabilities.compiled_with_fpc_usart = true;
#else
    capabilities.compiled_with_fpc_usart = false;
#endif
#ifdef WITH_FPC_USART_DEV
    capabilities.compiled_with_fpc_usart_dev = true;
#else
    capabilities.compiled_with_fpc_usart_dev = false;
#endif
#ifdef WITH_FPC_USART_HOST
    capabilities.compiled_with_fpc_usart_host = true;
#else
    capabilities.compiled_with_fpc_usart_host = false;
#endif
#ifdef WITH_LF
    capabilities.compiled_with_lf = true;
#else
    capabilities.compiled_with_lf = false;
#endif
#ifdef WITH_HITAG
    capabilities.compiled_with_hitag = true;
#else
    capabilities.compiled_with_hitag = false;
#endif
#ifdef WITH_HFSNIFF
    capabilities.compiled_with_hfsniff = true;
#else
    capabilities.compiled_with_hfsniff = false;
#endif
#ifdef WITH_ISO14443a
    capabilities.compiled_with_iso14443a = true;
#else
    capabilities.compiled_with_iso14443a = false;
#endif
#ifdef WITH_ISO14443b
    capabilities.compiled_with_iso14443b = true;
#else
    capabilities.compiled_with_iso14443b = false;
#endif
#ifdef WITH_ISO15693
    capabilities.compiled_with_iso15693 = true;
#else
    capabilities.compiled_with_iso15693 = false;
#endif
#ifdef WITH_FELICA
    capabilities.compiled_with_felica = true;
#else
    capabilities.compiled_with_felica = false;
#endif
#ifdef WITH_LEGICRF
    capabilities.compiled_with_legicrf = true;
#else
    capabilities.compiled_with_legicrf = false;
#endif
#ifdef WITH_ICLASS
    capabilities.compiled_with_iclass = true;
#else
    capabilities.compiled_with_iclass = false;
#endif
#ifdef WITH_NFCBARCODE
    capabilities.compiled_with_nfcbarcode = true;
#else
    capabilities.compiled_with_nfcbarcode = false;
#endif
#ifdef WITH_LCD
    capabilities.compiled_with_lcd = true;
#else
    capabilities.compiled_with_lcd = false;
#endif
    reply_ng(CMD_CAPABILITIES, PM3_SUCCESS, (uint8_t *)&capabilities, sizeof(capabilities));
}

// Show some leds in a pattern to identify StandAlone mod is running
void StandAloneMode(void) {
    DbpString("Stand-alone mode, no computer necessary");
    SpinDown(50);
    SpinDelay(50);
    SpinUp(50);
    SpinDelay(50);
    SpinDown(50);
}

/*
OBJECTIVE
Listen and detect an external reader. Determine the best location
for the antenna.

INSTRUCTIONS:
Inside the ListenReaderField() function, there is two mode.
By default, when you call the function, you will enter mode 1.
If you press the PM3 button one time, you will enter mode 2.
If you press the PM3 button a second time, you will exit the function.

DESCRIPTION OF MODE 1:
This mode just listens for an external reader field and lights up green
for HF and/or red for LF. This is the original mode of the detectreader
function.

DESCRIPTION OF MODE 2:
This mode will visually represent, using the LEDs, the actual strength of the
current compared to the maximum current detected. Basically, once you know
what kind of external reader is present, it will help you spot the best location to place
your antenna. You will probably not get some good results if there is a LF and a HF reader
at the same place! :-)
*/
#define LIGHT_LEVELS 20

void ListenReaderField(uint8_t limit) {
#define LF_ONLY 1
#define HF_ONLY 2
#define REPORT_CHANGE 10    // report new values only if they have changed at least by REPORT_CHANGE

    uint16_t lf_av = 0, lf_av_new, lf_baseline = 0, lf_max = 0;
    uint16_t hf_av = 0, hf_av_new,  hf_baseline = 0, hf_max = 0;
    uint16_t mode = 1, display_val, display_max;
    bool use_high = false;

    // switch off FPGA - we don't want to measure our own signal
    // 20180315 - iceman,  why load this before and then turn off?
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    LEDsoff();

    if (limit == LF_ONLY) {
        lf_av = lf_max = AvgAdc(ADC_CHAN_LF);
        Dbprintf("LF 125/134kHz Baseline: %dmV", (MAX_ADC_LF_VOLTAGE * lf_av) >> 10);
        lf_baseline = lf_av;
    }

    if (limit == HF_ONLY) {

        hf_av = hf_max = AvgAdc(ADC_CHAN_HF);

        // iceman,  useless,  since we are measuring readerfield,  not our field.  My tests shows a max of 20v from a reader.
        // RDV40 will hit the roof, try other ADC channel used in that hardware revision.
        use_high = (((MAX_ADC_HF_VOLTAGE * hf_max) >> 10) > MAX_ADC_HF_VOLTAGE - 300);
        if (use_high) {
            hf_av = hf_max = AvgAdc(ADC_CHAN_HF_RDV40);
        }

        Dbprintf("HF 13.56MHz Baseline: %dmV", (MAX_ADC_HF_VOLTAGE * hf_av) >> 10);
        hf_baseline = hf_av;
    }

    for (;;) {

        // Switch modes with button
        if (BUTTON_PRESS()) {
            SpinDelay(500);
            switch (mode) {
                case 1:
                    mode = 2;
                    DbpString("Signal Strength Mode");
                    break;
                case 2:
                default:
                    DbpString("Stopped");
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LEDsoff();
                    return;
            }
        }
        WDT_HIT();

        if (limit == LF_ONLY) {
            if (mode == 1) {
                if (ABS(lf_av - lf_baseline) > REPORT_CHANGE)
                    LED_D_ON();
                else
                    LED_D_OFF();
            }

            lf_av_new = AvgAdc(ADC_CHAN_LF);
            // see if there's a significant change
            if (ABS(lf_av - lf_av_new) > REPORT_CHANGE) {
                Dbprintf("LF 125/134kHz Field Change: %5dmV", (MAX_ADC_LF_VOLTAGE * lf_av_new) >> 10);
                lf_av = lf_av_new;
                if (lf_av > lf_max)
                    lf_max = lf_av;
            }
        }

        if (limit == HF_ONLY) {
            if (mode == 1) {
                if (ABS(hf_av - hf_baseline) > REPORT_CHANGE)
                    LED_B_ON();
                else
                    LED_B_OFF();
            }

            hf_av_new = (use_high) ? AvgAdc(ADC_CHAN_HF_RDV40) :  AvgAdc(ADC_CHAN_HF);

            // see if there's a significant change
            if (ABS(hf_av - hf_av_new) > REPORT_CHANGE) {
                Dbprintf("HF 13.56MHz Field Change: %5dmV", (MAX_ADC_HF_VOLTAGE * hf_av_new) >> 10);
                hf_av = hf_av_new;
                if (hf_av > hf_max)
                    hf_max = hf_av;
            }
        }

        if (mode == 2) {
            if (limit == LF_ONLY) {
                display_val = lf_av;
                display_max = lf_max;
            } else if (limit == HF_ONLY) {
                display_val = hf_av;
                display_max = hf_max;
            } else { /* Pick one at random */
                if ((hf_max - hf_baseline) > (lf_max - lf_baseline)) {
                    display_val = hf_av;
                    display_max = hf_max;
                } else {
                    display_val = lf_av;
                    display_max = lf_max;
                }
            }

            display_val = display_val * (4 * LIGHT_LEVELS) / MAX(1, display_max);
            uint32_t duty_a = MIN(MAX(display_val, 0 * LIGHT_LEVELS), 1 * LIGHT_LEVELS) - 0 * LIGHT_LEVELS;
            uint32_t duty_b = MIN(MAX(display_val, 1 * LIGHT_LEVELS), 2 * LIGHT_LEVELS) - 1 * LIGHT_LEVELS;
            uint32_t duty_c = MIN(MAX(display_val, 2 * LIGHT_LEVELS), 3 * LIGHT_LEVELS) - 2 * LIGHT_LEVELS;
            uint32_t duty_d = MIN(MAX(display_val, 3 * LIGHT_LEVELS), 4 * LIGHT_LEVELS) - 3 * LIGHT_LEVELS;

            // LED A
            if (duty_a == 0) {
                LED_A_OFF();
            } else if (duty_a == LIGHT_LEVELS) {
                LED_A_ON();
            } else {
                LED_A_ON();
                SpinDelay(duty_a);
                LED_A_OFF();
                SpinDelay(LIGHT_LEVELS - duty_a);
            }

            // LED B
            if (duty_b == 0) {
                LED_B_OFF();
            } else if (duty_b == LIGHT_LEVELS) {
                LED_B_ON();
            } else {
                LED_B_ON();
                SpinDelay(duty_b);
                LED_B_OFF();
                SpinDelay(LIGHT_LEVELS - duty_b);
            }

            // LED C
            if (duty_c == 0) {
                LED_C_OFF();
            } else if (duty_c == LIGHT_LEVELS) {
                LED_C_ON();
            } else {
                LED_C_ON();
                SpinDelay(duty_c);
                LED_C_OFF();
                SpinDelay(LIGHT_LEVELS - duty_c);
            }

            // LED D
            if (duty_d == 0) {
                LED_D_OFF();
            } else if (duty_d == LIGHT_LEVELS) {
                LED_D_ON();
            } else {
                LED_D_ON();
                SpinDelay(duty_d);
                LED_D_OFF();
                SpinDelay(LIGHT_LEVELS - duty_d);
            }
        }
    }
}
static void PacketReceived(PacketCommandNG *packet) {
    /*
    if (packet->ng) {
        Dbprintf("received NG frame with %d bytes payload, with command: 0x%04x", packet->length, cmd);
    } else {
        Dbprintf("received OLD frame of %d bytes, with command: 0x%04x and args: %d %d %d", packet->length, packet->cmd, packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
    }
    */

    switch (packet->cmd) {
        case CMD_QUIT_SESSION:
            reply_via_fpc = false;
            reply_via_usb = false;
            break;
#ifdef WITH_LF
        case CMD_LF_T55XX_SET_CONFIG: {
            setT55xxConfig(packet->oldarg[0], (t55xx_configurations_t *) packet->data.asBytes);
            break;
        }
        case CMD_LF_SAMPLING_GET_CONFIG: {
            printConfig();
            break;
        }
        case CMD_LF_SAMPLING_SET_CONFIG: {
            setSamplingConfig((sample_config *) packet->data.asBytes);
            break;
        }
        case CMD_LF_ACQ_RAW_ADC: {
            struct p {
                uint8_t silent;
                uint32_t samples;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            uint32_t bits = SampleLF(payload->silent, payload->samples);
            reply_ng(CMD_LF_ACQ_RAW_ADC, PM3_SUCCESS, (uint8_t *)&bits, sizeof(bits));
            break;
        }
        case CMD_LF_MOD_THEN_ACQ_RAW_ADC: {
            struct p {
                uint32_t delay;
                uint16_t ones;
                uint16_t zeros;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            ModThenAcquireRawAdcSamples125k(payload->delay, payload->zeros, payload->ones, packet->data.asBytes + 8);
            break;
        }
        case CMD_LF_SNIFF_RAW_ADC: {
            uint32_t bits = SniffLF();
            reply_mix(CMD_ACK, bits, 0, 0, 0, 0);
            break;
        }
        case CMD_LF_HID_DEMOD: {
            uint32_t high, low;
            CmdHIDdemodFSK(0, &high, &low, 1);
            break;
        }
        case CMD_LF_HID_SIMULATE: {
            lf_hidsim_t *payload = (lf_hidsim_t *)packet->data.asBytes;
            CmdHIDsimTAG(payload->hi2, payload->hi, payload->lo, payload->longFMT, 1);
            break;
        }
        case CMD_LF_FSK_SIMULATE: {
            lf_fsksim_t *payload = (lf_fsksim_t *)packet->data.asBytes;
            CmdFSKsimTAG(payload->fchigh, payload->fclow, payload->separator, payload->clock, packet->length - sizeof(lf_fsksim_t), payload->data, true);
            break;
        }
        case CMD_LF_ASK_SIMULATE: {
            lf_asksim_t *payload = (lf_asksim_t *)packet->data.asBytes;
            CmdASKsimTAG(payload->encoding, payload->invert, payload->separator, payload->clock, packet->length - sizeof(lf_asksim_t), payload->data, true);
            break;
        }
        case CMD_LF_PSK_SIMULATE: {
            lf_psksim_t *payload = (lf_psksim_t *)packet->data.asBytes;
            CmdPSKsimTag(payload->carrier, payload->invert, payload->clock, packet->length - sizeof(lf_psksim_t), payload->data, true);
            break;
        }
        case CMD_LF_HID_CLONE: {
            CopyHIDtoT55x7(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes[0]);
            break;
        }
        case CMD_LF_IO_DEMOD: {
            uint32_t high, low;
            CmdIOdemodFSK(0, &high, &low, 1);
            break;
        }
        case CMD_LF_EM410X_DEMOD: {
            uint32_t high;
            uint64_t low;
            CmdEM410xdemod(packet->oldarg[0], &high, &low, 1);
            break;
        }
        case CMD_LF_EM410X_WRITE: {
            WriteEM410x(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_LF_TI_READ: {
            ReadTItag();
            break;
        }
        case CMD_LF_TI_WRITE: {
            WriteTItag(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_LF_SIMULATE: {
            LED_A_ON();
            struct p {
                uint16_t len;
                uint16_t gap;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            // length, start gap, led control
            SimulateTagLowFrequency(payload->len, payload->gap, 1);
            reply_ng(CMD_LF_SIMULATE, PM3_EOPABORTED, NULL, 0);
            LED_A_OFF();
            break;
        }
        case CMD_LF_SIMULATE_BIDIR: {
            SimulateTagLowFrequencyBidir(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_LF_T55XX_READBL: {
            struct p {
                uint32_t password;
                uint8_t  blockno;
                uint8_t  page;
                bool     pwdmode;
                uint8_t  downlink_mode;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            T55xxReadBlock(payload->page, payload->pwdmode, false, payload->blockno, payload->password, payload->downlink_mode);
            break;
        }
        case CMD_LF_T55XX_WRITEBL: {
            // uses NG format
            T55xxWriteBlock(packet->data.asBytes);
            break;
        }
        case CMD_LF_T55XX_DANGERRAW: {
            T55xxDangerousRawTest(packet->data.asBytes);
            break;
        }
        case CMD_LF_T55XX_WAKEUP: {
            struct p {
                uint32_t password;
                uint8_t flags;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            T55xxWakeUp(payload->password, payload->flags);
            break;
        }
        case CMD_LF_T55XX_RESET_READ: {
            T55xxResetRead(packet->data.asBytes[0] & 0xff);
            break;
        }
        case CMD_LF_T55XX_CHK_PWDS: {
            T55xx_ChkPwds(packet->data.asBytes[0] & 0xff);
            break;
        }
        case CMD_LF_PCF7931_READ: {
            ReadPCF7931();
            break;
        }
        case CMD_LF_PCF7931_WRITE: {
            WritePCF7931(
                packet->data.asBytes[0], packet->data.asBytes[1], packet->data.asBytes[2], packet->data.asBytes[3],
                packet->data.asBytes[4], packet->data.asBytes[5], packet->data.asBytes[6], packet->data.asBytes[9],
                packet->data.asBytes[7] - 128, packet->data.asBytes[8] - 128,
                packet->oldarg[0],
                packet->oldarg[1],
                packet->oldarg[2]
            );
            break;
        }
        case CMD_LF_EM4X_READWORD: {
            struct p {
                uint32_t password;
                uint8_t address;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xReadWord(payload->address, payload->password, payload->usepwd);
            break;
        }
        case CMD_LF_EM4X_WRITEWORD: {
            struct p {
                uint32_t password;
                uint32_t data;
                uint8_t address;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xWriteWord(payload->address, payload->data, payload->password, payload->usepwd);
            break;
        }
        case CMD_LF_AWID_DEMOD:  {
            uint32_t high, low;
            // Set realtime AWID demodulation
            CmdAWIDdemodFSK(0, &high, &low, 1);
            break;
        }
        case CMD_LF_VIKING_CLONE: {
            struct p {
                bool Q5;
                uint8_t blocks[8];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            CopyVikingtoT55xx(payload->blocks, payload->Q5);
            break;
        }
        case CMD_LF_COTAG_READ: {
            Cotag(packet->oldarg[0]);
            break;
        }
#endif

#ifdef WITH_HITAG
        case CMD_LF_HITAG_SNIFF: { // Eavesdrop Hitag tag, args = type
            SniffHitag();
            break;
        }
        case CMD_LF_HITAG_SIMULATE: { // Simulate Hitag tag, args = memory content
            SimulateHitagTag((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_LF_HITAG_READER: { // Reader for Hitag tags, args = type and function
            ReaderHitag((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes);
            break;
        }
        case CMD_LF_HITAGS_SIMULATE: { // Simulate Hitag s tag, args = memory content
            SimulateHitagSTag((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_LF_HITAGS_TEST_TRACES: { // Tests every challenge within the given file
            check_challenges((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_LF_HITAGS_READ: { //Reader for only Hitag S tags, args = key or challenge
            ReadHitagS((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes);
            break;
        }
        case CMD_LF_HITAGS_WRITE: { //writer for Hitag tags args=data to write,page and key or challenge
            if ((hitag_function)packet->oldarg[0] < 10) {
                WritePageHitagS((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes, packet->oldarg[2]);
            } else {
                WriterHitag((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes, packet->oldarg[2]);
            }
            break;
        }
#endif

#ifdef WITH_ISO15693
        case CMD_HF_ISO15693_ACQ_RAW_ADC: {
            AcquireRawAdcSamplesIso15693();
            break;
        }
        case CMD_HF_ISO15693_RAWADC: {
            RecordRawAdcSamplesIso15693();
            break;
        }
        case CMD_HF_ISO15693_COMMAND: {
            DirectTag15693Command(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_ISO15693_FINDAFI: {
            BruteforceIso15693Afi(packet->oldarg[0]);
            break;
        }
        case CMD_HF_ISO15693_READER: {
            ReaderIso15693(packet->oldarg[0]);
            break;
        }
        case CMD_HF_ISO15693_SIMULATE: {
            SimTagIso15693(packet->oldarg[0], packet->data.asBytes);
            break;
        }
#endif

#ifdef WITH_LEGICRF
        case CMD_HF_LEGIC_SIMULATE: {
            LegicRfSimulate(packet->oldarg[0]);
            break;
        }
        case CMD_HF_LEGIC_WRITER: {
            LegicRfWriter(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_LEGIC_READER: {
            LegicRfReader(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_HF_LEGIC_INFO: {
            LegicRfInfo();
            break;
        }
        case CMD_HF_LEGIC_ESET: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            // arg0 = offset
            // arg1 = num of bytes
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            emlSet(packet->data.asBytes, packet->oldarg[0], packet->oldarg[1]);
            break;
        }
#endif

#ifdef WITH_ISO14443b
        case CMD_HF_SRI_READ: {
            ReadSTMemoryIso14443b(packet->oldarg[0]);
            break;
        }
        case CMD_HF_ISO14443B_SNIFF: {
            SniffIso14443b();
            break;
        }
        case CMD_HF_ISO14443B_SIMULATE: {
            SimulateIso14443bTag(packet->oldarg[0]);
            break;
        }
        case CMD_HF_ISO14443B_COMMAND: {
            //SendRawCommand14443B(packet->oldarg[0],packet->oldarg[1],packet->oldarg[2],packet->data.asBytes);
            SendRawCommand14443B_Ex(packet);
            break;
        }
#endif

#ifdef WITH_FELICA
        case CMD_HF_FELICA_COMMAND: {
            felica_sendraw(packet);
            break;
        }
        case CMD_HF_FELICALITE_SIMULATE: {
            felica_sim_lite(packet->oldarg[0]);
            break;
        }
        case CMD_HF_FELICA_SNIFF: {
            felica_sniff(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_HF_FELICALITE_DUMP: {
            felica_dump_lite_s();
            break;
        }
#endif

// always available
        case CMD_HF_DROPFIELD: {
            hf_field_off();
            break;
        }

#ifdef WITH_ISO14443a
        case CMD_HF_ISO14443A_SNIFF: {
            SniffIso14443a(packet->data.asBytes[0]);
            break;
        }
        case CMD_HF_ISO14443A_READER: {
            ReaderIso14443a(packet);
            break;
        }
        case CMD_HF_ISO14443A_SIMULATE: {
            struct p {
                uint8_t tagtype;
                uint8_t flags;
                uint8_t uid[10];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimulateIso14443aTag(payload->tagtype, payload->flags, payload->uid);  // ## Simulate iso14443a tag - pass tag type & UID
            break;
        }
        case CMD_HF_ISO14443A_ANTIFUZZ: {
            iso14443a_antifuzz(packet->oldarg[0]);
            break;
        }
        case CMD_HF_EPA_COLLECT_NONCE: {
            EPA_PACE_Collect_Nonce(packet);
            break;
        }
        case CMD_HF_EPA_REPLAY: {
            EPA_PACE_Replay(packet);
            break;
        }
        case CMD_HF_MIFARE_READER: {
            struct p {
                uint8_t first_run;
                uint8_t blockno;
                uint8_t key_type;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            ReaderMifare(payload->first_run, payload->blockno, payload->key_type);
            break;
        }
        case CMD_HF_MIFARE_READBL: {
            mf_readblock_t *payload = (mf_readblock_t *)packet->data.asBytes;
            MifareReadBlock(payload->blockno, payload->keytype, payload->key);
            break;
        }
        case CMD_HF_MIFAREU_READBL: {
            MifareUReadBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREUC_AUTH: {
            MifareUC_Auth(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_READCARD: {
            MifareUReadCard(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREUC_SETPWD: {
            MifareUSetPwd(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_READSC: {
            MifareReadSector(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_WRITEBL: {
            MifareWriteBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_WRITEBL: {
            MifareUWriteBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES: {
            MifareAcquireEncryptedNonces(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_NONCES: {
            MifareAcquireNonces(packet->oldarg[0], packet->oldarg[2]);
            break;
        }
        case CMD_HF_MIFARE_NESTED: {
            struct p {
                uint8_t block;
                uint8_t keytype;
                uint8_t target_block;
                uint8_t target_keytype;
                bool calibrate;
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareNested(payload->block, payload->keytype, payload->target_block, payload->target_keytype, payload->calibrate, payload->key);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS: {
            MifareChkKeys(packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS_FAST: {
            MifareChkKeys_fast(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_SIMULATE: {
            struct p {
                uint16_t flags;
                uint8_t exitAfter;
                uint8_t uid[10];
                uint16_t atqa;
                uint8_t sak;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            Mifare1ksim(payload->flags, payload->exitAfter, payload->uid, payload->atqa, payload->sak);
            break;
        }
        // emulator
        case CMD_SET_DBGMODE: {
            DBGLEVEL = packet->data.asBytes[0];
            Dbprintf("Debug level: %d", DBGLEVEL);
            reply_ng(CMD_SET_DBGMODE, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMCLR: {
            MifareEMemClr();
            reply_ng(CMD_HF_MIFARE_EML_MEMCLR, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMSET: {
            struct p {
                uint8_t blockno;
                uint8_t blockcnt;
                uint8_t blockwidth;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareEMemSet(payload->blockno, payload->blockcnt, payload->blockwidth, payload->data);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMGET: {
            struct p {
                uint8_t blockno;
                uint8_t blockcnt;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareEMemGet(payload->blockno, payload->blockcnt);
            break;
        }
        case CMD_HF_MIFARE_EML_LOAD: {
            mfc_eload_t *payload = (mfc_eload_t *) packet->data.asBytes;
            MifareECardLoadExt(payload->sectorcnt, payload->keytype);
            break;
        }
        // Work with "magic Chinese" card
        case CMD_HF_MIFARE_CSETBL: {
            MifareCSetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_CGETBL: {
            MifareCGetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_CIDENT: {
            MifareCIdent();
            break;
        }
        // mifare sniffer
//        case CMD_HF_MIFARE_SNIFF: {
//            SniffMifare(packet->oldarg[0]);
//            break;
//        }
        case CMD_HF_MIFARE_SETMOD: {
            MifareSetMod(packet->data.asBytes);
            break;
        }
        //mifare desfire
        case CMD_HF_DESFIRE_READBL: {
            break;
        }
        case CMD_HF_DESFIRE_WRITEBL: {
            break;
        }
        case CMD_HF_DESFIRE_AUTH1: {
            MifareDES_Auth1(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_AUTH2: {
            //MifareDES_Auth2(packet->oldarg[0],packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_READER: {
            //readermifaredes(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_INFO: {
            MifareDesfireGetInformation();
            break;
        }
        case CMD_HF_DESFIRE_COMMAND: {
            MifareSendCommand(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_NACK_DETECT: {
            DetectNACKbug();
            break;
        }
#endif

#ifdef WITH_NFCBARCODE
        case CMD_HF_THINFILM_READ: {
            ReadThinFilm();
            break;
        }
        case CMD_HF_THINFILM_SIMULATE: {
            SimulateThinFilm(packet->data.asBytes, packet->length);
            break;
        }
#endif

#ifdef WITH_ICLASS
        // Makes use of ISO14443a FPGA Firmware
        case CMD_HF_ICLASS_SNIFF: {
            SniffIClass();
            break;
        }
        case CMD_HF_ICLASS_SIMULATE: {
            SimulateIClass(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_READER: {
            ReaderIClass(packet->oldarg[0]);
            break;
        }
        case CMD_HF_ICLASS_REPLAY: {
            ReaderIClass_Replay(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_EML_MEMSET: {
            //iceman, should call FPGADOWNLOAD before, since it corrupts BigBuf
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            emlSet(packet->data.asBytes, packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_HF_ICLASS_WRITEBL: {
            struct p {
                uint8_t blockno;
                uint8_t data[12];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            iClass_WriteBlock(payload->blockno, payload->data);
            break;
        }
        // iceman2019, unused?
        case CMD_HF_ICLASS_READCHECK: { // auth step 1
            iClass_ReadCheck(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_HF_ICLASS_READBL: {
            /*
                        struct p {
                            uint8_t blockno;
                        } PACKED;
                        struct p *payload = (struct p *)packet->data.asBytes;
                        */
            iClass_ReadBlk(packet->data.asBytes[0]);
            break;
        }
        case CMD_HF_ICLASS_AUTH: { //check
            /*
                        struct p {
                            uint8_t mac[4];
                        } PACKED;
                        struct p *payload = (struct p *)packet->data.asBytes;
            */
            iClass_Authentication(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_CHKKEYS: {
            iClass_Authentication_fast(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_DUMP: {
            iClass_Dump(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_HF_ICLASS_CLONE: {
            struct p {
                uint8_t startblock;
                uint8_t endblock;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            iClass_Clone(payload->startblock, payload->endblock, payload->data);
            break;
        }
#endif

#ifdef WITH_HFSNIFF
        case CMD_HF_SNIFF: {
            HfSniff(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
#endif

#ifdef WITH_SMARTCARD
        case CMD_SMART_ATR: {
            SmartCardAtr();
            break;
        }
        case CMD_SMART_SETBAUD: {
            SmartCardSetBaud(packet->oldarg[0]);
            break;
        }
        case CMD_SMART_SETCLOCK: {
            SmartCardSetClock(packet->oldarg[0]);
            break;
        }
        case CMD_SMART_RAW: {
            SmartCardRaw(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_SMART_UPLOAD: {
            // upload file from client
            uint8_t *mem = BigBuf_get_addr();
            memcpy(mem + packet->oldarg[0], packet->data.asBytes, PM3_CMD_DATA_SIZE);
            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            break;
        }
        case CMD_SMART_UPGRADE: {
            SmartCardUpgrade(packet->oldarg[0]);
            break;
        }
#endif

#ifdef WITH_FPC_USART
        case CMD_USART_TX: {
            LED_B_ON();
            usart_writebuffer_sync(packet->data.asBytes, packet->length);
            reply_ng(CMD_USART_TX, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_USART_RX: {
            LED_B_ON();
            struct p {
                uint32_t waittime;
            } PACKED;
            struct p *payload = (struct p *) &packet->data.asBytes;
            uint16_t available;
            uint16_t pre_available = 0;
            uint8_t *dest = BigBuf_malloc(USART_FIFOLEN);
            uint32_t wait = payload->waittime;
            uint32_t ti = GetTickCount();
            while (true) {
                WaitMS(50);
                available = usart_rxdata_available();
                if (available > pre_available) {
                    // When receiving data, reset timer and shorten timeout
                    ti = GetTickCount();
                    wait = 50;
                    pre_available = available;
                    continue;
                }
                // We stop either after waittime if no data or 50ms after last data received
                if (GetTickCountDelta(ti) > wait)
                    break;
            }
            if (available > 0) {
                uint16_t len = usart_read_ng(dest, available);
                reply_ng(CMD_USART_RX, PM3_SUCCESS, dest, len);
            } else {
                reply_ng(CMD_USART_RX, PM3_ENODATA, NULL, 0);
            }
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_USART_TXRX: {
            LED_B_ON();
            struct p {
                uint32_t waittime;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) &packet->data.asBytes;
            usart_writebuffer_sync(payload->data, packet->length - sizeof(payload));
            uint16_t available;
            uint16_t pre_available = 0;
            uint8_t *dest = BigBuf_malloc(USART_FIFOLEN);
            uint32_t wait = payload->waittime;
            uint32_t ti = GetTickCount();
            while (true) {
                WaitMS(50);
                available = usart_rxdata_available();
                if (available > pre_available) {
                    // When receiving data, reset timer and shorten timeout
                    ti = GetTickCount();
                    wait = 50;
                    pre_available = available;
                    continue;
                }
                // We stop either after waittime if no data or 50ms after last data received
                if (GetTickCountDelta(ti) > wait)
                    break;
            }
            if (available > 0) {
                uint16_t len = usart_read_ng(dest, available);
                reply_ng(CMD_USART_TXRX, PM3_SUCCESS, dest, len);
            } else {
                reply_ng(CMD_USART_TXRX, PM3_ENODATA, NULL, 0);
            }
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_USART_CONFIG: {
            struct p {
                uint32_t baudrate;
                uint8_t parity;
            } PACKED;
            struct p *payload = (struct p *) &packet->data.asBytes;
            usart_init(payload->baudrate, payload->parity);
            reply_ng(CMD_USART_CONFIG, PM3_SUCCESS, NULL, 0);
            break;
        }
#endif
        case CMD_BUFF_CLEAR: {
            BigBuf_Clear();
            BigBuf_free();
            break;
        }
        case CMD_MEASURE_ANTENNA_TUNING: {
            MeasureAntennaTuning();
            break;
        }
        case CMD_MEASURE_ANTENNA_TUNING_HF: {
            if (packet->length != 1)
                reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EINVARG, NULL, 0);

            switch (packet->data.asBytes[0]) {
                case 1: // MEASURE_ANTENNA_TUNING_HF_START
                    // Let the FPGA drive the high-frequency antenna around 13.56 MHz.
                    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, NULL, 0);
                    break;
                case 2:
                    if (button_status == BUTTON_SINGLE_CLICK)
                        reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EOPABORTED, NULL, 0);
                    uint16_t volt = MeasureAntennaTuningHfData();
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, (uint8_t *)&volt, sizeof(volt));
                    break;
                case 3:
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, NULL, 0);
                    break;
                default:
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EINVARG, NULL, 0);
                    break;
            }
            break;
        }
        case CMD_MEASURE_ANTENNA_TUNING_LF: {
            if (packet->length != 2)
                reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EINVARG, NULL, 0);

            switch (packet->data.asBytes[0]) {
                case 1: // MEASURE_ANTENNA_TUNING_LF_START
                    // Let the FPGA drive the low-frequency antenna around 125kHz
                    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
                    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, packet->data.asBytes[1]);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, NULL, 0);
                    break;
                case 2:
                    if (button_status == BUTTON_SINGLE_CLICK)
                        reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EOPABORTED, NULL, 0);

                    uint32_t volt = MeasureAntennaTuningLfData();
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, (uint8_t *)&volt, sizeof(volt));
                    break;
                case 3:
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, NULL, 0);
                    break;
                default:
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EINVARG, NULL, 0);
                    break;
            }
            break;
        }
        case CMD_LISTEN_READER_FIELD: {
            if (packet->length != sizeof(uint8_t))
                break;
            ListenReaderField(packet->data.asBytes[0]);
            break;
        }
        case CMD_FPGA_MAJOR_MODE_OFF: { // ## FPGA Control
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            SpinDelay(200);
            LED_D_OFF(); // LED D indicates field ON or OFF
            break;
        }
        case CMD_DOWNLOAD_BIGBUF: {
            LED_B_ON();
            uint8_t *mem = BigBuf_get_addr();
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = BigBuf tracelen
            //Dbprintf("transfer to client parameters: %" PRIu32 " | %" PRIu32 " | %" PRIu32, startidx, numofbytes, packet->oldarg[2]);

            for (size_t i = 0; i < numofbytes; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
                int result = reply_old(CMD_DOWNLOADED_BIGBUF, i, len, BigBuf_get_traceLen(), mem + startidx + i, len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            // iceman,  when did sending samplingconfig array got attached here?!?
            // arg0 = status of download transfer
            // arg1 = RFU
            // arg2 = tracelen?
            // asbytes = samplingconfig array
            reply_old(CMD_ACK, 1, 0, BigBuf_get_traceLen(), getSamplingConfig(), sizeof(sample_config));
            LED_B_OFF();
            break;
        }
#ifdef WITH_LF
        case CMD_LF_UPLOAD_SIM_SAMPLES: {
            // iceman; since changing fpga_bitstreams clears bigbuff, Its better to call it before.
            // to be able to use this one for uploading data to device
            // flag =
            //    b0  0 skip
            //        1 clear bigbuff
            struct p {
                uint8_t flag;
                uint16_t offset;
                uint8_t *data;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;

            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

            if ((payload->flag & 0x1) == 0x1) {
                BigBuf_Clear_ext(false);
                BigBuf_free();
            }
            uint16_t offset = MIN(BIGBUF_SIZE - PM3_CMD_DATA_SIZE - 3, payload->offset);
            
            // need to copy len bytes of data, not PM3_CMD_DATA_SIZE - 3 - offset
            // ensure len bytes copied wont go past end of bigbuf
            uint16_t len = MIN(BIGBUF_SIZE - offset,PM3_CMD_DATA_SIZE - 3);

            uint8_t *mem = BigBuf_get_addr();
            memcpy(mem + offset, &payload->data, len);
            // memcpy(mem + offset, &payload->data, PM3_CMD_DATA_SIZE - 3 - offset);
            reply_ng(CMD_LF_UPLOAD_SIM_SAMPLES, PM3_SUCCESS, NULL, 0);
            break;
        }
#endif
        case CMD_DOWNLOAD_EML_BIGBUF: {
            LED_B_ON();
            uint8_t *mem = BigBuf_get_EM_addr();
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            for (size_t i = 0; i < numofbytes; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
                int result = reply_old(CMD_DOWNLOADED_EML_BIGBUF, i, len, 0, mem + startidx + i, len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_READ_MEM: {
            if (packet->length != sizeof(uint32_t))
                break;
            ReadMem(packet->data.asDwords[0]);
            break;
        }
#ifdef WITH_FLASH
        case CMD_SPIFFS_TEST: {
            test_spiffs();
            break;
        }
        case CMD_SPIFFS_CHECK: {
            rdv40_spiffs_check();
            break;
        }
        case CMD_SPIFFS_MOUNT: {
            rdv40_spiffs_lazy_mount();
            break;
        }
        case CMD_SPIFFS_UNMOUNT: {
            rdv40_spiffs_lazy_unmount();
            break;
        }
        case CMD_SPIFFS_PRINT_TREE: {
            rdv40_spiffs_safe_print_tree(false);
            break;
        }
        case CMD_SPIFFS_PRINT_FSINFO: {
            rdv40_spiffs_safe_print_fsinfo();
            break;
        }
        case CMD_SPIFFS_DOWNLOAD: {
            LED_B_ON();
            uint8_t filename[32];
            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            if (DBGLEVEL > 1) Dbprintf("> Filename received for spiffs dump : %s", filename);

            //uint32_t size = 0;
            //rdv40_spiffs_stat((char *)filename, (uint32_t *)size,RDV40_SPIFFS_SAFETY_SAFE);
            uint32_t size = packet->oldarg[1];
            //uint8_t buff[size];

            uint8_t *buff = BigBuf_malloc(size);
            rdv40_spiffs_read_as_filetype((char *)filename, (uint8_t *)buff, size, RDV40_SPIFFS_SAFETY_SAFE);

            // arg0 = filename
            // arg1 = size
            // arg2 = RFU

            for (size_t i = 0; i < size; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((size - i), PM3_CMD_DATA_SIZE);
                int result = reply_old(CMD_SPIFFS_DOWNLOADED, i, len, 0, buff + i, len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_STAT: {
            LED_B_ON();
            uint8_t filename[32];
            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            if (DBGLEVEL > 1) Dbprintf("> Filename received for spiffs STAT : %s", filename);
            int changed = rdv40_spiffs_lazy_mount();
            uint32_t size = size_in_spiffs((char *)filename);
            if (changed) rdv40_spiffs_lazy_unmount();
            reply_old(CMD_ACK, size, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_REMOVE: {
            LED_B_ON();
            uint8_t filename[32];
            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            if (DBGLEVEL > 1) Dbprintf("> Filename received for spiffs REMOVE : %s", filename);
            rdv40_spiffs_remove((char *) filename, RDV40_SPIFFS_SAFETY_SAFE);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_RENAME: {
            LED_B_ON();
            uint8_t src[32];
            uint8_t dest[32];
            uint8_t *pfilename = packet->data.asBytes;
            char *token;
            token = strtok((char *)pfilename, ",");
            strncpy((char *)src, token, sizeof(src) - 1);
            token = strtok(NULL, ",");
            strncpy((char *)dest, token, sizeof(dest) - 1);
            if (DBGLEVEL > 1) {
                Dbprintf("> Filename received as source for spiffs RENAME : %s", src);
                Dbprintf("> Filename received as destination for spiffs RENAME : %s", dest);
            }
            rdv40_spiffs_rename((char *) src, (char *)dest, RDV40_SPIFFS_SAFETY_SAFE);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_COPY: {
            LED_B_ON();
            uint8_t src[32];
            uint8_t dest[32];
            uint8_t *pfilename = packet->data.asBytes;
            char *token;
            token = strtok((char *)pfilename, ",");
            strncpy((char *)src, token, sizeof(src) - 1);
            token = strtok(NULL, ",");
            strncpy((char *)dest, token, sizeof(dest) - 1);
            if (DBGLEVEL > 1) {
                Dbprintf("> Filename received as source for spiffs COPY : %s", src);
                Dbprintf("> Filename received as destination for spiffs COPY : %s", dest);
            }
            rdv40_spiffs_copy((char *) src, (char *)dest, RDV40_SPIFFS_SAFETY_SAFE);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_WRITE: {
            LED_B_ON();
            uint8_t filename[32];
            uint32_t append = packet->oldarg[0];
            uint32_t size = packet->oldarg[1];
            uint8_t *data = packet->data.asBytes;

            //rdv40_spiffs_lazy_mount();

            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            data += SPIFFS_OBJ_NAME_LEN;

            if (DBGLEVEL > 1) Dbprintf("> Filename received for spiffs WRITE : %s with APPEND SET TO : %d", filename, append);
            if (!append) {
                rdv40_spiffs_write((char *) filename, (uint8_t *)data, size, RDV40_SPIFFS_SAFETY_SAFE);
            } else {
                rdv40_spiffs_append((char *) filename, (uint8_t *)data, size, RDV40_SPIFFS_SAFETY_SAFE);
            }
            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_SET_SPIBAUDRATE: {
            if (packet->length != sizeof(uint32_t))
                break;
            FlashmemSetSpiBaudrate(packet->data.asDwords[0]);
            break;
        }
        case CMD_FLASHMEM_WRITE: {
            LED_B_ON();
            uint8_t isok = 0;
            uint16_t res = 0;
            uint32_t startidx = packet->oldarg[0];
            uint16_t len = packet->oldarg[1];
            uint8_t *data = packet->data.asBytes;

            if (!FlashInit()) {
                break;
            }

            if (startidx == DEFAULT_T55XX_KEYS_OFFSET) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xC);
            } else if (startidx ==  DEFAULT_MF_KEYS_OFFSET) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0x9);
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xA);
            } else if (startidx == DEFAULT_ICLASS_KEYS_OFFSET) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xB);
            }

            res = Flash_Write(startidx, data, len);
            isok = (res == len) ? 1 : 0;

            reply_old(CMD_ACK, isok, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_WIPE: {
            LED_B_ON();
            uint8_t page = packet->oldarg[0];
            uint8_t initalwipe = packet->oldarg[1];
            bool isok = false;
            if (initalwipe) {
                isok = Flash_WipeMemory();
                reply_old(CMD_ACK, isok, 0, 0, 0, 0);
                LED_B_OFF();
                break;
            }
            if (page < 3)
                isok = Flash_WipeMemoryPage(page);

            reply_old(CMD_ACK, isok, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_DOWNLOAD: {

            LED_B_ON();
            uint8_t *mem = BigBuf_malloc(PM3_CMD_DATA_SIZE);
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];
            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            if (!FlashInit()) {
                break;
            }

            for (size_t i = 0; i < numofbytes; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
                Flash_CheckBusy(BUSY_TIMEOUT);
                bool isok = Flash_ReadDataCont(startidx + i, mem, len);
                if (!isok)
                    Dbprintf("reading flash memory failed ::  | bytes between %d - %d", i, len);

                isok = reply_old(CMD_FLASHMEM_DOWNLOADED, i, len, 0, mem, len);
                if (isok != 0)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d", i, len);
            }
            FlashStop();

            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_INFO: {

            LED_B_ON();
            rdv40_validation_t *info = (rdv40_validation_t *)BigBuf_malloc(sizeof(rdv40_validation_t));

            bool isok = Flash_ReadData(FLASH_MEM_SIGNATURE_OFFSET, info->signature, FLASH_MEM_SIGNATURE_LEN);

            if (FlashInit()) {
                Flash_UniqueID(info->flashid);
                FlashStop();
            }
            reply_old(CMD_ACK, isok, 0, 0, info, sizeof(rdv40_validation_t));
            BigBuf_free();

            LED_B_OFF();
            break;
        }
#endif
        case CMD_LF_SET_DIVISOR: {
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
            FpgaSendCommand(FPGA_CMD_SET_DIVISOR, packet->data.asBytes[0]);
            break;
        }
        case CMD_SET_ADC_MUX: {
            switch (packet->data.asBytes[0]) {
                case 0:
                    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
                    break;
                case 2:
                    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
                    break;
#ifndef WITH_FPC_USART
                case 1:
                    SetAdcMuxFor(GPIO_MUXSEL_LORAW);
                    break;
                case 3:
                    SetAdcMuxFor(GPIO_MUXSEL_HIRAW);
                    break;
#endif
            }
            break;
        }
        case CMD_VERSION: {
            SendVersion();
            break;
        }
        case CMD_STATUS: {
            SendStatus();
            break;
        }
        case CMD_TIA: {

            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf("  Slow clock old measured value:.........%d Hz", (16 * MAINCK) / mainf);
            TimingIntervalAcquisition();

            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf(""); // first message gets lost
            Dbprintf("  Slow clock new measured value:.........%d Hz", (16 * MAINCK) / mainf);
            reply_ng(CMD_TIA, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_STANDALONE: {
            RunMod();
            break;
        }
        case CMD_CAPABILITIES: {
            SendCapabilities();
            break;
        }
        case CMD_PING: {
            reply_ng(CMD_PING, PM3_SUCCESS, packet->data.asBytes, packet->length);
            break;
        }
#ifdef WITH_LCD
        case CMD_LCD_RESET: {
            LCDReset();
            break;
        }
        case CMD_LCD: {
            LCDSend(packet->oldarg[0]);
            break;
        }
#endif
        case CMD_FINISH_WRITE:
        case CMD_HARDWARE_RESET: {
            usb_disable();

            // (iceman) why this wait?
            SpinDelay(1000);
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
            // We're going to reset, and the bootrom will take control.
            for (;;) {}
            break;
        }
        case CMD_START_FLASH: {
            if (common_area.flags.bootrom_present) {
                common_area.command = COMMON_AREA_COMMAND_ENTER_FLASH_MODE;
            }
            usb_disable();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
            // We're going to flash, and the bootrom will take control.
            for (;;) {}
            break;
        }
        case CMD_DEVICE_INFO: {
            uint32_t dev_info = DEVICE_INFO_FLAG_OSIMAGE_PRESENT | DEVICE_INFO_FLAG_CURRENT_MODE_OS;
            if (common_area.flags.bootrom_present) {
                dev_info |= DEVICE_INFO_FLAG_BOOTROM_PRESENT;
            }
            reply_old(CMD_DEVICE_INFO, dev_info, 0, 0, 0, 0);
            break;
        }
        default: {
            Dbprintf("%s: 0x%04x", "unknown command:", packet->cmd);
            break;
        }
    }
}

void  __attribute__((noreturn)) AppMain(void) {

    SpinDelay(100);
    clear_trace();

    if (common_area.magic != COMMON_AREA_MAGIC || common_area.version != 1) {
        /* Initialize common area */
        memset(&common_area, 0, sizeof(common_area));
        common_area.magic = COMMON_AREA_MAGIC;
        common_area.version = 1;
    }
    common_area.flags.osimage_present = 1;

    LEDsoff();

    // The FPGA gets its clock from us from PCK0 output, so set that up.
    AT91C_BASE_PIOA->PIO_BSR = GPIO_PCK0;
    AT91C_BASE_PIOA->PIO_PDR = GPIO_PCK0;
    AT91C_BASE_PMC->PMC_SCER |= AT91C_PMC_PCK0;
    // PCK0 is PLL clock / 4 = 96MHz / 4 = 24MHz
    AT91C_BASE_PMC->PMC_PCKR[0] = AT91C_PMC_CSS_PLL_CLK | AT91C_PMC_PRES_CLK_4; //  4 for 24MHz pck0, 2 for 48 MHZ pck0
    AT91C_BASE_PIOA->PIO_OER = GPIO_PCK0;

    // Reset SPI
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST; // errata says it needs twice to be correctly set.

    // Reset SSC
    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;

    // Configure MUX
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    // Load the FPGA image, which we have stored in our flash.
    // (the HF version by default)
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    StartTickCount();

#ifdef WITH_LCD
    LCDInit();
#endif

#ifdef WITH_SMARTCARD
    I2C_init();
#endif

#ifdef WITH_FPC_USART
    usart_init(USART_BAUD_RATE, USART_PARITY);
#endif

    // This is made as late as possible to ensure enumeration without timeout
    // against device such as http://www.hobbytronics.co.uk/usb-host-board-v2
    usb_disable();
    usb_enable();
    allow_send_wtx = true;

#ifdef WITH_FLASH
    // If flash is not present, BUSY_TIMEOUT kicks in, let's do it after USB
    loadT55xxConfig();

    //
    // Enforce a spiffs check/garbage collection at boot so we are likely to never
    // fall under the 2 contigous free blocks availables
    rdv40_spiffs_check();
#endif

    for (;;) {
        WDT_HIT();

        // Check if there is a packet available
        PacketCommandNG rx;
        memset(&rx.data, 0, sizeof(rx.data));

        int ret = receive_ng(&rx);
        if (ret == PM3_SUCCESS) {
            PacketReceived(&rx);
        } else if (ret != PM3_ENODATA) {

            Dbprintf("Error in frame reception: %d %s", ret, (ret == PM3_EIO) ? "PM3_EIO" : "");
            // TODO if error, shall we resync ?
        }

        // Press button for one second to enter a possible standalone mode
        button_status = BUTTON_HELD(1000);
        if (button_status == BUTTON_HOLD) {
            /*
            * So this is the trigger to execute a standalone mod.  Generic entrypoint by following the standalone/standalone.h headerfile
            * All standalone mod "main loop" should be the RunMod() function.
            */
            allow_send_wtx = false;
            RunMod();
            allow_send_wtx = true;
        }
    }
}
