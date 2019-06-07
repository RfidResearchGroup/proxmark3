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
#include <stdarg.h>
#include <inttypes.h>
#include "usb_cdc.h"
#include "proxmark3.h"
#include "apps.h"
#include "fpga.h"
#include "util.h"
#include "printf.h"
#include "string.h"
#include "legicrf.h"
#include "legicrfsim.h"
#include "lfsampling.h"
#include "BigBuf.h"
#include "mifareutil.h"
#include "mifaresim.h"
#include "hitag.h"

#define DEBUG 1

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

/* useful when debugging new protocol implementations like FeliCa
void PrintToSendBuffer(void) {
    DbpString("Printing ToSendBuffer:");
    Dbhexdump(ToSendMax, ToSend, 0);
}
*/

void print_result(char *name, uint8_t *buf, size_t len) {

    uint8_t *p = buf;
    uint16_t tmp = len & 0xFFF0;

    for (; p - buf < tmp; p += 16) {
        Dbprintf("[%s: %02d/%02d] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 name,
                 p - buf,
                 len,
                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]
                );
    }
    if (len % 16 != 0) {
        char s[46] = {0};
        char *sp = s;
        for (; p - buf < len; p++) {
            sprintf(sp, "%02x ", p[0]);
            sp += 3;
        }
        Dbprintf("[%s: %02d/%02d] %s", name, p - buf, len, s);
    }
}

//=============================================================================
// Debug print functions, to go out over USB, to the usual PC-side client.
//=============================================================================

void DbpStringEx(uint32_t flags, char *str) {
#if DEBUG
    struct {
        uint16_t flag;
        uint8_t buf[PM3_CMD_DATA_SIZE - sizeof(uint16_t)];
    } PACKED data;
    data.flag = flags;
    uint16_t len = MIN(strlen(str), sizeof(data.buf));
    memcpy(data.buf, str, len);
    reply_ng(CMD_DEBUG_PRINT_STRING, PM3_SUCCESS, (uint8_t *)&data, sizeof(data.flag) + len);
#endif
}

void DbpString(char *str) {
#if DEBUG
    DbpStringEx(FLAG_LOG, str);
#endif
}

#if 0
void DbpIntegers(int x1, int x2, int x3) {
    reply_old(CMD_DEBUG_PRINT_INTEGERS, x1, x2, x3, 0, 0);
}
#endif
void DbprintfEx(uint32_t flags, const char *fmt, ...) {
#if DEBUG
    // should probably limit size here; oh well, let's just use a big buffer
    char output_string[128] = {0x00};
    va_list ap;
    va_start(ap, fmt);
    kvsprintf(fmt, output_string, 10, ap);
    va_end(ap);

    DbpStringEx(flags, output_string);
#endif
}

void Dbprintf(const char *fmt, ...) {
#if DEBUG
    // should probably limit size here; oh well, let's just use a big buffer
    char output_string[128] = {0x00};
    va_list ap;

    va_start(ap, fmt);
    kvsprintf(fmt, output_string, 10, ap);
    va_end(ap);

    DbpString(output_string);
#endif
}

// prints HEX & ASCII
void Dbhexdump(int len, uint8_t *d, bool bAsci) {
#if DEBUG
    char ascii[9];

    while (len > 0) {

        int l = (len > 8) ? 8 : len;

        memcpy(ascii, d, l);
        ascii[l] = 0;

        // filter safe ascii
        for (int i = 0; i < l; i++) {
            if (ascii[i] < 32 || ascii[i] > 126) {
                ascii[i] = '.';
            }
        }

        if (bAsci)
            Dbprintf("%-8s %*D", ascii, l, d, " ");
        else
            Dbprintf("%*D", l, d, " ");

        len -= 8;
        d += 8;
    }
#endif
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

    uint8_t LF_Results[256];
    uint32_t i, peak = 0, peakv = 0, peakf = 0;
    uint32_t v_lf125 = 0, v_lf134 = 0, v_hf = 0; // in mV

    memset(LF_Results, 0, sizeof(LF_Results));
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

    for (i = 255; i >= 19; i--) {
        WDT_HIT();
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, i);
        SpinDelay(20);
        uint32_t adcval = ((MAX_ADC_LF_VOLTAGE * AvgAdc(ADC_CHAN_LF)) >> 10);
        if (i == 95)
            v_lf125 = adcval; // voltage at 125Khz
        if (i == 89)
            v_lf134 = adcval; // voltage at 134Khz

        LF_Results[i] = adcval >> 9; // scale int to fit in byte for graphing purposes
        if (LF_Results[i] > peak) {
            peakv = adcval;
            peakf = i;
            peak = LF_Results[i];
        }
    }

    LED_A_ON();
    // Let the FPGA drive the high-frequency antenna around 13.56 MHz.
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
    SpinDelay(50);
    v_hf = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;

    // RDV40 will hit the roof, try other ADC channel used in that hardware revision.
    if (v_hf > MAX_ADC_HF_VOLTAGE - 300) {
        v_hf = (MAX_ADC_HF_VOLTAGE_RDV40 * AvgAdc(ADC_CHAN_HF_RDV40)) >> 10;
    }

    uint64_t arg0 = v_lf134;
    arg0 <<= 32;
    arg0 |= v_lf125;

    uint64_t arg2 = peakv;
    arg2 <<= 32;
    arg2 |= peakf;

    reply_mix(CMD_MEASURE_ANTENNA_TUNING, arg0, v_hf, arg2, LF_Results, 256);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

uint16_t MeasureAntennaTuningHfData(void) {
    uint16_t volt = 0; // in mV
    volt = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;
    bool use_high = (volt > MAX_ADC_HF_VOLTAGE - 300);

    if (!use_high) {
        volt = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;
    } else {
        volt = (MAX_ADC_HF_VOLTAGE_RDV40 * AvgAdc(ADC_CHAN_HF_RDV40)) >> 10;
    }
    return volt;
}

void ReadMem(int addr) {
    const uint8_t *data = ((uint8_t *)addr);

    Dbprintf("%x: %02x %02x %02x %02x %02x %02x %02x %02x", addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
}

/* osimage version information is linked in */
extern struct version_information version_information;
/* bootrom version information is pointed to from _bootphase1_version_pointer */
extern char *_bootphase1_version_pointer, _flash_start, _flash_end, _bootrom_start, _bootrom_end, __data_src_start__;
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
        FormatVersionInformation(temp, sizeof(temp), " bootrom: ", bootrom_version);
        strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
    }

    FormatVersionInformation(temp, sizeof(temp), "      os: ", &version_information);
    strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);

    strncat(VersionString, "\n [ FPGA ]\n", sizeof(VersionString) - strlen(VersionString) - 1);

    for (int i = 0; i < fpga_bitstream_num; i++) {
        strncat(VersionString, fpga_version_information[i], sizeof(VersionString) - strlen(VersionString) - 1);
        if (i < fpga_bitstream_num - 1) {
            strncat(VersionString, "\n", sizeof(VersionString) - strlen(VersionString) - 1);
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
    payload.versionstr_len = strlen(VersionString);
    memcpy(payload.versionstr, VersionString, strlen(VersionString));

    reply_ng(CMD_VERSION, PM3_SUCCESS, (uint8_t *)&payload, 12 + strlen(VersionString));
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
    DbpString(_BLUE_("Installed StandAlone Mode"));
    ModInfo();

#ifdef WITH_FLASH
    Flashmem_print_info();
#endif

    reply_old(CMD_ACK, 1, 0, 0, 0, 0);
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
#ifdef WITH_LCD
    capabilities.compiled_with_lcd = true;
#else
    capabilities.compiled_with_lcd = false;
#endif
    reply_ng(CMD_CAPABILITIES, PM3_SUCCESS, (uint8_t *)&capabilities, sizeof(capabilities));
}

// Show some leds in a pattern to identify StandAlone mod is running
void StandAloneMode(void) {

    DbpString("Stand-alone mode! No PC necessary.");

    SpinDown(50);
    SpinOff(50);
    SpinUp(50);
    SpinOff(50);
    SpinDown(50);
    SpinDelay(500);
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
        case CMD_SET_LF_T55XX_CONFIG: {
            setT55xxConfig(packet->oldarg[0], (t55xx_config *) packet->data.asBytes);
            break;
        }
        case CMD_SET_LF_SAMPLING_CONFIG: {
            setSamplingConfig((sample_config *) packet->data.asBytes);
            break;
        }
        case CMD_ACQUIRE_RAW_ADC_SAMPLES_125K: {
            struct p {
                uint8_t silent;
                uint32_t samples;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            uint32_t bits = SampleLF(payload->silent, payload->samples);
            reply_ng(CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, PM3_SUCCESS, (uint8_t *)&bits, sizeof(bits));
            break;
        }
        case CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K: {
            struct p {
                uint32_t delay;
                uint16_t ones;
                uint16_t zeros;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            ModThenAcquireRawAdcSamples125k(payload->delay, payload->zeros, payload->ones, packet->data.asBytes + 8);
            break;
        }
        case CMD_LF_SNIFF_RAW_ADC_SAMPLES: {
            uint32_t bits = SniffLF();
            reply_mix(CMD_ACK, bits, 0, 0, 0, 0);
            break;
        }
        case CMD_HID_DEMOD_FSK: {
            uint32_t high, low;
            CmdHIDdemodFSK(packet->oldarg[0], &high, &low, 1);
            break;
        }
        case CMD_HID_SIM_TAG: {
            CmdHIDsimTAG(packet->oldarg[0], packet->oldarg[1], 1);
            break;
        }
        case CMD_FSK_SIM_TAG: {
            lf_fsksim_t *payload = (lf_fsksim_t *)packet->data.asBytes;
            CmdFSKsimTAG(payload->fchigh, payload->fclow, payload->separator, payload->clock, packet->length - sizeof(lf_fsksim_t), payload->data, true);
            break;
        }
        case CMD_ASK_SIM_TAG: {
            lf_asksim_t *payload = (lf_asksim_t *)packet->data.asBytes;
            CmdASKsimTAG(payload->encoding, payload->invert, payload->separator, payload->clock, packet->length - sizeof(lf_asksim_t), payload->data, true);
            break;
        }
        case CMD_PSK_SIM_TAG: {
            lf_psksim_t *payload = (lf_psksim_t *)packet->data.asBytes;
            CmdPSKsimTag(payload->carrier, payload->invert, payload->clock, packet->length - sizeof(lf_psksim_t), payload->data, true);
            break;
        }
        case CMD_HID_CLONE_TAG: {
            CopyHIDtoT55x7(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes[0]);
            break;
        }
        case CMD_IO_DEMOD_FSK: {
            uint32_t high, low;
            CmdIOdemodFSK(packet->oldarg[0], &high, &low, 1);
            break;
        }
        case CMD_IO_CLONE_TAG: {
            CopyIOtoT55x7(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_EM410X_DEMOD: {
            uint32_t high;
            uint64_t low;
            CmdEM410xdemod(packet->oldarg[0], &high, &low, 1);
            break;
        }
        case CMD_EM410X_WRITE_TAG: {
            WriteEM410x(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_READ_TI_TYPE: {
            ReadTItag();
            break;
        }
        case CMD_WRITE_TI_TYPE: {
            WriteTItag(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_SIMULATE_TAG_125K: {
            LED_A_ON();
            struct p {
                uint16_t len;
                uint16_t gap;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            // length, start gap, led control
            SimulateTagLowFrequency(payload->len, payload->gap, 1);
            reply_ng(CMD_SIMULATE_TAG_125K, PM3_EOPABORTED, NULL, 0);
            LED_A_OFF();
            break;
        }
        case CMD_LF_SIMULATE_BIDIR: {
            SimulateTagLowFrequencyBidir(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_INDALA_CLONE_TAG: {
            CopyIndala64toT55x7(packet->data.asDwords[0], packet->data.asDwords[1]);
            break;
        }
        case CMD_INDALA_CLONE_TAG_L: {
            CopyIndala224toT55x7(
                packet->data.asDwords[0], packet->data.asDwords[1], packet->data.asDwords[2], packet->data.asDwords[3],
                packet->data.asDwords[4], packet->data.asDwords[5], packet->data.asDwords[6]
            );
            break;
        }
        case CMD_T55XX_READ_BLOCK: {
            struct p {
                uint32_t password;
                uint8_t blockno;
                uint8_t page;
                bool pwdmode;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            T55xxReadBlock(payload->page, payload->pwdmode, false, payload->blockno, payload->password);
            break;
        }
        case CMD_T55XX_WRITE_BLOCK: {
            // uses NG format
            T55xxWriteBlock(packet->data.asBytes);
            break;
        }
        case CMD_T55XX_WAKEUP: {
            T55xxWakeUp(packet->oldarg[0]);
            break;
        }
        case CMD_T55XX_RESET_READ: {
            T55xxResetRead();
            break;
        }
        case CMD_T55XX_CHKPWDS: {
            T55xx_ChkPwds();
            break;
        }
        case CMD_PCF7931_READ: {
            ReadPCF7931();
            break;
        }
        case CMD_PCF7931_WRITE: {
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
        case CMD_EM4X_READ_WORD: {
            struct p {
                uint32_t password;
                uint8_t address;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xReadWord(payload->address, payload->password, payload->usepwd);
            break;
        }
        case CMD_EM4X_WRITE_WORD: {
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
        case CMD_AWID_DEMOD_FSK:  {
            uint32_t high, low;
            // Set realtime AWID demodulation
            CmdAWIDdemodFSK(packet->oldarg[0], &high, &low, 1);
            break;
        }
        case CMD_VIKING_CLONE_TAG: {
            CopyVikingtoT55xx(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_COTAG: {
            Cotag(packet->oldarg[0]);
            break;
        }
#endif

#ifdef WITH_HITAG
        case CMD_SNIFF_HITAG: { // Eavesdrop Hitag tag, args = type
            SniffHitag();
            break;
        }
        case CMD_SIMULATE_HITAG: { // Simulate Hitag tag, args = memory content
            SimulateHitagTag((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_READER_HITAG: { // Reader for Hitag tags, args = type and function
            ReaderHitag((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes);
            break;
        }
        case CMD_SIMULATE_HITAG_S: { // Simulate Hitag s tag, args = memory content
            SimulateHitagSTag((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_TEST_HITAGS_TRACES: { // Tests every challenge within the given file
            check_challenges((bool)packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_READ_HITAG_S: { //Reader for only Hitag S tags, args = key or challenge
            ReadHitagS((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes);
            break;
        }
        case CMD_WR_HITAG_S: { //writer for Hitag tags args=data to write,page and key or challenge
            if ((hitag_function)packet->oldarg[0] < 10) {
                WritePageHitagS((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes, packet->oldarg[2]);
            } else {
                WriterHitag((hitag_function)packet->oldarg[0], (hitag_data *)packet->data.asBytes, packet->oldarg[2]);
            }
            break;
        }
#endif

#ifdef WITH_ISO15693
        case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693: {
            AcquireRawAdcSamplesIso15693();
            break;
        }
        case CMD_RECORD_RAW_ADC_SAMPLES_ISO_15693: {
            RecordRawAdcSamplesIso15693();
            break;
        }
        case CMD_ISO_15693_COMMAND: {
            DirectTag15693Command(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_ISO_15693_FIND_AFI: {
            BruteforceIso15693Afi(packet->oldarg[0]);
            break;
        }
        case CMD_READER_ISO_15693: {
            ReaderIso15693(packet->oldarg[0]);
            break;
        }
        case CMD_SIMTAG_ISO_15693: {
            SimTagIso15693(packet->oldarg[0], packet->data.asBytes);
            break;
        }
#endif

#ifdef WITH_LEGICRF
        case CMD_SIMULATE_TAG_LEGIC_RF: {
            LegicRfSimulate(packet->oldarg[0]);
            break;
        }
        case CMD_WRITER_LEGIC_RF: {
            LegicRfWriter(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_READER_LEGIC_RF: {
            LegicRfReader(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_LEGIC_INFO: {
            LegicRfInfo();
            break;
        }
        case CMD_LEGIC_ESET: {
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
        case CMD_READ_SRI_TAG: {
            ReadSTMemoryIso14443b(packet->oldarg[0]);
            break;
        }
        case CMD_SNIFF_ISO_14443B: {
            SniffIso14443b();
            break;
        }
        case CMD_SIMULATE_TAG_ISO_14443B: {
            SimulateIso14443bTag(packet->oldarg[0]);
            break;
        }
        case CMD_ISO_14443B_COMMAND: {
            //SendRawCommand14443B(packet->oldarg[0],packet->oldarg[1],packet->oldarg[2],packet->data.asBytes);
            SendRawCommand14443B_Ex(packet);
            break;
        }
#endif

#ifdef WITH_FELICA
        case CMD_FELICA_COMMAND: {
            felica_sendraw(packet);
            break;
        }
        case CMD_FELICA_LITE_SIM: {
            felica_sim_lite(packet->oldarg[0]);
            break;
        }
        case CMD_FELICA_SNIFF: {
            felica_sniff(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_FELICA_LITE_DUMP: {
            felica_dump_lite_s();
            break;
        }
#endif

#ifdef WITH_ISO14443a
        case CMD_SNIFF_ISO_14443a: {
            SniffIso14443a(packet->data.asBytes[0]);
            break;
        }
        case CMD_READER_ISO_14443a: {
            ReaderIso14443a(packet);
            break;
        }
        case CMD_SIMULATE_TAG_ISO_14443a: {
            struct p {
                uint8_t tagtype;
                uint8_t flags;
                uint8_t uid[10];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimulateIso14443aTag(payload->tagtype, payload->flags, payload->uid);  // ## Simulate iso14443a tag - pass tag type & UID
            break;
        }
        case CMD_ANTIFUZZ_ISO_14443a: {
            iso14443a_antifuzz(packet->oldarg[0]);
            break;
        }
        case CMD_EPA_PACE_COLLECT_NONCE: {
            EPA_PACE_Collect_Nonce(packet);
            break;
        }
        case CMD_EPA_PACE_REPLAY: {
            EPA_PACE_Replay(packet);
            break;
        }
        case CMD_READER_MIFARE: {
            ReaderMifare(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
            break;
        }
        case CMD_MIFARE_READBL: {
            mf_readblock_t *payload = (mf_readblock_t *)packet->data.asBytes;
            MifareReadBlock(payload->blockno, payload->keytype, payload->key);
            break;
        }
        case CMD_MIFAREU_READBL: {
            MifareUReadBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFAREUC_AUTH: {
            MifareUC_Auth(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_MIFAREU_READCARD: {
            MifareUReadCard(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_MIFAREUC_SETPWD: {
            MifareUSetPwd(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_READSC: {
            MifareReadSector(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_WRITEBL: {
            MifareWriteBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        //case CMD_MIFAREU_WRITEBL_COMPAT: {
        //MifareUWriteBlockCompat(packet->oldarg[0], packet->data.asBytes);
        //break;
        //}
        case CMD_MIFAREU_WRITEBL: {
            MifareUWriteBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_ACQUIRE_ENCRYPTED_NONCES: {
            MifareAcquireEncryptedNonces(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_ACQUIRE_NONCES: {
            MifareAcquireNonces(packet->oldarg[0], packet->oldarg[2]);
            break;
        }
        case CMD_MIFARE_NESTED: {
            MifareNested(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_CHKKEYS: {
            MifareChkKeys(packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_CHKKEYS_FAST: {
            MifareChkKeys_fast(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_SIMULATE_MIFARE_CARD: {
            struct p {
                uint16_t flags;
                uint8_t exitAfter;
                uint8_t uid[10];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            Mifare1ksim(payload->flags, payload->exitAfter, payload->uid);
            break;
        }
        // emulator
        case CMD_SET_DBGMODE: {
            DBGLEVEL = packet->data.asBytes[0];
            Dbprintf("Debug level: %d", DBGLEVEL);
            reply_ng(CMD_SET_DBGMODE, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_MIFARE_EML_MEMCLR: {
            MifareEMemClr();
            reply_ng(CMD_MIFARE_EML_MEMCLR, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_MIFARE_EML_MEMSET: {
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
        case CMD_MIFARE_EML_MEMGET: {
            struct p {
                uint8_t blockno;
                uint8_t blockcnt;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareEMemGet(payload->blockno, payload->blockcnt);
            break;
        }
        case CMD_MIFARE_EML_CARDLOAD: {
            MifareECardLoad(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        // Work with "magic Chinese" card
        case CMD_MIFARE_CSETBLOCK: {
            MifareCSetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_CGETBLOCK: {
            MifareCGetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_CIDENT: {
            MifareCIdent();
            break;
        }
        // mifare sniffer
//        case CMD_MIFARE_SNIFFER: {
//            SniffMifare(packet->oldarg[0]);
//            break;
//        }
        case CMD_MIFARE_SETMOD: {
            MifareSetMod(packet->data.asBytes);
            break;
        }
        //mifare desfire
        case CMD_MIFARE_DESFIRE_READBL: {
            break;
        }
        case CMD_MIFARE_DESFIRE_WRITEBL: {
            break;
        }
        case CMD_MIFARE_DESFIRE_AUTH1: {
            MifareDES_Auth1(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_DESFIRE_AUTH2: {
            //MifareDES_Auth2(packet->oldarg[0],packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_DES_READER: {
            //readermifaredes(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_DESFIRE_INFO: {
            MifareDesfireGetInformation();
            break;
        }
        case CMD_MIFARE_DESFIRE: {
            MifareSendCommand(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_MIFARE_COLLECT_NONCES: {
            break;
        }
        case CMD_MIFARE_NACK_DETECT: {
            DetectNACKbug();
            break;
        }
#endif

#ifdef WITH_ICLASS
        // Makes use of ISO14443a FPGA Firmware
        case CMD_SNIFF_ICLASS: {
            SniffIClass();
            break;
        }
        case CMD_SIMULATE_TAG_ICLASS: {
            SimulateIClass(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_READER_ICLASS: {
            ReaderIClass(packet->oldarg[0]);
            break;
        }
        case CMD_READER_ICLASS_REPLAY: {
            ReaderIClass_Replay(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_ICLASS_EML_MEMSET: {
            //iceman, should call FPGADOWNLOAD before, since it corrupts BigBuf
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            emlSet(packet->data.asBytes, packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_ICLASS_WRITEBLOCK: {
            iClass_WriteBlock(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_ICLASS_READCHECK: { // auth step 1
            iClass_ReadCheck(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_ICLASS_READBLOCK: {
            iClass_ReadBlk(packet->oldarg[0]);
            break;
        }
        case CMD_ICLASS_AUTHENTICATION: { //check
            iClass_Authentication(packet->data.asBytes);
            break;
        }
        case CMD_ICLASS_CHECK_KEYS: {
            iClass_Authentication_fast(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_ICLASS_DUMP: {
            iClass_Dump(packet->oldarg[0], packet->oldarg[1]);
            break;
        }
        case CMD_ICLASS_CLONE: {
            iClass_Clone(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
#endif

#ifdef WITH_HFSNIFF
        case CMD_HF_SNIFFER: {
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
        case CMD_UPLOAD_SIM_SAMPLES_125K: {
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

            uint8_t *mem = BigBuf_get_addr();
            memcpy(mem + payload->offset, &payload->data, PM3_CMD_DATA_SIZE - 3);
            reply_ng(CMD_UPLOAD_SIM_SAMPLES_125K, PM3_SUCCESS, NULL, 0);
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
        case CMD_FLASHMEM_SET_SPIBAUDRATE: {
            FlashmemSetSpiBaudrate(packet->oldarg[0]);
            break;
        }
        case CMD_FLASHMEM_READ: {
            LED_B_ON();
            uint32_t startidx = packet->oldarg[0];
            uint16_t len = packet->oldarg[1];

            Dbprintf("FlashMem read | %d - %d | ", startidx, len);

            size_t size = MIN(PM3_CMD_DATA_SIZE, len);

            if (!FlashInit()) {
                break;
            }

            uint8_t *mem = BigBuf_malloc(size);

            for (size_t i = 0; i < len; i += size) {
                len = MIN((len - i), size);

                Dbprintf("FlashMem reading  | %d | %d | %d |", startidx + i, i, len);
                uint16_t isok = Flash_ReadDataCont(startidx + i, mem, len);
                if (isok == len) {
                    print_result("Chunk: ", mem, len);
                } else {
                    Dbprintf("FlashMem reading failed | %d | %d", len, isok);
                    break;
                }
            }
            BigBuf_free();
            FlashStop();
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_WRITE: {
            LED_B_ON();
            uint8_t isok = 0;
            uint16_t res = 0;
            uint32_t startidx = packet->oldarg[0];
            uint16_t len = packet->oldarg[1];
            uint8_t *data = packet->data.asBytes;

            uint32_t tmp = startidx + len;

            if (!FlashInit()) {
                break;
            }

            Flash_CheckBusy(BUSY_TIMEOUT);
            Flash_WriteEnable();

            if (startidx == DEFAULT_T55XX_KEYS_OFFSET) {
                Flash_Erase4k(3, 0xC);
            } else if (startidx ==  DEFAULT_MF_KEYS_OFFSET) {
                Flash_Erase4k(3, 0x9);
                Flash_Erase4k(3, 0xA);
            } else if (startidx == DEFAULT_ICLASS_KEYS_OFFSET) {
                Flash_Erase4k(3, 0xB);
            }

            Flash_CheckBusy(BUSY_TIMEOUT);
            Flash_WriteEnable();

            // inside 256b page?
            if ((tmp & 0xFF) != 0) {

                // is offset+len larger than a page
                tmp = (startidx & 0xFF) + len;
                if (tmp > 0xFF) {

                    // data spread over two pages.

                    // offset xxxx10,
                    uint8_t first_len = (~startidx & 0xFF) + 1;

                    // first mem page
                    res = Flash_WriteDataCont(startidx, data, first_len);

                    isok = (res == first_len) ? 1 : 0;

                    // second mem page
                    res = Flash_WriteDataCont(startidx + first_len, data + first_len, len - first_len);

                    isok &= (res == (len - first_len)) ? 1 : 0;

                } else {
                    res = Flash_WriteDataCont(startidx, data, len);
                    isok = (res == len) ? 1 : 0;
                }
            } else {
                res = Flash_WriteDataCont(startidx, data, len);
                isok = (res == len) ? 1 : 0;
            }
            FlashStop();

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
        case CMD_SET_LF_DIVISOR: {
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
        case CMD_SETUP_WRITE:
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
    // PCK0 is PLL clock / 4 = 96Mhz / 4 = 24Mhz
    AT91C_BASE_PMC->PMC_PCKR[0] = AT91C_PMC_CSS_PLL_CLK | AT91C_PMC_PRES_CLK_4; //  4 for 24Mhz pck0, 2 for 48 MHZ pck0
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

#ifdef WITH_FLASH
    // If flash is not present, BUSY_TIMEOUT kicks in, let's do it after USB
    loadT55xxConfig();
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
            RunMod();
        }
    }
}
