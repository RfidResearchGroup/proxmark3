//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Miscellaneous routines for low frequency sampling.
//-----------------------------------------------------------------------------

#include "lfsampling.h"

/*
Default LF config is set to:
    decimation = 1  (we keep 1 out of 1 samples)
    bits_per_sample = 8
    averaging = YES
    divisor = 95 (125khz)
    trigger_threshold = 0
    */
sample_config config = { 1, 8, 1, 95, 0 } ;

void printConfig() {
    Dbprintf("LF Sampling config");
    Dbprintf("  [q] divisor.............%d (%d KHz)", config.divisor, 12000 / (config.divisor + 1));
    Dbprintf("  [b] bps.................%d", config.bits_per_sample);
    Dbprintf("  [d] decimation..........%d", config.decimation);
    Dbprintf("  [a] averaging...........%s", (config.averaging) ? "Yes" : "No");
    Dbprintf("  [t] trigger threshold...%d", config.trigger_threshold);
}

/**
 * Called from the USB-handler to set the sampling configuration
 * The sampling config is used for std reading and sniffing.
 *
 * Other functions may read samples and ignore the sampling config,
 * such as functions to read the UID from a prox tag or similar.
 *
 * Values set to '0' implies no change (except for averaging)
 * @brief setSamplingConfig
 * @param sc
 */
void setSamplingConfig(sample_config *sc) {
    if (sc->divisor != 0) config.divisor = sc->divisor;
    if (sc->bits_per_sample != 0) config.bits_per_sample = sc->bits_per_sample;
    if (sc->trigger_threshold != -1) config.trigger_threshold = sc->trigger_threshold;

    config.decimation = (sc->decimation != 0) ? sc->decimation : 1;
    config.averaging = sc->averaging;
    if (config.bits_per_sample > 8) config.bits_per_sample = 8;

    printConfig();
}

sample_config *getSamplingConfig() {
    return &config;
}

struct BitstreamOut {
    uint8_t *buffer;
    uint32_t numbits;
    uint32_t position;
};

/**
 * @brief Pushes bit onto the stream
 * @param stream
 * @param bit
 */
void pushBit(BitstreamOut *stream, uint8_t bit) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = stream->position & 7;
    *(stream->buffer + bytepos) |= (bit > 0) << (7 - bitpos);
    stream->position++;
    stream->numbits++;
}

/**
* Setup the FPGA to listen for samples. This method downloads the FPGA bitstream
* if not already loaded, sets divisor and starts up the antenna.
* @param divisor : 1, 88> 255 or negative ==> 134.8 KHz
*                  0 or 95 ==> 125 KHz
*
**/
void LFSetupFPGAForADC(int divisor, bool lf_field) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    if ((divisor == 1) || (divisor < 0) || (divisor > 255))
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
    else if (divisor == 0)
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    else
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, divisor);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | (lf_field ? FPGA_LF_ADC_READER_FIELD : 0));

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
    // 50ms for the resonant antenna to settle.
    SpinDelay(50);
    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc();
    // start a 1.5ticks is 1us
    StartTicks();
}

/**
 * Does the sample acquisition. If threshold is specified, the actual sampling
 * is not commenced until the threshold has been reached.
 * This method implements decimation and quantization in order to
 * be able to provide longer sample traces.
 * Uses the following global settings:
 * @param decimation - how much should the signal be decimated. A decimation of N means we keep 1 in N samples, etc.
 * @param bits_per_sample - bits per sample. Max 8, min 1 bit per sample.
 * @param averaging If set to true, decimation will use averaging, so that if e.g. decimation is 3, the sample
 * value that will be used is the average value of the three samples.
 * @param trigger_threshold - a threshold. The sampling won't commence until this threshold has been reached. Set
 * to -1 to ignore threshold.
 * @param silent - is true, now outputs are made. If false, dbprints the status
 * @return the number of bits occupied by the samples.
 */
uint32_t DoAcquisition(uint8_t decimation, uint32_t bits_per_sample, bool averaging, int trigger_threshold, bool silent, int bufsize, uint32_t cancel_after) {

    uint8_t *dest = BigBuf_get_addr();
    bufsize = (bufsize > 0 && bufsize < BigBuf_max_traceLen()) ? bufsize : BigBuf_max_traceLen();

    if (bits_per_sample < 1) bits_per_sample = 1;
    if (bits_per_sample > 8) bits_per_sample = 8;

    if (decimation < 1) decimation = 1;

    // use a bit stream to handle the output
    BitstreamOut data = { dest, 0, 0};
    int sample_counter = 0;
    uint8_t sample = 0;

    // if we want to do averaging
    uint32_t sample_sum = 0 ;
    uint32_t sample_total_numbers = 0;
    uint32_t sample_total_saved = 0;
    uint32_t cancel_counter = 0;

    while (!BUTTON_PRESS() && !usb_poll_validate_length()) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

            // Testpoint 8 (TP8) can be used to trigger oscilliscope
            LED_D_OFF();

            // threshold either high or low values 128 = center 0.  if trigger = 178
            if ((trigger_threshold > 0) && (sample < (trigger_threshold + 128)) && (sample > (128 - trigger_threshold))) {
                if (cancel_after > 0) {
                    cancel_counter++;
                    if (cancel_after == cancel_counter)
                        break;
                }
                continue;
            }

            trigger_threshold = 0;
            sample_total_numbers++;

            if (averaging)
                sample_sum += sample;

            // check decimation
            if (decimation > 1) {
                sample_counter++;
                if (sample_counter < decimation) continue;
                sample_counter = 0;
            }

            // averaging
            if (averaging && decimation > 1) {
                sample = sample_sum / decimation;
                sample_sum = 0;
            }

            // store the sample
            sample_total_saved ++;
            if (bits_per_sample == 8) {
                dest[sample_total_saved - 1] = sample;

                // Get the return value correct
                data.numbits = sample_total_saved << 3;
                if (sample_total_saved >= bufsize) break;

            } else {
                pushBit(&data, sample & 0x80);
                if (bits_per_sample > 1) pushBit(&data, sample & 0x40);
                if (bits_per_sample > 2) pushBit(&data, sample & 0x20);
                if (bits_per_sample > 3) pushBit(&data, sample & 0x10);
                if (bits_per_sample > 4) pushBit(&data, sample & 0x08);
                if (bits_per_sample > 5) pushBit(&data, sample & 0x04);
                if (bits_per_sample > 6) pushBit(&data, sample & 0x02);

                if ((data.numbits >> 3) + 1 >= bufsize) break;
            }
        }
    }

    if (!silent) {
        Dbprintf("Done, saved %d out of %d seen samples at %d bits/sample", sample_total_saved, sample_total_numbers, bits_per_sample);
        Dbprintf("buffer samples: %02x %02x %02x %02x %02x %02x %02x %02x ...",
                 dest[0], dest[1], dest[2], dest[3], dest[4], dest[5], dest[6], dest[7]);
    }

    // Ensure that DC offset removal and noise check is performed for any device-side processing
    removeSignalOffset(dest, bufsize);
    computeSignalProperties(dest, bufsize);

    return data.numbits;
}
/**
 * @brief Does sample acquisition, ignoring the config values set in the sample_config.
 * This method is typically used by tag-specific readers who just wants to read the samples
 * the normal way
 * @param trigger_threshold
 * @param silent
 * @return number of bits sampled
 */
uint32_t DoAcquisition_default(int trigger_threshold, bool silent) {
    return DoAcquisition(1, 8, 0, trigger_threshold, silent, 0, 0);
}
uint32_t DoAcquisition_config(bool silent, int sample_size) {
    return DoAcquisition(config.decimation
                         , config.bits_per_sample
                         , config.averaging
                         , config.trigger_threshold
                         , silent
                         , sample_size
                         , 0);
}

uint32_t DoPartialAcquisition(int trigger_threshold, bool silent, int sample_size, uint32_t cancel_after) {
    return DoAcquisition(1, 8, 0, trigger_threshold, silent, sample_size, cancel_after);
}

uint32_t ReadLF(bool activeField, bool silent, int sample_size) {
    if (!silent)
        printConfig();
    LFSetupFPGAForADC(config.divisor, activeField);
    uint32_t ret = DoAcquisition_config(silent, sample_size);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return ret;
}

/**
* Initializes the FPGA for reader-mode (field on), and acquires the samples.
* @return number of bits sampled
**/
uint32_t SampleLF(bool printCfg, int sample_size) {
    BigBuf_Clear_ext(false);
    return ReadLF(true, printCfg, sample_size);
}
/**
* Initializes the FPGA for sniffer-mode (field off), and acquires the samples.
* @return number of bits sampled
**/
uint32_t SniffLF() {
    BigBuf_Clear_ext(false);
    return ReadLF(false, true, 0);
}

/**
* acquisition of T55x7 LF signal. Similar to other LF, but adjusted with @marshmellows thresholds
* the data is collected in BigBuf.
**/
void doT55x7Acquisition(size_t sample_size) {

#define T55xx_READ_UPPER_THRESHOLD 128+60  // 60 grph
#define T55xx_READ_LOWER_THRESHOLD 128-60  // -60 grph
#define T55xx_READ_TOL   5

    uint8_t *dest = BigBuf_get_addr();
    uint16_t bufsize = BigBuf_max_traceLen();

    if (bufsize > sample_size)
        bufsize = sample_size;

    uint8_t curSample = 0, lastSample = 0;
    uint16_t i = 0, skipCnt = 0;
    bool startFound = false;
    bool highFound = false;
    bool lowFound = false;

    while (!BUTTON_PRESS() && !usb_poll_validate_length() && skipCnt < 1000 && (i < bufsize)) {
        WDT_HIT();


        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            curSample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            LED_D_OFF();

            // skip until the first high sample above threshold
            if (!startFound && curSample > T55xx_READ_UPPER_THRESHOLD) {
                //if (curSample > lastSample)
                // lastSample = curSample;
                highFound = true;
            } else if (!highFound) {
                skipCnt++;
                continue;
            }
            // skip until the first low sample below threshold
            if (!startFound && curSample < T55xx_READ_LOWER_THRESHOLD) {
                //if (curSample > lastSample)
                lastSample = curSample;
                lowFound = true;
            } else if (!lowFound) {
                skipCnt++;
                continue;
            }

            // skip until first high samples begin to change
            if (startFound || curSample > T55xx_READ_LOWER_THRESHOLD + T55xx_READ_TOL) {
                // if just found start - recover last sample
                if (!startFound) {
                    dest[i++] = lastSample;
                    startFound = true;
                }
                // collect samples
                dest[i++] = curSample;
            }
        }
    }
}
/**
* acquisition of Cotag LF signal. Similart to other LF,  since the Cotag has such long datarate RF/384
* and is Manchester?,  we directly gather the manchester data into bigbuff
**/

#define COTAG_T1 384
#define COTAG_T2 (COTAG_T1>>1)
#define COTAG_ONE_THRESHOLD 128+30
#define COTAG_ZERO_THRESHOLD 128-30
#ifndef COTAG_BITS
#define COTAG_BITS 264
#endif
void doCotagAcquisition(size_t sample_size) {

    uint8_t *dest = BigBuf_get_addr();
    uint16_t bufsize = BigBuf_max_traceLen();

    if (bufsize > sample_size)
        bufsize = sample_size;

    dest[0] = 0;
    uint8_t sample = 0, firsthigh = 0, firstlow = 0;
    uint16_t i = 0;
    uint16_t noise_counter = 0;

    while (!BUTTON_PRESS() && !usb_poll_validate_length() && (i < bufsize) && (noise_counter < (COTAG_T1 << 1))) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

            // find first peak
            if (!firsthigh) {
                if (sample < COTAG_ONE_THRESHOLD) {
                    noise_counter++;
                    continue;
                }
                noise_counter = 0;
                firsthigh = 1;
            }
            if (!firstlow) {
                if (sample > COTAG_ZERO_THRESHOLD) {
                    noise_counter++;
                    continue;
                }
                noise_counter = 0;
                firstlow = 1;
            }

            ++i;

            if (sample > COTAG_ONE_THRESHOLD)
                dest[i] = 255;
            else if (sample < COTAG_ZERO_THRESHOLD)
                dest[i] = 0;
            else
                dest[i] = dest[i - 1];
        }
    }
}

uint32_t doCotagAcquisitionManchester() {

    uint8_t *dest = BigBuf_get_addr();
    uint16_t bufsize = BigBuf_max_traceLen();

    if (bufsize > COTAG_BITS)
        bufsize = COTAG_BITS;

    dest[0] = 0;
    uint8_t sample = 0, firsthigh = 0, firstlow = 0;
    uint16_t sample_counter = 0, period = 0;
    uint8_t curr = 0, prev = 0;
    uint16_t noise_counter = 0;

    while (!BUTTON_PRESS() && !usb_poll_validate_length() && (sample_counter < bufsize)  && (noise_counter < (COTAG_T1 << 1))) {
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

            // find first peak
            if (!firsthigh) {
                if (sample < COTAG_ONE_THRESHOLD) {
                    noise_counter++;
                    continue;
                }
                noise_counter = 0;
                firsthigh = 1;
            }

            if (!firstlow) {
                if (sample > COTAG_ZERO_THRESHOLD) {
                    noise_counter++;
                    continue;
                }
                noise_counter = 0;
                firstlow = 1;
            }

            // set sample 255, 0,  or previous
            if (sample > COTAG_ONE_THRESHOLD) {
                prev = curr;
                curr = 1;
            } else if (sample < COTAG_ZERO_THRESHOLD) {
                prev = curr;
                curr = 0;
            } else {
                curr = prev;
            }

            // full T1 periods,
            if (period > 0) {
                --period;
                continue;
            }

            dest[sample_counter] = curr;
            ++sample_counter;
            period = COTAG_T1;
        }
    }
    return sample_counter;
}
