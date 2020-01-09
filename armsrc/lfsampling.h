#ifndef __LFSAMPLING_H
#define __LFSAMPLING_H

#include "common.h"
#include "pm3_cmd.h"

typedef struct {
    uint8_t *buffer;
    uint32_t numbits;
    uint32_t position;
} BitstreamOut;

typedef struct {
    int dec_counter;
    uint32_t sum;
    uint32_t counter;
    uint32_t total_saved;
} sampling_t;

/**
* acquisition of Cotag LF signal. Similar to other LF,  since the Cotag has such long datarate RF/384
* and is Manchester?,  we directly gather the manchester data into bigbuff
**/
void doCotagAcquisition(size_t sample_size);
uint32_t doCotagAcquisitionManchester(void);

/**
* acquisition of T55x7 LF signal. Similar to other LF, but adjusted with @marshmellows thresholds
* the data is collected in BigBuf.
**/
void doT55x7Acquisition(size_t sample_size);

/**
* Initializes the FPGA for reader-mode (field on), and acquires the samples.
* @return number of bits sampled
**/
uint32_t SampleLF(bool verbose, uint32_t sample_size);

/**
* Initializes the FPGA for sniff-mode (field off), and acquires the samples.
* @return number of bits sampled
**/
uint32_t SniffLF();

uint32_t DoAcquisition(uint8_t decimation, uint8_t bits_per_sample, bool avg, int16_t trigger_threshold,
                       bool verbose, uint32_t sample_size, uint32_t cancel_after, int32_t samples_to_skip);

// adds sample size to default options
uint32_t DoPartialAcquisition(int trigger_threshold, bool verbose, uint32_t sample_size, uint32_t cancel_after);

/**
 * @brief Does sample acquisition, ignoring the config values set in the sample_config.
 * This method is typically used by tag-specific readers who just wants to read the samples
 * the normal way
 * @param trigger_threshold
 * @param verbose
 * @return number of bits sampled
 */
uint32_t DoAcquisition_default(int trigger_threshold, bool verbose);
/**
 * @brief Does sample acquisition, using the config values set in the sample_config.
 * @param trigger_threshold
 * @param verbose
 * @return number of bits sampled
 */

uint32_t DoAcquisition_config(bool verbose, uint32_t sample_size);

/**
 * Refactoring of lf sampling buffer
 */
void initSampleBuffer(uint32_t *sample_size);
void logSample(uint8_t sample, uint8_t decimation, uint8_t bits_per_sample, bool avg);
uint32_t getSampleCounter();

/**
* Setup the FPGA to listen for samples. This method downloads the FPGA bitstream
* if not already loaded, sets divisor and starts up the antenna.
* @param divisor : 1, 88> 255 or negative ==> 134.8 kHz
*                  0 or 95 ==> 125 kHz
*
**/
void LFSetupFPGAForADC(int divisor, bool lf_field);

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
void setSamplingConfig(sample_config *sc);

sample_config *getSamplingConfig();

void printConfig();

#endif // __LFSAMPLING_H
