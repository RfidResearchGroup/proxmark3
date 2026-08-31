//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, April 2006
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//-----------------------------------------------------------------------------
#include "fpga_loader.h"
#include "fpga_apis.h"

#include "proxmark3_arm.h"
#include "appmain.h"
#include "BigBuf.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "fpga.h"
#include "string.h"

#include "lz4.h"       // uncompress

typedef struct {
    LZ4_streamDecode_t *lz4StreamDecode;
    char *next_in;
    int avail_in;
} lz4_stream_t;

typedef lz4_stream_t *lz4_streamp_t;

// this is where the bitstreams are located in memory:
extern uint32_t _binary_obj_fpga_all_bit_z_start[], _binary_obj_fpga_all_bit_z_end[];

static uint8_t *fpga_image_ptr = NULL;
static uint32_t uncompressed_bytes_cnt;

// remember which version of the bitstream we have already downloaded to the FPGA
// For high-capacity FPGA chips, the FPGA firmware may have been merged,
// and this flag can let us know which mode it is running in?
static int downloaded_bitstream = FPGA_BITSTREAM_UNKNOWN;

//----------------------------------------------------------------------------
// Uncompress (inflate) the FPGA data. Returns one decompressed byte with each call.
//----------------------------------------------------------------------------
static int get_from_fpga_combined_stream(lz4_streamp_t compressed_fpga_stream, uint8_t *output_buffer) {
    if (fpga_image_ptr == output_buffer + FPGA_RING_BUFFER_BYTES) { // need more data
        fpga_image_ptr = output_buffer;
        int cmp_bytes;
        memcpy(&cmp_bytes, compressed_fpga_stream->next_in, sizeof(int));
        compressed_fpga_stream->next_in += 4;
        compressed_fpga_stream->avail_in -= cmp_bytes + 4;
        int res = LZ4_decompress_safe_continue(compressed_fpga_stream->lz4StreamDecode,
                                               compressed_fpga_stream->next_in,
                                               (char *)output_buffer,
                                               cmp_bytes,
                                               FPGA_RING_BUFFER_BYTES);
        if (res <= 0) {
            Dbprintf("inflate returned: %d", res);
            return res;
        }
        compressed_fpga_stream->next_in += cmp_bytes;
    }
    uncompressed_bytes_cnt++;
    return *fpga_image_ptr++;
}

static int bitstream_target_to_index(FPGA_config bitstream_target) {
    static int8_t bitstream_index_map[FPGA_CONFIG_COUNT] = {-1};

    // Initialize
    if (bitstream_index_map[FPGA_BITSTREAM_UNKNOWN] == -1) {
        bitstream_index_map[FPGA_BITSTREAM_UNKNOWN] = 0;

        for (size_t i = 0; i < g_fpga_bitstream_num; i++) {
            FPGA_VERSION_INFORMATION info = g_fpga_version_information[i];
            bitstream_index_map[info.target_config] = i;
        }
    }

    return bitstream_index_map[bitstream_target];
}

//----------------------------------------------------------------------------
// Undo the interleaving of several FPGA config files. FPGA config files
// are combined into one big file:
// 288 bytes from FPGA file 1, followed by 288 bytes from FGPA file 2, etc.
//----------------------------------------------------------------------------
static int get_from_fpga_stream(int bitstream_target, lz4_streamp_t compressed_fpga_stream, uint8_t *output_buffer) {
    int bitstream_index = bitstream_target_to_index(bitstream_target);
    while ((uncompressed_bytes_cnt / FPGA_INTERLEAVE_SIZE) % g_fpga_bitstream_num != bitstream_index) {
        // skip undesired data belonging to other bitstream_targets
        get_from_fpga_combined_stream(compressed_fpga_stream, output_buffer);
    }

    return get_from_fpga_combined_stream(compressed_fpga_stream, output_buffer);
}

//----------------------------------------------------------------------------
// Initialize decompression of the respective (HF or LF) FPGA stream
//----------------------------------------------------------------------------
static bool reset_fpga_stream(int bitstream_target, lz4_streamp_t compressed_fpga_stream, uint8_t *output_buffer) {
    uint8_t header[FPGA_BITSTREAM_FIXED_HEADER_SIZE];

    uncompressed_bytes_cnt = 0;

    // initialize z_stream structure for inflate:
    compressed_fpga_stream->next_in = (char *)_binary_obj_fpga_all_bit_z_start;
    compressed_fpga_stream->avail_in = (uint32_t)_binary_obj_fpga_all_bit_z_end - (uint32_t)_binary_obj_fpga_all_bit_z_start;

    int res = LZ4_setStreamDecode(compressed_fpga_stream->lz4StreamDecode, NULL, 0);
    if (res == 0)
        return false;

    fpga_image_ptr = output_buffer + FPGA_RING_BUFFER_BYTES;

    for (uint16_t i = 0; i < FPGA_BITSTREAM_FIXED_HEADER_SIZE; i++)
        header[i] = get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer);

    // Check for a valid .bit file (starts with bitparse_fixed_header)
    if (memcmp(bitparse_fixed_header, header, FPGA_BITSTREAM_FIXED_HEADER_SIZE) == 0)
        return true;

    return false;
}

static void DownloadFPGA_byte(uint8_t w) {
#define SEND_BIT(x) { if(w & (1<<x) ) Gpio_FPGA_DIN_High(); else Gpio_FPGA_DIN_Low(); Gpio_FPGA_CCLK_High(); Gpio_FPGA_CCLK_Low(); }
    SEND_BIT(7);
    SEND_BIT(6);
    SEND_BIT(5);
    SEND_BIT(4);
    SEND_BIT(3);
    SEND_BIT(2);
    SEND_BIT(1);
    SEND_BIT(0);
}

// TODO DXL: Abstract this function
// Download the fpga image starting at current stream position with length FpgaImageLen bytes
static void DownloadFPGA(int bitstream_target, int FpgaImageLen, lz4_streamp_t compressed_fpga_stream, uint8_t *output_buffer) {
    int i = 0;

#if !defined XC3 && !defined PM5
    gpio_fpga_on_setup();
    Gpio_FPGA_ON_High(); // ensure everything is powered on
#endif

    SpinDelay(50);

    LED_D_ON();

    // setup initial logic state
    Gpio_FPGA_NPROGRAM_High();
    Gpio_FPGA_CCLK_Low();
    Gpio_FPGA_DIN_Low();

    // setup gpio function
    gpio_fpga_download_setup();

#if defined XC3
    // ICopyX(3S100E) M2 & M3 OUTPUT HIGH, for 'Slave Serial' mode select.
    Gpio_FPGA_XC3_M1_High();
    Gpio_FPGA_XC3_M2_High();
#endif

    // enter FPGA configuration mode
    Gpio_FPGA_NPROGRAM_Low();
    SpinDelay(50);
    Gpio_FPGA_NPROGRAM_High();

    i = 100000;
    // wait for FPGA ready to accept data signal
    while ((i) && (!Gpio_FPGA_NINIT_Read())) {
        i--;
    }

    // crude error indicator, leave both red LEDs on and return
    if (i == 0) {
        LED_C_ON();
        LED_D_ON();
        return;
    }

#if defined XC3
    // ICopyX(3S100E) M2 & M3 return to SPI peripheral
    Gpio_FPGA_XC3_M1_Low();
    Gpio_FPGA_XC3_M2_Low();
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SPCK | GPIO_MOSI;
#endif

    for (i = 0; i < FpgaImageLen; i++) {
        int b = get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer);
        if (b < 0) {
            Dbprintf("Error %d during FpgaDownload", b);
            break;
        }
        DownloadFPGA_byte(b);
    }

    // continue to clock FPGA until ready signal goes high
    i = 100000;
    while ((i--) && (!Gpio_FPGA_DONE_Read())) {
        Gpio_FPGA_CCLK_High();
        Gpio_FPGA_CCLK_Low();
    }
    // crude error indicator, leave both red LEDs on and return
    if (i == 0) {
        LED_C_ON();
        LED_D_ON();
        return;
    }
    LED_D_OFF();
}

/* Simple Xilinx .bit parser. The file starts with the fixed opaque byte sequence
 * 00 09 0f f0 0f f0 0f f0 0f f0 00 00 01
 * After that the format is 1 byte section type (ASCII character), 2 byte length
 * (big endian), <length> bytes content. Except for section 'e' which has 4 bytes
 * length.
 */
static int bitparse_find_section(int bitstream_target, char section_name, uint32_t *section_length, lz4_streamp_t compressed_fpga_stream, uint8_t *output_buffer) {

#define MAX_FPGA_BIT_STREAM_HEADER_SEARCH 100  // maximum number of bytes to search for the requested section

    int result = 0;
    uint16_t numbytes = 0;
    while (numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH) {
        char current_name = get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer);
        numbytes++;
        uint32_t current_length = 0;
        if (current_name < 'a' || current_name > 'e') {
            /* Strange section name, abort */
            break;
        }
        current_length = 0;
        switch (current_name) {
            case 'e':
                /* Four byte length field */
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 24;
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 16;
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 8;
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 0;
                numbytes += 4;
                if (current_length > 300 * 1024) {
                    /* section e should never exceed about 300KB, if the length is too big limit it but still send the bitstream just in case */
                    current_length = 300 * 1024;
                }
                break;
            default: /* Two byte length field */
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 8;
                current_length += get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer) << 0;
                numbytes += 2;
                if (current_length > 64) {
                    /* if text field is too long, keep it but truncate it */
                    current_length = 64;
                }
        }

        if (current_name == section_name) {
            /* Found it */
            *section_length = current_length;
            result = 1;
            break;
        }

        for (uint32_t i = 0; i < current_length && numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH; i++) {
            get_from_fpga_stream(bitstream_target, compressed_fpga_stream, output_buffer);
            numbytes++;
        }
    }
    return result;
}

//----------------------------------------------------------------------------
// Change FPGA image status, if image loaded.
// bitstream_target is your new fpga image version
// return true if can change.
// return false if image is unloaded.
//----------------------------------------------------------------------------
#if defined XC3 || defined PM5
static bool FpgaConfCurrentMode(int bitstream_target) {
    // fpga "XC3S100E" image is merged. If fpga image is no init, We need load hf_lf_allinone.bit.
    if (downloaded_bitstream != FPGA_BITSTREAM_UNKNOWN) {
        // gpio function setup
        gpio_fpga_switch_setup();

        // try to turn off antenna
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

        if (bitstream_target == FPGA_BITSTREAM_LF) {
            Gpio_FPGA_SWITCH_Low();
        } else {
            Gpio_FPGA_SWITCH_High();
        }
        // update downloaded_bitstream
        downloaded_bitstream = bitstream_target;
        // turn off antenna
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        return true;
    }
    return false;
}
#endif

//----------------------------------------------------------------------------
// Check which FPGA image is currently loaded (if any). If necessary
// decompress and load the correct (HF or LF) image to the FPGA
//----------------------------------------------------------------------------
static void FpgaDownloadAndGoEx(int bitstream_target, bool keep_em) {

    // check whether or not the bitstream is already loaded
    if (downloaded_bitstream == bitstream_target) {
        FpgaEnableTracing();
        return;
    }

#if defined PM5
    // The FPGA of PM5 comes with built-in FLASH, so there is no need to download it at startup anymore.
    downloaded_bitstream = bitstream_target; // FpgaConfCurrentMode() requires downloading for the first time, but we skipped it.
    FpgaConfCurrentMode(bitstream_target);
    return; // always return
#endif

#if defined XC3
    // If we can change image version
    // direct return.
    if (FpgaConfCurrentMode(bitstream_target)) {
        return;
    }
#endif

    // Send waiting time extension request as this will take a while
    send_wtx(FPGA_LOAD_WAIT_TIME);

    bool verbose = (g_dbglevel > 3);

    // make sure that we have enough memory to decompress
    if (keep_em) {
        BigBuf_free_keep_EM();
        BigBuf_Clear_keep_EM();
    } else {
        BigBuf_free();
        BigBuf_Clear_ext(verbose);
    }

    lz4_stream_t compressed_fpga_stream;
    LZ4_streamDecode_t lz4StreamDecode_body = {{ 0 }};
    compressed_fpga_stream.lz4StreamDecode = &lz4StreamDecode_body;
    uint8_t *output_buffer = BigBuf_calloc(FPGA_RING_BUFFER_BYTES);
    if (output_buffer == NULL) {
        Dbprintf(_RED_("Not enough memory to decompress FPGA image (%d bytes)"), FPGA_RING_BUFFER_BYTES);
        return;
    }

    if (reset_fpga_stream(bitstream_target, &compressed_fpga_stream, output_buffer) == false) {
        Dbprintf(_RED_("reset_fpga_stream failed"));
        return;
    }

    uint32_t bitstream_length;
    if (bitparse_find_section(bitstream_target, 'e', &bitstream_length, &compressed_fpga_stream, output_buffer)) {
        DownloadFPGA(bitstream_target, bitstream_length, &compressed_fpga_stream, output_buffer);
        downloaded_bitstream = bitstream_target;
    }

#if defined XC3
    // first download fpga image to hf
    // we need to change fpga status to hf
    FpgaConfCurrentMode(bitstream_target);
#endif

    // turn off antenna
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // free eventually allocated BigBuf memory
    if (keep_em) {
        BigBuf_free_keep_EM();
        BigBuf_Clear_keep_EM();
    } else {
        BigBuf_free();
        BigBuf_Clear_ext(false);
    }
}

void FpgaDownloadAndGo(int bitstream_target) {
    FpgaDownloadAndGoEx(bitstream_target, false);
}

void FpgaDownloadAndGo_keep_EM(int bitstream_target) {
    FpgaDownloadAndGoEx(bitstream_target, true);
}

//----------------------------------------------------------------------------
// Which FPGA bitstream has been downloaded currently.
//----------------------------------------------------------------------------
int FpgaGetCurrent(void) {
    return downloaded_bitstream;
}

void FpgaResetBitstream(void) {
    downloaded_bitstream = FPGA_BITSTREAM_UNKNOWN;
}

//----------------------------------------------------------------------------
// The information of the bitstream of the FPGA that has been downloaded currently.
//----------------------------------------------------------------------------
const char *FpgaGetCurrentVersionString(void) {
    return g_fpga_version_information[bitstream_target_to_index(downloaded_bitstream)].versionString;
}
