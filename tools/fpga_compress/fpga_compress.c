//-----------------------------------------------------------------------------
// piwi, 2017, 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Compression tool for FPGA config files. Compress several *.bit files at
// compile time. Decompression is done at run time (see fpgaloader.c).
// This uses the lz4 library tuned to this specific case. The small file sizes
// allow to use "insane" parameters for optimum compression ratio.
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "fpga.h"
#include "lz4hc.h"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

static void usage(void) {
    fprintf(stdout, "Usage: fpga_compress <infile1> <infile2> ... <infile_n> <outfile>\n");
    fprintf(stdout, "          Combine n FPGA bitstream files and compress them into one.\n\n");
    fprintf(stdout, "       fpga_compress -v <infile1> <infile2> ... <infile_n> <outfile>\n");
    fprintf(stdout, "          Extract Version Information from FPGA bitstream files and write it to <outfile>\n\n");
    fprintf(stdout, "       fpga_compress -d <infile> <outfile(s)>\n");
    fprintf(stdout, "          Decompress <infile>. Write result to <outfile(s)>\n\n");
}

static bool all_feof(FILE *infile[], uint8_t num_infiles) {
    for (uint16_t i = 0; i < num_infiles; i++) {
        if (!feof(infile[i])) {
            return false;
        }
    }
    return true;
}

static int zlib_compress(FILE *infile[], uint8_t num_infiles, FILE *outfile) {

    uint8_t *fpga_config = calloc(num_infiles * FPGA_CONFIG_SIZE, sizeof(uint8_t));
    if (fpga_config == NULL) {
        fprintf(stderr, "failed to allocate memory");
        return (EXIT_FAILURE);
    }

    // read the input files. Interleave them into fpga_config[]
    uint32_t total_size = 0;
    do {

        if (total_size > num_infiles * FPGA_CONFIG_SIZE) {
            fprintf(stderr,
                    "Input files too big (total > %li bytes). These are probably not PM3 FPGA config files.\n"
                    , num_infiles * FPGA_CONFIG_SIZE
                   );

            free(fpga_config);
            return (EXIT_FAILURE);
        }

        for (uint16_t j = 0; j < num_infiles; j++) {
            for (uint16_t k = 0; k < FPGA_INTERLEAVE_SIZE; k++) {
                uint8_t c = (uint8_t)fgetc(infile[j]);

                if (!feof(infile[j])) {
                    fpga_config[total_size++] = c;
                } else if (num_infiles > 1) {
                    fpga_config[total_size++] = '\0';
                }
            }
        }

    } while (all_feof(infile, num_infiles) == false);

    uint32_t buffer_size = FPGA_RING_BUFFER_BYTES;

    if (num_infiles == 1) {
        // 1M bytes for now
        buffer_size = 1024 * 1024;
    }

    uint32_t outsize_max = LZ4_compressBound(buffer_size);

    char *outbuf = calloc(outsize_max, sizeof(char));
    if (outbuf == NULL) {
        fprintf(stderr, "failed to allocate memory");
        free(fpga_config);
        return (EXIT_FAILURE);
    }

    char *ring_buffer = calloc(buffer_size, sizeof(char));
    if (ring_buffer == NULL) {
        fprintf(stderr, "failed to allocate memory");
        free(outbuf);
        free(fpga_config);
        return (EXIT_FAILURE);
    }

    LZ4_streamHC_t *lz4_streamhc = LZ4_createStreamHC();
    LZ4_resetStreamHC_fast(lz4_streamhc, LZ4HC_CLEVEL_MAX);

    int current_in = 0;
    int current_out = 0;

    while (current_in < total_size) {

        int bytes_to_copy = MIN(FPGA_RING_BUFFER_BYTES, (total_size - current_in));

        memcpy(ring_buffer, fpga_config + current_in, bytes_to_copy);

        int cmp_bytes = LZ4_compress_HC_continue(lz4_streamhc, ring_buffer, outbuf, bytes_to_copy, outsize_max);
        if (cmp_bytes < 0) {
            fprintf(stderr, "(lz4 - zlib_compress) error,  got negative number of bytes from LZ4_compress_HC_continue call. got %d", cmp_bytes);
            free(ring_buffer);
            free(outbuf);
            free(fpga_config);
            LZ4_freeStreamHC(lz4_streamhc);
            return (EXIT_FAILURE);
        }

        // write size
        fwrite(&cmp_bytes, sizeof(int), 1, outfile);

        // write compressed data
        fwrite(outbuf, sizeof(char), cmp_bytes, outfile);

        current_in += bytes_to_copy;
        current_out += cmp_bytes;
    }

    // free allocated buffers
    free(ring_buffer);
    free(outbuf);
    free(fpga_config);
    LZ4_freeStreamHC(lz4_streamhc);

    if (current_out == 0) {
        fprintf(stderr, "error in lz4");
        return (EXIT_FAILURE);
    } else {
        fprintf(stdout, "compressed %u input bytes to %d output bytes\n", total_size, current_out);
    }
    return (EXIT_SUCCESS);
}

typedef struct lz4_stream_s {
    LZ4_streamDecode_t *lz4StreamDecode;
    char *next_in;
    int avail_in;
} lz4_stream;


// Call it either with opened infile + outsize=0
// or with opened infile, opened outfiles, num_outfiles and valid outsize
static int zlib_decompress(FILE *infile, FILE *outfiles[], uint8_t num_outfiles, long *outsize) {

    if (num_outfiles > 10) {
        return (EXIT_FAILURE);
    }

    LZ4_streamDecode_t lz4StreamDecode_body = {{ 0 }};
    char outbuf[FPGA_RING_BUFFER_BYTES] = {0};

    // file size
    fseek(infile, 0L, SEEK_END);
    long infile_size = ftell(infile);
    fseek(infile, 0L, SEEK_SET);

    if (infile_size <= 0) {
        printf("error, when getting filesize");
        return (EXIT_FAILURE);
    }

    char *outbufall = NULL;
    if (*outsize >  0) {
        outbufall = calloc(*outsize, sizeof(char));
        if (outbufall == NULL) {
            return (EXIT_FAILURE);
        }
    }

    char *inbuf = calloc(infile_size, sizeof(char));
    if (inbuf == NULL) {
        if (outbufall) {
            free(outbufall);
        }
        return (EXIT_FAILURE);
    }

    size_t num_read = fread(inbuf, sizeof(char), infile_size, infile);

    if (num_read != infile_size) {
        if (outbufall) {
            free(outbufall);
        }
        free(inbuf);
        return (EXIT_FAILURE);
    }

    lz4_stream compressed_fpga_stream;
    // initialize lz4 structures
    compressed_fpga_stream.lz4StreamDecode = &lz4StreamDecode_body;
    compressed_fpga_stream.next_in = inbuf;
    compressed_fpga_stream.avail_in = infile_size;

    long total_size = 0;
    while (compressed_fpga_stream.avail_in > 0) {
        int cmp_bytes;
        memcpy(&cmp_bytes, compressed_fpga_stream.next_in, sizeof(int));
        compressed_fpga_stream.next_in += 4;
        compressed_fpga_stream.avail_in -= cmp_bytes + 4;

        const int decBytes = LZ4_decompress_safe_continue(compressed_fpga_stream.lz4StreamDecode, compressed_fpga_stream.next_in, outbuf, cmp_bytes, FPGA_RING_BUFFER_BYTES);
        if (decBytes <= 0) {
            break;
        }

        if (outbufall != NULL) {
            memcpy(outbufall + total_size, outbuf, decBytes);
        }

        total_size += decBytes;
        compressed_fpga_stream.next_in += cmp_bytes;
    }

    if (outbufall == NULL) {
        *outsize = total_size;
        fseek(infile, 0L, SEEK_SET);
        return EXIT_SUCCESS;
    } else {

        // seeking for trailing zeroes
        long offset = 0;
        long outfilesizes[10] = {0};
        for (long k = 0; k < *outsize / (FPGA_INTERLEAVE_SIZE * num_outfiles); k++) {
            for (uint16_t j = 0; j < num_outfiles; j++) {
                for (long i = 0; i < FPGA_INTERLEAVE_SIZE; i++) {
                    if (outbufall[offset + i]) {
                        outfilesizes[j] = (k * FPGA_INTERLEAVE_SIZE) + i + 1;
                    }
                }
                offset += FPGA_INTERLEAVE_SIZE;
            }
        }

        total_size = 0;
        // FPGA bit file ends with 16 zeroes
        for (uint16_t j = 0; j < num_outfiles; j++) {
            outfilesizes[j] += 16;
            total_size += outfilesizes[j];
        }

        offset = 0;
        for (long k = 0; k < *outsize / (FPGA_INTERLEAVE_SIZE * num_outfiles); k++) {
            for (uint16_t j = 0; j < num_outfiles; j++) {
                if (k * FPGA_INTERLEAVE_SIZE < outfilesizes[j]) {
                    uint16_t chunk = (outfilesizes[j] - (k * FPGA_INTERLEAVE_SIZE) < FPGA_INTERLEAVE_SIZE) ?
                                     outfilesizes[j] - (k * FPGA_INTERLEAVE_SIZE) : FPGA_INTERLEAVE_SIZE;

                    fwrite(outbufall + offset, chunk, sizeof(char), outfiles[j]);
                }
                offset += FPGA_INTERLEAVE_SIZE;
            }
        }
        printf("uncompressed %li input bytes to %li output bytes\n", infile_size, total_size);
    }

    free(outbufall);
    free(inbuf);
    return (EXIT_SUCCESS);
}


/* Simple Xilinx .bit parser. The file starts with the fixed opaque byte sequence
 * 00 09 0f f0 0f f0 0f f0 0f f0 00 00 01
 * After that the format is 1 byte section type (ASCII character), 2 byte length
 * (big endian), <length> bytes content. Except for section 'e' which has 4 bytes
 * length.
 */
static int bitparse_find_section(FILE *infile, char section_name, unsigned int *section_length) {

#define MAX_FPGA_BIT_STREAM_HEADER_SEARCH 100  // maximum number of bytes to search for the requested section

    int result = 0;
    uint16_t numbytes = 0;
    while (numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH) {
        char current_name = (char)fgetc(infile);
        numbytes++;
        if (current_name < 'a' || current_name > 'e') {
            /* Strange section name, abort */
            break;
        }
        uint32_t current_length = 0;
        int tmp;
        switch (current_name) {
            case 'e':
                /* Four byte length field */
                for (int i = 0; i < 4; i++) {
                    tmp = fgetc(infile);
                    /* image length sanity check, should be under 300KB */
                    if ((tmp < 0) || (tmp > 300 * 1024)) {
                        break;
                    }
                    current_length += tmp << (24 - (i * 8));
                }
                numbytes += 4;
                break;
            default: /* Fall through, two byte length field */
                for (int i = 0; i < 2; i++) {
                    tmp = fgetc(infile);
                    /* if name, date or time fields are too long, we probably shouldn't parse them */
                    if ((tmp < 0) || (tmp > 64)) {
                        break;
                    }
                    current_length += tmp << (8 - (i * 8));
                }
                numbytes += 2;
                break;
        }

        if (current_name != 'e' && current_length > 255) {
            /* Maybe a parse error */
            break;
        }

        if (current_name == section_name) {
            /* Found it */
            *section_length = current_length;
            result = 1;
            break;
        }

        for (uint32_t i = 0; i < current_length && numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH; i++) {
            (void)fgetc(infile);
            numbytes++;
        }
    }
    return result;
}

static int FpgaGatherVersion(FILE *infile, char *infile_name, char *dst, int len) {
    uint32_t fpga_info_len;
    char tempstr[40] = {0x00};

    dst[0] = '\0';

    for (uint16_t i = 0; i < FPGA_BITSTREAM_FIXED_HEADER_SIZE; i++) {
        if (fgetc(infile) != bitparse_fixed_header[i]) {
            fprintf(stderr, "Invalid FPGA file. Aborting...\n\n");
            return (EXIT_FAILURE);
        }
    }

    if (bitparse_find_section(infile, 'a', &fpga_info_len)) {
        for (uint32_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                tempstr[i] = c;
            }
        }

        strncat(dst, tempstr, len - strlen(dst) - 1);
    }

    strncat(dst, " image ", len - strlen(dst) - 1);
    if (bitparse_find_section(infile, 'b', &fpga_info_len)) {
        for (uint32_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                tempstr[i] = c;
            }
        }
        strncat(dst, tempstr, len - strlen(dst) - 1);
    }

    strncat(dst, " ", len - strlen(dst) - 1);
    if (bitparse_find_section(infile, 'c', &fpga_info_len)) {
        for (uint32_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                if (c == '/') c = '-';
                if (c == ' ') c = '0';
                tempstr[i] = c;
            }
        }
        strncat(dst, tempstr, len - strlen(dst) - 1);
    }

    if (bitparse_find_section(infile, 'd', &fpga_info_len)) {
        strncat(dst, " ", len - strlen(dst) - 1);
        for (uint32_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                if (c == ' ') c = '0';
                tempstr[i] = c;
            }
        }
        strncat(dst, tempstr, len - strlen(dst) - 1);
    }
    return 0;
}

static void print_version_info_preamble(FILE *outfile, int num_infiles) {
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.\n");
    fprintf(outfile, "//\n");
    fprintf(outfile, "// This code is licensed to you under the terms of the GNU GPL, version 3 or,\n");
    fprintf(outfile, "// at your option, any later version. See the LICENSE.txt file for the text of\n");
    fprintf(outfile, "// the license.\n");
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "// Version information on fpga images\n");
    fprintf(outfile, "//\n");
    fprintf(outfile, "// This file is generated by fpga_compress. Don't edit!\n");
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "\n\n");
    fprintf(outfile, "const int g_fpga_bitstream_num = %d;\n", num_infiles);
    fprintf(outfile, "const char *const g_fpga_version_information[%d] = {\n", num_infiles);
}

static int generate_fpga_version_info(FILE *infile[], char *infile_names[], int num_infiles, FILE *outfile) {

    char version_string[80] = "";

    print_version_info_preamble(outfile, num_infiles);

    for (int i = 0; i < num_infiles; i++) {
        FpgaGatherVersion(infile[i], infile_names[i], version_string, sizeof(version_string));
        fprintf(outfile, "    \" %s\"", version_string);
        if (i != num_infiles - 1) {
            fprintf(outfile, ",");
        }
        fprintf(outfile, "\n");
    }
    fprintf(outfile, "};\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc == 1 || argc == 2) {
        usage();
        return (EXIT_FAILURE);
    }

    if (!strcmp(argv[1], "-d")) { // Decompress

        if (argc < 4) {
            usage();
            return (EXIT_FAILURE);
        }

        uint8_t num_output_files = argc - 3;
        FILE **outfiles = calloc(num_output_files, sizeof(FILE *));
        char **outfile_names = calloc(num_output_files, sizeof(char *));
        for (uint8_t i = 0; i < num_output_files; i++) {
            outfile_names[i] = argv[i + 3];
            outfiles[i] = fopen(outfile_names[i], "wb");
            if (outfiles[i] == NULL) {
                fprintf(stderr, "Error. Cannot open output file %s\n\n", outfile_names[i]);
                free(outfile_names);
                free(outfiles);
                return (EXIT_FAILURE);
            }
        }

        FILE *infile = fopen(argv[2], "rb");
        if (infile == NULL) {
            fprintf(stderr, "Error. Cannot open input file %s\n\n", argv[2]);

            // close file handlers
            for (uint16_t j = 0; j < num_output_files; j++) {
                fclose(outfiles[j]);
            }

            free(outfile_names);
            free(outfiles);
            return (EXIT_FAILURE);
        }

        long outsize = 0;
        int ret = 0;
        // First call to estimate output size
        ret = zlib_decompress(infile, outfiles, num_output_files, &outsize);
        if (ret == EXIT_SUCCESS) {
            // Second call to create files
            ret = zlib_decompress(infile, outfiles, num_output_files, &outsize);
        }

        // close file handlers
        fclose(infile);
        for (uint16_t j = 0; j < num_output_files; j++) {
            fclose(outfiles[j]);
        }

        free(outfile_names);
        free(outfiles);
        return (ret);

    } else { // Compress or generate version info

        bool generate_version_file = false;
        uint8_t num_input_files = 0;
        if (!strcmp(argv[1], "-v")) {  // generate version info
            generate_version_file = true;
            num_input_files = argc - 3;
        } else {  // compress 1..n fpga files
            num_input_files = argc - 2;
        }

        FILE **infiles = calloc(num_input_files, sizeof(FILE *));
        char **infile_names = calloc(num_input_files, sizeof(char *));
        for (uint8_t i = 0; i < num_input_files; i++) {
            infile_names[i] = argv[i + (generate_version_file ? 2 : 1)];
            infiles[i] = fopen(infile_names[i], "rb");
            if (infiles[i] == NULL) {
                fprintf(stderr, "Error. Cannot open input file %s\n\n", infile_names[i]);
                free(infile_names);
                free(infiles);
                return (EXIT_FAILURE);
            }
        }

        FILE *outfile = fopen(argv[argc - 1], "wb");
        if (outfile == NULL) {
            fprintf(stderr, "Error. Cannot open output file %s\n\n", argv[argc - 1]);

            // close file handlers
            for (uint16_t j = 0; j < num_input_files; j++) {
                fclose(infiles[j]);
            }

            free(infile_names);
            free(infiles);
            return (EXIT_FAILURE);
        }

        int ret = 0;
        if (generate_version_file) {
            ret = generate_fpga_version_info(infiles, infile_names, num_input_files, outfile);
        } else {
            ret = zlib_compress(infiles, num_input_files, outfile);
        }

        // close file handlers
        fclose(outfile);
        for (uint16_t j = 0; j < num_input_files; j++) {
            fclose(infiles[j]);
        }

        // free file name allocs
        free(infile_names);
        free(infiles);
        return (ret);
    }
}
