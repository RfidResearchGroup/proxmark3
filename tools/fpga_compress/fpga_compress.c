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

#define HARDNESTED_TABLE_SIZE (uint32_t)(sizeof(uint32_t) * ((1L<<19)+1))

static void usage(void) {
    fprintf(stdout, "Usage: fpga_compress <infile1> <infile2> ... <infile_n> <outfile>\n");
    fprintf(stdout, "          Combine n FPGA bitstream files and compress them into one.\n\n");
    fprintf(stdout, "       fpga_compress -v <infile1> <infile2> ... <infile_n> <outfile>\n");
    fprintf(stdout, "          Extract Version Information from FPGA bitstream files and write it to <outfile>\n\n");
    fprintf(stdout, "       fpga_compress -d <infile> <outfile>\n");
    fprintf(stdout, "          Decompress <infile>. Write result to <outfile>\n\n");
    fprintf(stdout, "       fpga_compress -t <infile> <outfile>\n");
    fprintf(stdout, "          Compress hardnested table <infile>. Write result to <outfile>\n\n");
}

static bool all_feof(FILE *infile[], uint8_t num_infiles) {
    for (uint16_t i = 0; i < num_infiles; i++) {
        if (!feof(infile[i])) {
            return false;
        }
    }
    return true;
}

static int zlib_compress(FILE *infile[], uint8_t num_infiles, FILE *outfile, bool hardnested_mode) {
    uint8_t *fpga_config;

    if (hardnested_mode) {
        fpga_config = calloc(num_infiles * HARDNESTED_TABLE_SIZE, sizeof(uint8_t));
    } else {
        fpga_config = calloc(num_infiles * FPGA_CONFIG_SIZE, sizeof(uint8_t));
    }

    // read the input files. Interleave them into fpga_config[]
    uint32_t total_size = 0;
    do {

        if (total_size >= num_infiles * (hardnested_mode ? HARDNESTED_TABLE_SIZE : FPGA_CONFIG_SIZE)) {
            if (hardnested_mode) {
                fprintf(stderr,
                        "Input file too big (> %" PRIu32 " bytes). This is probably not a hardnested bitflip state table.\n"
                        , HARDNESTED_TABLE_SIZE);

            } else {
                fprintf(stderr,
                        "Input files too big (total > %li bytes). These are probably not PM3 FPGA config files.\n"
                        , num_infiles * FPGA_CONFIG_SIZE);
            }
            for (uint16_t j = 0; j < num_infiles; j++) {
                fclose(infile[j]);
            }
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

    } while (!all_feof(infile, num_infiles));

    uint32_t buffer_size = FPGA_RING_BUFFER_BYTES;

    if (num_infiles == 1)
        buffer_size = 1024 * 1024; //1M for now

    uint32_t outsize_max = LZ4_compressBound(buffer_size);

    char *outbuf = calloc(outsize_max, sizeof(char));

    LZ4_streamHC_t* lz4_streamhc = LZ4_createStreamHC();
    LZ4_resetStreamHC_fast(lz4_streamhc, LZ4HC_CLEVEL_MAX);

    int current_in = 0;
    int current_out = 0;
    char * ring_buffer = calloc(buffer_size, sizeof(char));
    while (current_in < total_size) {
        int bytes_to_copy = FPGA_RING_BUFFER_BYTES;
        if (total_size - current_in < FPGA_RING_BUFFER_BYTES)
            bytes_to_copy = total_size - current_in;

        memcpy(ring_buffer, fpga_config + current_in, bytes_to_copy);
        int cmp_bytes = LZ4_compress_HC_continue(lz4_streamhc, ring_buffer, outbuf, bytes_to_copy, outsize_max);

        fwrite(&cmp_bytes, sizeof(int), 1, outfile);
        fwrite(outbuf, sizeof(char), cmp_bytes, outfile);

        current_in += bytes_to_copy;
        current_out += cmp_bytes;
    }

    free(ring_buffer);
    free(outbuf);
    free(fpga_config);
    
    fclose(outfile);        
    for (uint16_t j = 0; j < num_infiles; j++) {
        fclose(infile[j]);
    }
    LZ4_freeStreamHC(lz4_streamhc);
    
    fprintf(stdout, "compressed %u input bytes to %u output bytes\n", total_size, current_out);

    if (current_out == 0) {
        fprintf(stderr, "Error in lz4");
        return (EXIT_FAILURE);
    }
    return (EXIT_SUCCESS);
}

typedef struct lz4_stream_s {
    LZ4_streamDecode_t* lz4StreamDecode;
    char* next_in;
    int avail_in;
} lz4_stream;

static int zlib_decompress(FILE *infile, FILE *outfile) {

    LZ4_streamDecode_t lz4StreamDecode_body = {{ 0 }};
    char outbuf[FPGA_RING_BUFFER_BYTES];

    fseek(infile, 0L, SEEK_END);
    long infile_size = ftell(infile);
    fseek(infile, 0L, SEEK_SET);

    if (infile_size <= 0) {
        printf("error, when getting filesize");
        fclose(outfile);
        fclose(infile);
        return (EXIT_FAILURE);
    }

    char* inbuf = calloc(infile_size, sizeof(char));
    size_t num_read = fread(inbuf, sizeof(char), infile_size, infile);

    if (num_read != infile_size) {
        fclose(outfile);
        fclose(infile);
        free(inbuf);
        return (EXIT_FAILURE);
    }

    lz4_stream compressed_fpga_stream;
    // initialize lz4 structures
    compressed_fpga_stream.lz4StreamDecode = &lz4StreamDecode_body;
    compressed_fpga_stream.next_in = inbuf;
    compressed_fpga_stream.avail_in = infile_size;

    int total_size = 0;
    while (compressed_fpga_stream.avail_in > 0) {
        int cmp_bytes;
        memcpy(&cmp_bytes, compressed_fpga_stream.next_in, sizeof(int));
        compressed_fpga_stream.next_in += 4;
        compressed_fpga_stream.avail_in -= cmp_bytes + 4;
        const int decBytes = LZ4_decompress_safe_continue(compressed_fpga_stream.lz4StreamDecode, compressed_fpga_stream.next_in, outbuf, cmp_bytes, FPGA_RING_BUFFER_BYTES);
        if (decBytes <= 0) {
            break;
        }
        fwrite(outbuf, decBytes, sizeof(char), outfile);
        total_size += decBytes;
        compressed_fpga_stream.next_in += cmp_bytes;
    }
    printf("uncompressed %li input bytes to %i output bytes\n", infile_size, total_size);
    fclose(outfile);
    fclose(infile);
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
    int result = 0;
#define MAX_FPGA_BIT_STREAM_HEADER_SEARCH 100  // maximum number of bytes to search for the requested section
    uint16_t numbytes = 0;
    while (numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH) {
        char current_name = (char)fgetc(infile);
        numbytes++;
        if (current_name < 'a' || current_name > 'e') {
            /* Strange section name, abort */
            break;
        }
        unsigned int current_length = 0;
        switch (current_name) {
            case 'e':
                /* Four byte length field */
                current_length += fgetc(infile) << 24;
                current_length += fgetc(infile) << 16;
                current_length += fgetc(infile) << 8;
                current_length += fgetc(infile) << 0;
                numbytes += 4;
                break;
            default: /* Fall through, two byte length field */
                current_length += fgetc(infile) << 8;
                current_length += fgetc(infile) << 0;
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

        for (uint16_t i = 0; i < current_length && numbytes < MAX_FPGA_BIT_STREAM_HEADER_SEARCH; i++) {
            (void)fgetc(infile);
            numbytes++;
        }
    }
    return result;
}

static int FpgaGatherVersion(FILE *infile, char *infile_name, char *dst, int len) {
    unsigned int fpga_info_len;
    char tempstr[40] = {0x00};

    dst[0] = '\0';

    for (uint16_t i = 0; i < FPGA_BITSTREAM_FIXED_HEADER_SIZE; i++) {
        if (fgetc(infile) != bitparse_fixed_header[i]) {
            fprintf(stderr, "Invalid FPGA file. Aborting...\n\n");
            return (EXIT_FAILURE);
        }
    }

    if (!memcmp("fpga_lf", basename(infile_name), 7))
        strncat(dst, "LF", len - strlen(dst) - 1);
    else if (!memcmp("fpga_hf", basename(infile_name), 7))
        strncat(dst, "HF", len - strlen(dst) - 1);

    strncat(dst, " image built", len - strlen(dst) - 1);
    if (bitparse_find_section(infile, 'b', &fpga_info_len)) {
        strncat(dst, " for ", len - strlen(dst) - 1);
        for (uint16_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                tempstr[i] = c;
            }
        }
        strncat(dst, tempstr, len - strlen(dst) - 1);
    }

    if (bitparse_find_section(infile, 'c', &fpga_info_len)) {
        strncat(dst, " on ", len - strlen(dst) - 1);
        for (uint16_t i = 0; i < fpga_info_len; i++) {
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
        strncat(dst, " at ", len - strlen(dst) - 1);
        for (uint16_t i = 0; i < fpga_info_len; i++) {
            char c = (char)fgetc(infile);
            if (i < sizeof(tempstr)) {
                tempstr[i] = c;
            }
        }
        strncat(dst, tempstr, len - strlen(dst) - 1);
    }
    return 0;
}

static void print_version_info_preamble(FILE *outfile, int num_infiles) {
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "// piwi, 2018\n");
    fprintf(outfile, "//\n");
    fprintf(outfile, "// This code is licensed to you under the terms of the GNU GPL, version 2 or,\n");
    fprintf(outfile, "// at your option, any later version. See the LICENSE.txt file for the text of\n");
    fprintf(outfile, "// the license.\n");
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "// Version information on fpga images\n");
    fprintf(outfile, "//\n");
    fprintf(outfile, "// This file is generated by fpga_compress. Don't edit!\n");
    fprintf(outfile, "//-----------------------------------------------------------------------------\n");
    fprintf(outfile, "// slurdge, 2020\n");
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
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 1 || argc == 2) {
        usage();
        return (EXIT_FAILURE);
    }

    if (!strcmp(argv[1], "-d")) { // Decompress

        FILE **infiles = calloc(1, sizeof(FILE *));
        if (argc != 4) {
            usage();
            free(infiles);
            return (EXIT_FAILURE);
        }
        infiles[0] = fopen(argv[2], "rb");
        if (infiles[0] == NULL) {
            fprintf(stderr, "Error. Cannot open input file %s\n\n", argv[2]);
            free(infiles);
            return (EXIT_FAILURE);
        }
        FILE *outfile = fopen(argv[3], "wb");
        if (outfile == NULL) {
            fprintf(stderr, "Error. Cannot open output file %s\n\n", argv[3]);
            free(infiles);
            return (EXIT_FAILURE);
        }

        int ret = zlib_decompress(infiles[0], outfile);
        free(infiles);
        return (ret);

    } else { // Compress or generate version info

        bool hardnested_mode = false;
        bool generate_version_file = false;
        int num_input_files = 0;
        if (!strcmp(argv[1], "-t")) {  // compress one hardnested table
            if (argc != 4) {
                usage();
                return (EXIT_FAILURE);
            }
            hardnested_mode = true;
            num_input_files = 1;
        } else if (!strcmp(argv[1], "-v")) {  // generate version info
            generate_version_file = true;
            num_input_files = argc - 3;
        } else {  // compress 1..n fpga files
            num_input_files = argc - 2;
        }

        FILE **infiles = calloc(num_input_files, sizeof(FILE *));
        char **infile_names = calloc(num_input_files, sizeof(char *));
        for (uint16_t i = 0; i < num_input_files; i++) {
            infile_names[i] = argv[i + ((hardnested_mode || generate_version_file) ? 2 : 1)];
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
            free(infile_names);
            free(infiles);
            return (EXIT_FAILURE);
        }
        if (generate_version_file) {
            if (generate_fpga_version_info(infiles, infile_names, num_input_files, outfile)) {
                free(infile_names);
                free(infiles);
                return (EXIT_FAILURE);
            }
        } else {
            int ret = zlib_compress(infiles, num_input_files, outfile, hardnested_mode);
            free(infile_names);
            free(infiles);
            return (ret);
        }
    }
}
