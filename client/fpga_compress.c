//-----------------------------------------------------------------------------
// piwi, 2017, 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Compression tool for FPGA config files. Compress several *.bit files at
// compile time. Decompression is done at run time (see fpgaloader.c).
// This uses the zlib library tuned to this specific case. The small file sizes
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
#include "zlib.h"

#define MAX(a,b) ((a)>(b)?(a):(b))

// zlib configuration
#define COMPRESS_LEVEL          9  // use best possible compression
#define COMPRESS_WINDOW_BITS    15 // default = max = 15 for a window of 2^15 = 32KBytes
#define COMPRESS_MEM_LEVEL      9  // determines the amount of memory allocated during compression. Default = 8.
/* COMPRESS_STRATEGY can be
    Z_DEFAULT_STRATEGY (the default),
    Z_FILTERED (more huffmann, less string matching),
    Z_HUFFMAN_ONLY (huffman only, no string matching)
    Z_RLE (distances limited to one)
    Z_FIXED (prevents the use of dynamic Huffman codes)
*/

#define COMPRESS_STRATEGY         Z_DEFAULT_STRATEGY
// zlib tuning parameters:
#define COMPRESS_GOOD_LENGTH      258
#define COMPRESS_MAX_LAZY         258
#define COMPRESS_MAX_NICE_LENGTH  258
#define COMPRESS_MAX_CHAIN        8192

#define HARDNESTED_TABLE_SIZE (sizeof(uint32_t) * ((1L<<19)+1))

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


static voidpf fpga_deflate_malloc(voidpf opaque, uInt items, uInt size) {
    return calloc(items * size, sizeof(uint8_t));
}


static void fpga_deflate_free(voidpf opaque, voidpf address) {
    free(address);
}


static bool all_feof(FILE *infile[], uint8_t num_infiles) {
    for (uint16_t i = 0; i < num_infiles; i++) {
        if (!feof(infile[i])) {
            return false;
        }
    }
    return true;
}


int zlib_compress(FILE *infile[], uint8_t num_infiles, FILE *outfile, bool hardnested_mode) {
    uint8_t *fpga_config;
    uint32_t i;
    int32_t ret;
    uint8_t c;
    z_stream compressed_fpga_stream;

    if (hardnested_mode) {
        fpga_config = calloc(num_infiles * HARDNESTED_TABLE_SIZE, sizeof(uint8_t));
    } else {
        fpga_config = calloc(num_infiles * FPGA_CONFIG_SIZE, sizeof(uint8_t));
    }
    // read the input files. Interleave them into fpga_config[]
    i = 0;
    do {

        if (i >= num_infiles * (hardnested_mode ? HARDNESTED_TABLE_SIZE : FPGA_CONFIG_SIZE)) {
            if (hardnested_mode) {
                fprintf(stderr,
#if __WORDSIZE == 64
                        "Input file too big (> %" PRIu64 " bytes). This is probably not a hardnested bitflip state table.\n"
#else
                        "Input file too big (> %lu bytes). This is probably not a hardnested bitflip state table.\n"
#endif
                        , HARDNESTED_TABLE_SIZE);

            } else {
                fprintf(stderr, "Input files too big (total > %lu bytes). These are probably not PM3 FPGA config files.\n", num_infiles * FPGA_CONFIG_SIZE);
            }
            for (uint16_t j = 0; j < num_infiles; j++) {
                fclose(infile[j]);
            }
            free(fpga_config);
            return (EXIT_FAILURE);
        }

        for (uint16_t j = 0; j < num_infiles; j++) {
            for (uint16_t k = 0; k < FPGA_INTERLEAVE_SIZE; k++) {
                c = (uint8_t)fgetc(infile[j]);
                if (!feof(infile[j])) {
                    fpga_config[i++] = c;
                } else if (num_infiles > 1) {
                    fpga_config[i++] = '\0';
                }
            }
        }

    } while (!all_feof(infile, num_infiles));

    // initialize zlib structures
    compressed_fpga_stream.next_in = fpga_config;
    compressed_fpga_stream.avail_in = i;
    compressed_fpga_stream.zalloc = fpga_deflate_malloc;
    compressed_fpga_stream.zfree = fpga_deflate_free;
    compressed_fpga_stream.opaque = Z_NULL;

    ret = deflateInit2(&compressed_fpga_stream,
                       COMPRESS_LEVEL,
                       Z_DEFLATED,
                       COMPRESS_WINDOW_BITS,
                       COMPRESS_MEM_LEVEL,
                       COMPRESS_STRATEGY);

    // estimate the size of the compressed output
    uint32_t outsize_max = deflateBound(&compressed_fpga_stream, compressed_fpga_stream.avail_in);
    uint8_t *outbuf = calloc(outsize_max, sizeof(uint8_t));
    compressed_fpga_stream.next_out = outbuf;
    compressed_fpga_stream.avail_out = outsize_max;

    if (ret == Z_OK) {
        ret = deflateTune(&compressed_fpga_stream,
                          COMPRESS_GOOD_LENGTH,
                          COMPRESS_MAX_LAZY,
                          COMPRESS_MAX_NICE_LENGTH,
                          COMPRESS_MAX_CHAIN);
    }

    if (ret == Z_OK) {
        ret = deflate(&compressed_fpga_stream, Z_FINISH);
    }

    fprintf(stdout, "compressed %u input bytes to %lu output bytes\n", i, compressed_fpga_stream.total_out);

    if (ret != Z_STREAM_END) {
        fprintf(stderr, "Error in deflate(): %d %s\n", ret, compressed_fpga_stream.msg);
        free(outbuf);
        deflateEnd(&compressed_fpga_stream);
        for (uint16_t j = 0; j < num_infiles; j++) {
            fclose(infile[j]);
        }
        fclose(outfile);
        free(fpga_config);
        return (EXIT_FAILURE);
    }

    for (i = 0; i < compressed_fpga_stream.total_out; i++) {
        fputc(outbuf[i], outfile);
    }

    free(outbuf);
    deflateEnd(&compressed_fpga_stream);
    for (uint16_t j = 0; j < num_infiles; j++) {
        fclose(infile[j]);
    }
    fclose(outfile);
    free(fpga_config);

    return (EXIT_SUCCESS);

}


int zlib_decompress(FILE *infile, FILE *outfile) {
#define DECOMPRESS_BUF_SIZE 1024
    uint8_t outbuf[DECOMPRESS_BUF_SIZE];
    uint8_t inbuf[DECOMPRESS_BUF_SIZE];
    int32_t ret;

    z_stream compressed_fpga_stream;

    // initialize zlib structures
    compressed_fpga_stream.next_in = inbuf;
    compressed_fpga_stream.avail_in = 0;
    compressed_fpga_stream.next_out = outbuf;
    compressed_fpga_stream.avail_out = DECOMPRESS_BUF_SIZE;
    compressed_fpga_stream.zalloc = fpga_deflate_malloc;
    compressed_fpga_stream.zfree = fpga_deflate_free;
    compressed_fpga_stream.opaque = Z_NULL;

    ret = inflateInit2(&compressed_fpga_stream, 0);

    do {
        if (compressed_fpga_stream.avail_in == 0) {
            compressed_fpga_stream.next_in = inbuf;
            uint16_t i = 0;
            do {
                int32_t c = fgetc(infile);
                if (!feof(infile)) {
                    inbuf[i++] = c & 0xFF;
                    compressed_fpga_stream.avail_in++;
                } else {
                    break;
                }
            } while (i < DECOMPRESS_BUF_SIZE);
        }

        ret = inflate(&compressed_fpga_stream, Z_SYNC_FLUSH);

        if (ret != Z_OK && ret != Z_STREAM_END) {
            break;
        }

        if (compressed_fpga_stream.avail_out == 0) {
            for (uint16_t i = 0; i < DECOMPRESS_BUF_SIZE; i++) {
                fputc(outbuf[i], outfile);
            }
            compressed_fpga_stream.avail_out = DECOMPRESS_BUF_SIZE;
            compressed_fpga_stream.next_out = outbuf;
        }
    } while (ret == Z_OK);

    if (ret == Z_STREAM_END) {  // reached end of input
        uint16_t i = 0;
        while (compressed_fpga_stream.avail_out < DECOMPRESS_BUF_SIZE) {
            fputc(outbuf[i++], outfile);
            compressed_fpga_stream.avail_out++;
        }
        fclose(outfile);
        fclose(infile);
        return (EXIT_SUCCESS);
    } else {
        fprintf(stderr, "Error. Inflate() returned error %d, %s", ret, compressed_fpga_stream.msg);
        fclose(outfile);
        fclose(infile);
        return (EXIT_FAILURE);
    }

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
                numbytes += 2;
            default: /* Fall through, two byte length field */
                current_length += fgetc(infile) << 8;
                current_length += fgetc(infile) << 0;
                numbytes += 2;
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
    fprintf(outfile, "\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "const int fpga_bitstream_num = %d;\n", num_infiles);
    fprintf(outfile, "const char* const fpga_version_information[%d] = {\n", num_infiles);
}

static int generate_fpga_version_info(FILE *infile[], char *infile_names[], int num_infiles, FILE *outfile) {

    char version_string[80] = "";

    print_version_info_preamble(outfile, num_infiles);

    for (int i = 0; i < num_infiles; i++) {
        FpgaGatherVersion(infile[i], infile_names[i], version_string, sizeof(version_string));
        fprintf(outfile, "\t\" %s\"", version_string);
        if (i != num_infiles - 1) {
            fprintf(outfile, ",");
        }
        fprintf(outfile, "\n");
    }
    fprintf(outfile, "};\n");
    return 0;
}

int main(int argc, char **argv) {
    FILE **infiles;
    char **infile_names;
    FILE *outfile;

    if (argc == 1 || argc == 2) {
        usage();
        return (EXIT_FAILURE);
    }

    if (!strcmp(argv[1], "-d")) { // Decompress

        infiles = calloc(1, sizeof(FILE *));
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
        outfile = fopen(argv[3], "wb");
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

        infiles = calloc(num_input_files, sizeof(FILE *));
        infile_names = calloc(num_input_files, sizeof(char *));
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
        outfile = fopen(argv[argc - 1], "wb");
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
