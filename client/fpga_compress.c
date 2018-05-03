//-----------------------------------------------------------------------------
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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "zlib.h"

#define MAX(a,b) ((a)>(b)?(a):(b))

// zlib configuration
#define COMPRESS_LEVEL			9		// use best possible compression
#define COMPRESS_WINDOW_BITS	15		// default = max = 15 for a window of 2^15 = 32KBytes
#define COMPRESS_MEM_LEVEL		9		// determines the amount of memory allocated during compression. Default = 8.
/* COMPRESS_STRATEGY can be 
	Z_DEFAULT_STRATEGY (the default), 
	Z_FILTERED (more huffmann, less string matching),
	Z_HUFFMAN_ONLY (huffman only, no string matching)
	Z_RLE (distances limited to one)
	Z_FIXED (prevents the use of dynamic Huffman codes)
*/	
#define	COMPRESS_STRATEGY		Z_DEFAULT_STRATEGY
// zlib tuning parameters:
#define COMPRESS_GOOD_LENGTH		258
#define	COMPRESS_MAX_LAZY			258	
#define	COMPRESS_MAX_NICE_LENGTH	258
#define	COMPRESS_MAX_CHAIN			8192

#define FPGA_INTERLEAVE_SIZE	288 	// (the FPGA's internal config frame size is 288 bits. Interleaving with 288 bytes should give best compression)
#define FPGA_CONFIG_SIZE            42336L  // our current fpga_[lh]f.bit files are 42175 bytes. Rounded up to next multiple of FPGA_INTERLEAVE_SIZE
#define HARDNESTED_TABLE_SIZE		(sizeof(uint32_t) * ((1L<<19)+1))

static void usage(void)
{
	fprintf(stdout, "Usage: fpga_compress <infile1> <infile2> ... <infile_n> <outfile>\n");
	fprintf(stdout, "          Combine n FPGA bitstream files and compress them into one.\n\n");
	fprintf(stdout, "       fpga_compress -d <infile> <outfile>");
	fprintf(stdout, "          Decompress <infile>. Write result to <outfile>");
	fprintf(stdout, "       fpga_compress -t <infile> <outfile>");
	fprintf(stdout, "          Compress hardnested table <infile>. Write result to <outfile>");
}


static voidpf fpga_deflate_malloc(voidpf opaque, uInt items, uInt size)
{
	return malloc(items*size);
}


static void fpga_deflate_free(voidpf opaque, voidpf address)
{
	return free(address);
}


static bool all_feof(FILE *infile[], uint8_t num_infiles)
{
	for (uint16_t i = 0; i < num_infiles; i++) {
		if (!feof(infile[i])) {
			return false;
		}
	}	
	return true;
}


int zlib_compress(FILE *infile[], uint8_t num_infiles, FILE *outfile, bool hardnested_mode)
{
	uint8_t *fpga_config;
	uint32_t i;
	int32_t ret;
	uint8_t c;
	z_stream compressed_fpga_stream;

	if (hardnested_mode) {
		fpga_config = malloc(num_infiles * HARDNESTED_TABLE_SIZE);
	} else {
	fpga_config = malloc(num_infiles * FPGA_CONFIG_SIZE);
	}		
	// read the input files. Interleave them into fpga_config[]
	i = 0;
	do {

		if (i >= num_infiles * (hardnested_mode?HARDNESTED_TABLE_SIZE:FPGA_CONFIG_SIZE)) {
			if (hardnested_mode) {
				fprintf(stderr, "Input file too big (> %lu bytes). This is probably not a hardnested bitflip state table.\n", HARDNESTED_TABLE_SIZE);
			} else {
				fprintf(stderr, "Input files too big (total > %lu bytes). These are probably not PM3 FPGA config files.\n", num_infiles*FPGA_CONFIG_SIZE);
			}
			for(uint16_t j = 0; j < num_infiles; j++) {
				fclose(infile[j]);
			}
			free(fpga_config);
			return(EXIT_FAILURE);
		}

		for(uint16_t j = 0; j < num_infiles; j++) {
			for(uint16_t k = 0; k < FPGA_INTERLEAVE_SIZE; k++) {
				c = fgetc(infile[j]);
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
		for(uint16_t j = 0; j < num_infiles; j++) {
			fclose(infile[j]);
		}
		fclose(outfile);
		free(infile);
		free(fpga_config);
		return(EXIT_FAILURE);
		}
		
	for (i = 0; i < compressed_fpga_stream.total_out; i++) {
		fputc(outbuf[i], outfile);
	}	

	free(outbuf);
	deflateEnd(&compressed_fpga_stream);
	for(uint16_t j = 0; j < num_infiles; j++) {
		fclose(infile[j]);
	}
	fclose(outfile);
	free(infile);
	free(fpga_config);
	
	return(EXIT_SUCCESS);
	
}


int zlib_decompress(FILE *infile, FILE *outfile)
{
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
		return(EXIT_SUCCESS);
	} else {
		fprintf(stderr, "Error. Inflate() returned error %d, %s", ret, compressed_fpga_stream.msg);
		fclose(outfile);
		fclose(infile);
		return(EXIT_FAILURE);
	}
	
}


int main(int argc, char **argv)
{
	FILE **infiles;
	FILE *outfile;
	
	if (argc == 1 || argc == 2) {
		usage();
		return(EXIT_FAILURE);
	}
	
	if (!strcmp(argv[1], "-d")) {			// Decompress
		infiles = calloc(1, sizeof(FILE*));
		if (argc != 4) {
			usage();
			return(EXIT_FAILURE);
		} 
		infiles[0] = fopen(argv[2], "rb");
		if (infiles[0] == NULL) {
			fprintf(stderr, "Error. Cannot open input file %s", argv[2]);
			return(EXIT_FAILURE);
		}
		outfile = fopen(argv[3], "wb");
		if (outfile == NULL) {
			fprintf(stderr, "Error. Cannot open output file %s", argv[3]);
			return(EXIT_FAILURE);
		}
		return zlib_decompress(infiles[0], outfile);

	} else {								// Compress

		bool hardnested_mode = false;
		int num_input_files = 0;
		if (!strcmp(argv[1], "-t")) { // hardnested table
			if (argc != 4) {
				usage();
				return(EXIT_FAILURE);
			}
			hardnested_mode = true;
			num_input_files = 1;
		} else {
			num_input_files = argc-2;
		}
		int adder = (hardnested_mode) ? 2 : 1;
		
		infiles = calloc(num_input_files, sizeof(FILE*));
		for (uint16_t i = 0; i < num_input_files; i++) { 
			infiles[i] = fopen(argv[i + adder ] , "rb");
			if (infiles[i] == NULL) {
				fprintf(stderr, "Error. Cannot open input file %s", argv[i + adder] );
				return(EXIT_FAILURE);
			} else {
                printf("Opening %s %d \n", argv[i + adder], i+adder );
			}
		}
		outfile = fopen(argv[argc-1], "wb");
		if (outfile == NULL) {
			fprintf(stderr, "Error. Cannot open output file %s", argv[argc-1]);
			return(EXIT_FAILURE);
		}
		return zlib_compress(infiles, num_input_files, outfile, hardnested_mode);
	}
}
