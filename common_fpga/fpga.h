//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------

#ifndef __FPGA_H
#define __FPGA_H

#include <stdbool.h>
#include <inttypes.h>

#define FPGA_BITSTREAM_FIXED_HEADER_SIZE    sizeof(bitparse_fixed_header)
#define FPGA_INTERLEAVE_SIZE                288
#define FPGA_CONFIG_SIZE                    42336L  // our current fpga_[lh]f.bit files are 42175 bytes. Rounded up to next multiple of FPGA_INTERLEAVE_SIZE
#define FPGA_RING_BUFFER_BYTES              (1024 * 39)
#define FPGA_TRACE_SIZE                     3072

static const uint8_t bitparse_fixed_header[] = {0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01};
extern const int g_fpga_bitstream_num;
extern const char *const g_fpga_version_information[];

#endif
