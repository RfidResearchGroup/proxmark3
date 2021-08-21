// Defining commands, modes and options. This must be aligned to the definitions in fpgaloader.h
// Note: the definitions here are without shifts

// Commands:
`define FPGA_CMD_SET_CONFREG                        1
`define FPGA_CMD_TRACE_ENABLE                       2

// Major modes:
`define FPGA_MAJOR_MODE_HF_READER                   0
`define FPGA_MAJOR_MODE_HF_SIMULATOR                1
`define FPGA_MAJOR_MODE_HF_ISO14443A                2
`define FPGA_MAJOR_MODE_HF_SNIFF                    3
`define FPGA_MAJOR_MODE_HF_ISO18092                 4
`define FPGA_MAJOR_MODE_HF_GET_TRACE                5
`define FPGA_MAJOR_MODE_OFF                         7

// Options for the generic HF reader
`define FPGA_HF_READER_MODE_RECEIVE_IQ              0
`define FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE       1
`define FPGA_HF_READER_MODE_RECEIVE_PHASE           2
`define FPGA_HF_READER_MODE_SEND_FULL_MOD           3
`define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD        4
`define FPGA_HF_READER_MODE_SNIFF_IQ                5
`define FPGA_HF_READER_MODE_SNIFF_AMPLITUDE         6
`define FPGA_HF_READER_MODE_SNIFF_PHASE             7
`define FPGA_HF_READER_MODE_SEND_JAM                8

`define FPGA_HF_READER_SUBCARRIER_848_KHZ           0
`define FPGA_HF_READER_SUBCARRIER_424_KHZ           1
`define FPGA_HF_READER_SUBCARRIER_212_KHZ           2

// Options for the HF simulated tag, how to modulate
`define FPGA_HF_SIMULATOR_NO_MODULATION             0
`define FPGA_HF_SIMULATOR_MODULATE_BPSK             1
`define FPGA_HF_SIMULATOR_MODULATE_212K             2
`define FPGA_HF_SIMULATOR_MODULATE_424K             4
`define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        5

// Options for ISO14443A
`define FPGA_HF_ISO14443A_SNIFFER                   0
`define FPGA_HF_ISO14443A_TAGSIM_LISTEN             1
`define FPGA_HF_ISO14443A_TAGSIM_MOD                2
`define FPGA_HF_ISO14443A_READER_LISTEN             3
`define FPGA_HF_ISO14443A_READER_MOD                4

//options for ISO18092 / Felica
`define FPGA_HF_ISO18092_FLAG_NOMOD                 1 // 0001 disable modulation module
`define FPGA_HF_ISO18092_FLAG_424K                  2 // 0010 should enable 414k mode (untested). No autodetect
`define FPGA_HF_ISO18092_FLAG_READER                4 // 0100 enables antenna power, to act as a reader instead of tag