#ifndef FPGA_APIS_H_
#define FPGA_APIS_H_

#include "common.h"
#include "fpga.h"


/*
 Communication between ARM / FPGA is done inside armsrc/fpgaloader.c see: function FpgaSendCommand()
 Send 16 bit command / data pair to FPGA with the bit format:

+------ frame layout circa 2020 ------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C  M  M  M  M  P  P  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_LF_* or FPGA_HF_* parameter
|  C  C  C  C              D  D  D  D  D  D  D  D | C = FPGA_CMD_SET_DIVISOR, D = divisor
|  C  C  C  C              T  T  T  T  T  T  T  T | C = FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, T = threshold
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
|  C  C  C  C  P  P  P  P  P  P  P  P  P  P  P  P | C = FPGA_CMD_SET_PWR_PWM_LOW_COUNT, P = low count value for HF/LF driver power PWM (PM5)
+-------------------------------------------------+

+------ frame layout current ---------------------+
| 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
+-------------------------------------------------+
|  C  C  C  C           M  M  M  P  P  P  P  P  P | C = FPGA_CMD_SET_CONFREG, M = FPGA_MAJOR_MODE_*, P = FPGA_LF_* or FPGA_HF_* parameter
|  C  C  C  C              D  D  D  D  D  D  D  D | C = FPGA_CMD_SET_DIVISOR, D = divisor
|  C  C  C  C              T  T  T  T  T  T  T  T | C = FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, T = threshold
|  C  C  C  C                                   E | C = FPGA_CMD_TRACE_ENABLE, E=0 off, E=1 on
+-------------------------------------------------+

  shift_reg receive this 16bit frame

  LF command
  ----------
  shift_reg[15:12] == 4bit command
  LF has three commands (FPGA_CMD_SET_CONFREG, FPGA_CMD_SET_DIVISOR, FPGA_CMD_SET_EDGE_DETECT_THRESHOLD)
  Current commands uses only 2bits. We have room for up to 4bits of commands total (7).

  LF data
  -------
  shift_reg[11:0] == 12bit data
  lf data is divided into MAJOR MODES and configuration values.

  The major modes uses 3bits (0,1,2,3,7 | 000, 001, 010, 011, 111)
    000 FPGA_MAJOR_MODE_LF_READER        = Act as LF reader (modulate)
    001 FPGA_MAJOR_MODE_LF_EDGE_DETECT   = Simulate LF
    010 FPGA_MAJOR_MODE_LF_PASSTHRU      = Passthrough mode, CROSS_LO line connected to SSP_DIN. SSP_DOUT logic level controls if we modulate / listening
    011 FPGA_MAJOR_MODE_LF_ADC           = refactor hitag 2, clear ADC sampling
    111 FPGA_MAJOR_MODE_OFF              = turn off sampling.

  Each one of this major modes can have options. Currently these two major modes uses options.
   - FPGA_MAJOR_MODE_LF_READER
   - FPGA_MAJOR_MODE_LF_EDGE_DETECT

   FPGA_MAJOR_MODE_LF_READER
   -------------------------------------
    lf_field = 1bit  (FPGA_LF_ADC_READER_FIELD)

    You can send FPGA_CMD_SET_DIVISOR to set with FREQUENCY the fpga should sample at
    divisor = 8bits shift_reg[7:0]

   FPGA_MAJOR_MODE_LF_EDGE_DETECT
   ------------------------------------------
    lf_ed_toggle_mode = 1bits
    lf_ed_threshold = 8bits threshold defaults to 127

    You can send FPGA_CMD_SET_EDGE_DETECT_THRESHOLD to set a custom threshold
    lf_ed_threshold = 8bits threshold value.

  conf_word 12bits
    conf_word[7:5]  = 3bit major mode.
    conf_word[0]    = 1bit lf_field
    conf_word[1]    = 1bit lf_ed_toggle_mode
    conf_word[7:0]  = 8bit divisor
    conf_word[7:0]  = 8bit threshold

*/
// Defining commands, modes and options. This must be aligned to the definitions in fpga/define.v
#define FPGA_MAJOR_MODE_MASK                        0x01C0
#define FPGA_MINOR_MODE_MASK                        0x003F

// Definitions for the FPGA commands.
#define FPGA_CMD_SET_CONFREG                        (1<<12)
#define FPGA_CMD_SET_DIVISOR                        (2<<12)
#define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          (3<<12)
#define FPGA_CMD_TRACE_ENABLE                       (2<<12)
#define FPGA_CMD_SET_PWR_PWM_LOW_COUNT              (4<<12) // For PM5

// Major modes
#define FPGA_MAJOR_MODE_LF_READER                   (0<<6)
#define FPGA_MAJOR_MODE_LF_EDGE_DETECT              (1<<6)
#define FPGA_MAJOR_MODE_LF_PASSTHRU                 (2<<6)
#define FPGA_MAJOR_MODE_LF_ADC                      (3<<6)

#define FPGA_MAJOR_MODE_HF_READER                   (0<<6)
#define FPGA_MAJOR_MODE_HF_SIMULATOR                (1<<6)
#define FPGA_MAJOR_MODE_HF_ISO14443A                (2<<6)
#define FPGA_MAJOR_MODE_HF_SNIFF                    (3<<6)
#define FPGA_MAJOR_MODE_HF_ISO18092                 (4<<6)
#define FPGA_MAJOR_MODE_HF_GET_TRACE                (5<<6)
#define FPGA_MAJOR_MODE_OFF                         (7<<6)

// Options for LF_READER
#define FPGA_LF_ADC_READER_FIELD                    ( 1 )

// Options for LF_EDGE_DETECT
#define FPGA_LF_EDGE_DETECT_READER_FIELD            ( 1 )
#define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             ( 2 )

// Modulate the coil on the 10k leg alone instead of the 33 Ohm one, for a
// shallower tag answer.  Understood by LF_EDGE_DETECT and LF_ADC.
#define FPGA_LF_WEAK_LOAD                           ( 4 )

// Hold the envelope follower while the tag simulator is modulating, so its own
// answer does not drag the slicing levels away from the reader's signal.
#define FPGA_LF_EDGE_DETECT_HOLD_TRACKER            ( 8 )

// Let the edge detector keep working on a small tracked span, so a reader frame
// riding on a recovering envelope is still sliced instead of being ignored.
#define FPGA_LF_EDGE_DETECT_SENSITIVE               ( 16 )

// Detect edges from the slope of the signal rather than from a level, so a frame
// riding on a recovering envelope is still resolved.
#define FPGA_LF_EDGE_DETECT_SLOPE                   ( 32 )

// Options for the generic HF reader
#define FPGA_HF_READER_MODE_RECEIVE_IQ              ( 0 )
#define FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE       ( 1 )
#define FPGA_HF_READER_MODE_RECEIVE_PHASE           ( 2 )
#define FPGA_HF_READER_MODE_SEND_FULL_MOD           ( 3 )
#define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD        ( 4 )
#define FPGA_HF_READER_MODE_SNIFF_IQ                ( 5 )
#define FPGA_HF_READER_MODE_SNIFF_AMPLITUDE         ( 6 )
#define FPGA_HF_READER_MODE_SNIFF_PHASE             ( 7 )
#define FPGA_HF_READER_MODE_SEND_JAM                ( 8 )
#define FPGA_HF_READER_MODE_SEND_SHALLOW_MOD_RDV4   ( 9 )

#define FPGA_HF_READER_SUBCARRIER_848_KHZ           (0<<4)
#define FPGA_HF_READER_SUBCARRIER_424_KHZ           (1<<4)
#define FPGA_HF_READER_SUBCARRIER_212_KHZ           (2<<4)
#define FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ     (3<<4)

// Options for the HF simulated tag, how to modulate
#define FPGA_HF_SIMULATOR_NO_MODULATION             ( 0 )
#define FPGA_HF_SIMULATOR_MODULATE_BPSK             ( 1 )
#define FPGA_HF_SIMULATOR_MODULATE_212K             ( 2 )
#define FPGA_HF_SIMULATOR_MODULATE_424K             ( 4 )
#define FPGA_HF_SIMULATOR_MODULATE_424K_8BIT        ( 5 )

// Options for ISO14443A
#define FPGA_HF_ISO14443A_SNIFFER                   ( 0 )
#define FPGA_HF_ISO14443A_TAGSIM_LISTEN             ( 1 )
#define FPGA_HF_ISO14443A_TAGSIM_MOD                ( 2 )
#define FPGA_HF_ISO14443A_READER_LISTEN             ( 3 )
#define FPGA_HF_ISO14443A_READER_MOD                ( 4 )

// Options for ISO18092 / Felica
#define FPGA_HF_ISO18092_FLAG_NOMOD                 ( 1 ) // 0001 disable modulation module
#define FPGA_HF_ISO18092_FLAG_424K                  ( 2 ) // 0010 should enable 414k mode (untested). No autodetect
#define FPGA_HF_ISO18092_FLAG_READER                ( 4 ) // 0100 enables antenna power, to act as a reader instead of tag
#define FPGA_HF_ISO18092_FLAG_PROBE                 ( 8 ) // 1000 signal probe: stream envelope peak-to-peak instead of demodulated bits

// Options for adc mux.
// The mux is no longer set directly through the GPIO PIN to solve the problem of high coupling with the platform.
typedef enum {
    ADC_MUXSEL_HIPKD = 0U,
    ADC_MUXSEL_LOPKD,
    ADC_MUXSEL_LORAW,
    ADC_MUXSEL_HIRAW,
} adc_mux_io_t;

// Block and wait for SSC data to be ready.
#define FPGA_SSC_RX_READY_WAIT()    while(!FPGA_SSC_RX_Ready()) {}

// Check if data already ready.
// On the AT91 platform, There is no need to consider overflow, as the data is always up-to-date.
// On the AT32 platform, You must call this function to confirm that the data is ready before reading the value.
// Warn: Continuously call this function to refresh the rx state, to avoid receiving stopped due to unused old data!
//  If no this function call after DELAY/SlowTask, you may always get a fixed old data!!!
//  !!! For maximum platform compatibility, it is essential to call this function !!!
STATIC_FORCE_INLINE bool FPGA_SSC_RX_Ready(void);

// Check if data can transmit next one.
// The data clk is from fpga, so if fpga rx & process done, the next byte can transmit.
STATIC_FORCE_INLINE bool FPGA_SSC_TX_Ready(void);

// Check if RX by DMA is done.
// Note: Only call this function to check data ready when DMA running.
STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Done(void);

// Check if TX done. if done? next byte can put in DT register by FPGA_SSC_TX_Value() function.
// Note: Call this function before FPGA_SSC_TX_Value() calling.
STATIC_FORCE_INLINE bool FPGA_SSC_TX_Done(void);

// Read the data received by SSC. The number of bits and bits order of the data are determined when configuring SSC.
// Note: this function has different characteristics on different platforms.
// On the AT91 platform, you can always get the latest received data.
// On the AT32 platform, if you don't check if the data is already ready, you may get an old data.
// Warn: We must first ensure that the data is ready, call the FPGA_SSC_RX_READY_WAIT() or FPGA_SSC_RX_Ready()
STATIC_FORCE_INLINE uint32_t FPGA_SSC_RX_Value(void);

// Send the data by SSC, no DMA.
// Warn: Before sending, it is necessary to check if the previous sending has been completed!
STATIC_FORCE_INLINE void FPGA_SSC_TX_Value(uint32_t v);

// Some platforms' send(data) registers may not automatically reset to zero.
// We need to ensure that a clearing action is performed before and after sending.
// Problem solved: If the sending (data) register is not cleared or non-zero data is received,
// it may cause erroneous modulation by continuing to send non-zero data after the transmission is completed.
// Note: This function will not wait for the sending to complete(Just waiting for TX ready).
STATIC_FORCE_INLINE void FPGA_SSC_TX_Clear(void);

// DMA rx disable
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Disable(void);

// DMA rx enable
// Note: Just started DMA transfer, will not reconfigure DMA.
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Enable(void);

// The buf address currently receiving and storing data (not the address of data that has already been received)
// |done|done|done|working|  <- you will get 'working' address.
STATIC_FORCE_INLINE uint32_t *FPGA_SSC_DMA_RX_Current_Address(void);

// How much data still needs to be received?
// After receiving an item each time, subtract 1 from this value.
// Note: Is not bytes count, the bytes count is from FPGA_SSC_DMA_RX_Remaining_Count() * SSC_DATA_WIDTH
STATIC_FORCE_INLINE uint16_t FPGA_SSC_DMA_RX_Remaining_Count(void);

// Continuing to trigger the next reception,
// DMA will automatically perform address rotation when the device supports NEXT BUF.
// Attention: This may result in data being overwritten.
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Repeat(void *buf, uint16_t len);

// Continue to trigger the next reception.
// This function will only trigger one reception and will not automatically trigger two receptions using the same address.
// It can be used when data processing speed is slow or when asynchronous reception processing with multiple buffers is required.
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Single(void *buf, uint16_t len);

//-----------------------------------------------------------------------------
// DMA RX double-buffer status & refresh (primary + "next").
// The AT91 PDC exposes a primary buffer (RPR/RCR) and a "next" buffer
// (RNPR/RNCR); when the primary drains, the "next" buffer is swapped in
// automatically. Platforms without a "next" buffer (AT32) implement these
// so the primary operations degrade to no-ops and all (re)arming is done
// through the secondary buffer.
//-----------------------------------------------------------------------------

// Has the primary RX buffer fully drained (its remaining count reached 0)?
STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Primary_Done(void);

// Has the "next" RX buffer also been consumed (nothing left to swap in)?
STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Secondary_Done(void);

// Re-arm both the primary and the "next" RX buffer (restart continuous RX).
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Both(void *buf, uint16_t len);

// Re-arm only the "next" RX buffer.
STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Secondary(void *buf, uint16_t len);

//-----------------------------------------------------------------------------
// Provide a 24MHz clock from ARM to FPGA
// This is the most important main clock for FPGA, so it must be implemented!
//-----------------------------------------------------------------------------
void FpgaSetup24MHzClk(void);

//-----------------------------------------------------------------------------
// Reset the fpga communication interface of Fpga
// 1. SPI for CMD
// 2. SSC for DataStream
// In AT32, it's reset the both spi, no SSC.
//-----------------------------------------------------------------------------
void FpgaResetComInterface(void);

//-----------------------------------------------------------------------------
// The working mode of FPGA corresponds to the SSC communication frame mode. For platform compatibility,
// the cross-platform design only supports 8 or 16 bits.
// If the function returns 1, it is 16 bits data and MSB,
// otherwise, it is 8 bits data and MSB.
//-----------------------------------------------------------------------------
bool FpgaIs16BitMsbMode(uint16_t fpga_mode);

//-----------------------------------------------------------------------------
// Set up the synchronous serial port with the set of options that fits
// the FPGA mode. Both RX and TX are always enabled.
// For AT91, it is SSC, and for AT32, it is SPI-TI_MODE
// Note: at32 spi 16bit max, so please try to use 8-bit or 16 bit transmission,
//       otherwise platform compatibility cannot be handled.
//-----------------------------------------------------------------------------
void FpgaSetupSsc(uint16_t fpga_mode);

//-----------------------------------------------------------------------------
// Modify the mode settings for rx&tx frames
// bits: How many bits are received each time, 8 or 16
// msb:  Should we transfer MSB first?
// Note: It can only be used to overwrite the settings of FpgaSetupSsc.
// Warn: RX&TX must use data of the same width! Avoid platform compatibility issues.
//-----------------------------------------------------------------------------
void FpgaUpdateFrameMode(uint8_t bits, bool rx_msb, bool tx_msb);

//-----------------------------------------------------------------------------
// Set up DMA to receive samples from the FPGA. We will use the PDC, with
// a single buffer as a circular buffer (so that we just chain back to
// ourselves, not to another buffer).
//-----------------------------------------------------------------------------
bool FpgaSetupSscRxDmaRepeat(void *buf, uint16_t len);

//-----------------------------------------------------------------------------
// Set up DMA to receive samples from the FPGA. We will use the PDC, with
// a single buffer not circular buffer (So it will only trigger one collection to this buffer
// to avoid data being overwritten.).
//-----------------------------------------------------------------------------
bool FpgaSetupSscRxDmaSingle(void *buf, uint16_t len);

//-----------------------------------------------------------------------------
// Send a 16 bit command/data pair to the FPGA.
// The bit format is:  C3 C2 C1 C0 D11 D10 D9 D8 D7 D6 D5 D4 D3 D2 D1 D0
// where C is the 4 bit command and D is the 12 bit data
//
// @params cmd and v  gets OR:ED over each other.  Take careful note of overlapping bits.
//-----------------------------------------------------------------------------
void FpgaSendCommand(uint16_t cmd, uint16_t v);

//-----------------------------------------------------------------------------
// Write the FPGA setup word (that determines what mode the logic is in, read
// vs. clone vs. etc.). This is now a special case of FpgaSendCommand() to
// avoid changing this function's occurrence everywhere in the source code.
//-----------------------------------------------------------------------------
void FpgaWriteConfWord(uint16_t v);

//-----------------------------------------------------------------------------
// enable FPGA internal tracing
//-----------------------------------------------------------------------------
void FpgaEnableTracing(void);

//-----------------------------------------------------------------------------
// disable FPGA internal tracing
//-----------------------------------------------------------------------------
void FpgaDisableTracing(void);

//-----------------------------------------------------------------------------
// Print the current FPGA information.
//-----------------------------------------------------------------------------
void Fpga_print_status(void);

//-----------------------------------------------------------------------------
// Set up the CMOS switches that mux the ADC: four switches, independently
// closable, but should only close one at a time. Not an FPGA thing, but
// the samples from the ADC always flow through the FPGA.
//-----------------------------------------------------------------------------
void SetAdcMuxFor(adc_mux_io_t muxTo);

//-----------------------------------------------------------------------------
// general turn off the antenna method
//-----------------------------------------------------------------------------
void switch_off(void);

//-----------------------------------------------------------------------------
// Start FPGA bitstream configuration. Once started, the configuration will
// restart from the beginning of the bitstream (any previous configuration
// progress will be discarded).
// configSram: If true, configure into SRAM; if false, configure into Flash.
//             Note: FPGAs on certain platforms may not support Flash
//             configuration. If Flash configuration is not supported,
//             PM3_EDEVNOTSUPP will be returned.
// fileLength: The length of the bitstream file in bytes. Some platforms may
//             require this parameter to determine the configuration result or
//             perform pre-configuration preparations. If the length exceeds
//             the maximum size supported by the FPGA, PM3_EOVFLOW will be
//             returned.
// return: PM3_XXX error code. Returns PM3_SUCCESS on successful configuration,
//         or an error code on failure. If the error code is PM3_EFAILED, refer
//         to FpgaConfigPlatformStatus() for more detailed error information.
//-----------------------------------------------------------------------------
int FpgaStartConfig(bool configSram, uint32_t fileLength);

//-----------------------------------------------------------------------------
// Write bitstream data to the FPGA.
// data: Pointer to the bitstream data. Memory alignment is not required for
//       the passed pointer, as each platform implementation handles buffered
//       writing based on its minimum write unit.
// data_length: Length of the bitstream data in bytes. If the length exceeds
//              the maximum size supported by the FPGA, PM3_EOVFLOW will be
//              returned.
// return: PM3_XXX error code. Returns PM3_SUCCESS on successful configuration,
//         or an error code on failure. If the error code is PM3_EFAILED, refer
//         to FpgaConfigPlatformStatus() for more detailed error information.
//-----------------------------------------------------------------------------
int FpgaConfigWrite(uint8_t *data, uint32_t data_length);

//-----------------------------------------------------------------------------
// Stop FPGA bitstream configuration and release resources allocated during
// the configuration process.
// return: PM3_XXX error code. Returns PM3_SUCCESS if the configuration is
//         successfully stopped, or an error code if stopping fails. If the
//         error code is PM3_EFAILED, refer to FpgaConfigPlatformStatus() for
//         more detailed error information.
//-----------------------------------------------------------------------------
int FpgaStopConfig(void);

//-----------------------------------------------------------------------------
// Get the FPGA configuration status. The return value is a platform-specific
// status code. Please refer to the platform-related documentation or source
// code for specific status information.
// This function is primarily used to obtain more detailed error information
// when configuration fails, facilitating debugging and issue troubleshooting.
//-----------------------------------------------------------------------------
uint32_t FpgaConfigPlatformStatus(void);

#ifdef PM5
#include "fpga_hw_at32.h"
#else
#include "fpga_hw_at91.h"
#endif

#endif // FPGA_APIS_H_
