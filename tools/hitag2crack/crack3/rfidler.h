/***************************************************************************
 * A copy of the GNU GPL is appended to this file.                         *
 *                                                                         *
 * This licence is based on the nmap licence, and we express our gratitude *
 * for the work that went into producing it. There is no other connection  *
 * between RFIDler and nmap either expressed or implied.                   *
 *                                                                         *
 ********************** IMPORTANT RFIDler LICENSE TERMS ********************
 *                                                                         *
 *                                                                         *
 * All references to RFIDler herein imply all it's derivatives, namely:    *
 *                                                                         *
 * o RFIDler-LF Standard                                                   *
 * o RFIDler-LF Lite                                                       *
 * o RFIDler-LF Nekkid                                                     *
 *                                                                         *
 *                                                                         *
 * RFIDler is (C) 2013-2015 Aperture Labs Ltd.                             *
 *                                                                         *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed RFIDler technology into proprietary   *
 * software or hardware, we sell alternative licenses                      *
 * (contact sales@aperturelabs.com).                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * RFIDler with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Aperture Labs Ltd. grants*
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * RFIDler or grant special permissions to use it in other open source     *
 * software.  Please contact sales@aperturelabs.com with any such requests.*
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * RFIDler in other works, are happy to help.  As mentioned above, we also *
 * offer alternative license to integrate RFIDler into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of RFIDler.  Please email sales@aperturelabs.com  *
 * for further information.                                                *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port RFIDler to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the RFIDler mailing list for possible incorporation into the         *
 * main distribution.  By sending these changes to Aperture Labs Ltd. or   *
 * one of the Aperture Labs Ltd. development mailing lists, or checking    *
 * them into the RFIDler source code repository, it is understood (unless  *
 * you specify otherwise) that you are offering the RFIDler Project        *
 * (Aperture Labs Ltd.) the unlimited, non-exclusive right to reuse,       *
 * modify, and relicense the code.  RFIDler will always be available Open  *
 * Source, but this is important because the inability to relicense code   *
 * has caused devastating problems for other Free Software projects (such  *
 * as KDE and NASM).  We also occasionally relicense the code to third     *
 * parties as discussed above. If you wish to specify special license      *
 * conditions of your contributions, just say so when you send them.       *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the RFIDler   *
 * license file for more details (it's in a COPYING file included with     *
 * RFIDler, and also available from                                        *
 *   https://github.com/ApertureLabsLtd/RFIDler/COPYING                    *
 *                                                                         *
 ***************************************************************************/

// Author: Adam Laurie <adam@aperturelabs.com>

#include <stdio.h>
#include <string.h>

// BCD hardware revision for usb descriptor (usb_descriptors.c)
#define RFIDLER_HW_VERSION        0x020

// max sizes in BITS
#define MAXBLOCKSIZE        512
#define MAXTAGSIZE          4096
#define MAXUID              512

#define TMP_LARGE_BUFF_LEN  2048
#define TMP_SMALL_BUFF_LEN  256
#define ANALOGUE_BUFF_LEN   8192

#define COMMS_BUFFER_SIZE   128

#define DETECT_BUFFER_SIZE  512

#define SAMPLEMASK          ~(BIT_1 | BIT_0)    // mask to remove two bottom bits from analogue sample - we will then use those for reader & bit period

// globals

extern BOOL             WiegandOutput;                      // Output wiegand data whenenver UID is read
extern BYTE             *EMU_Reset_Data;                    // Pointer to full array of bits as bytes, stored as 0x00/0x01, '*'  terminated
extern BYTE             *EMU_Data;                          // Pointer to current location in EMU_Reset_Data
extern BYTE             EMU_ThisBit;                        // The next data bit to transmit
extern BYTE             EMU_SubCarrier_T0;                  // Number of Frame Clocks for sub-carrier '0'
extern BYTE             EMU_SubCarrier_T1;                  // Number of Frame Clocks for sub-carrier '1'
extern unsigned int     EMU_Repeat;                         // Number of times to transmit full data set
extern BOOL             EMU_Background;                     // Emulate in the background until told to stop
extern unsigned int     EMU_DataBitRate;                    // Number of Frame Clocks per bit
extern BYTE             TmpBits[TMP_LARGE_BUFF_LEN];        // Shared scratchpad
extern BYTE             ReaderPeriod;                       // Flag for sample display
extern unsigned char    Comms_In_Buffer[COMMS_BUFFER_SIZE]; // USB/Serial buffer
extern BYTE             Interface;                          // user interface - CLI or API
extern BYTE             CommsChannel;                       // user comms channel - USB or UART
extern BOOL             FakeRead;                           // flag for analogue sampler to signal it wants access to buffers during read
extern BOOL             PWD_Mode;                           // is this tag password protected?
extern BYTE             Password[9];                        // 32 bits as HEX string set with LOGIN
extern unsigned int     Led_Count;                          // LED status counter, also used for entropy
extern unsigned long    Reader_Bit_Count;                   // Reader ISR bit counter
extern char             Previous;                           // Reader ISR previous bit type

// RWD (read/write device) coil state
extern BYTE             RWD_State;                              // current state of RWD coil
extern unsigned int     RWD_Fc;                                 // field clock in uS
extern unsigned int     RWD_Gap_Period;                         // length of command gaps in OC5 ticks
extern unsigned int     RWD_Zero_Period;                        // length of '0' in OC5 ticks
extern unsigned int     RWD_One_Period;                         // length of '1' in OC5 ticks
extern unsigned int     RWD_Sleep_Period;                       // length of initial sleep to reset tag in OC5 ticks
extern unsigned int     RWD_Wake_Period;                        // length required for tag to restart in OC5 ticks
extern unsigned int     RWD_Wait_Switch_TX_RX;                  // length to wait when switching from TX to RX in OC5 ticks
extern unsigned int     RWD_Wait_Switch_RX_TX;                  // length to wait when switching from RX to TX in OC5 ticks
extern unsigned int     RWD_Post_Wait;                          // low level ISR wait period in OC5 ticks
extern unsigned int     RWD_OC5_config;                         // Output Compare Module settings
extern unsigned int     RWD_OC5_r;                              // Output Compare Module primary compare value
extern unsigned int     RWD_OC5_rs;                             // Output Compare Module secondary compare value
extern BYTE             RWD_Command_Buff[TMP_SMALL_BUFF_LEN];   // Command buffer, array of bits as bytes, stored as 0x00/0x01, '*' terminated
extern BYTE             *RWD_Command_ThisBit;                   // Current command bit
extern BOOL             Reader_ISR_State;                       // current state of reader ISR

// NVM variables
// timings etc. that want to survive a reboot should go here
typedef struct {
    BYTE            Name[7];  // will be set to "RFIDler" so we can test for new device
    BYTE            AutoRun[128]; // optional command to run at startup
    unsigned char   TagType;
    unsigned int    PSK_Quality;
    unsigned int    Timeout;
    unsigned int    Wiegand_Pulse;
    unsigned int    Wiegand_Gap;
    BOOL            Wiegand_IdleState;
    unsigned int    FrameClock;
    unsigned char   Modulation;
    unsigned int    DataRate;
    unsigned int    DataRateSub0;
    unsigned int    DataRateSub1;
    unsigned int    DataBits;
    unsigned int    DataBlocks;
    unsigned int    BlockSize;
    unsigned char   SyncBits;
    BYTE            Sync[4];
    BOOL            BiPhase;
    BOOL            Invert;
    BOOL            Manchester;
    BOOL            HalfDuplex;
    unsigned int    Repeat;
    unsigned int    PotLow;
    unsigned int    PotHigh;
    unsigned int    RWD_Gap_Period;
    unsigned int    RWD_Zero_Period;
    unsigned int    RWD_One_Period;
    unsigned int    RWD_Sleep_Period;
    unsigned int    RWD_Wake_Period;
    unsigned int    RWD_Wait_Switch_TX_RX;
    unsigned int    RWD_Wait_Switch_RX_TX;
} StoredConfig;

// somewhere to store TAG data. this will be interpreted according to the TAG
// type.
typedef struct {
    BYTE   TagType;            // raw tag type
    BYTE   EmulatedTagType;    // tag type this tag is configured to emulate
    BYTE   UID[MAXUID + 1];    // Null-terminated HEX string
    BYTE   Data[MAXTAGSIZE];   // raw data
    unsigned char   DataBlocks;         // number of blocks in Data field
    unsigned int    BlockSize;          // blocksize in bits
} VirtualTag;

extern StoredConfig RFIDlerConfig;
extern VirtualTag RFIDlerVTag;
extern BYTE TmpBuff[NVM_PAGE_SIZE];
extern BYTE DataBuff[ANALOGUE_BUFF_LEN];
extern unsigned int DataBuffCount;
extern const BYTE *ModulationSchemes[];
extern const BYTE *OnOff[];
extern const BYTE *HighLow[];
extern const BYTE *TagTypes[];

// globals for ISRs
extern BYTE EmulationMode;
extern unsigned long HW_Bits;
extern BYTE HW_Skip_Bits;
extern unsigned int PSK_Min_Pulse;
extern BOOL PSK_Read_Error;
extern BOOL Manchester_Error;
extern BOOL SnifferMode;
extern unsigned int Clock_Tick_Counter;
extern BOOL Clock_Tick_Counter_Reset;

// smart card lib
#define MAX_ATR_LEN			(BYTE)33
extern BYTE scCardATR[MAX_ATR_LEN];
extern BYTE scATRLength;

// RTC
extern rtccTime	RTC_time;			// time structure
extern rtccDate	RTC_date;			// date structure

// digital pots
#define POTLOW_DEFAULT      100
#define POTHIGH_DEFAULT     150
#define DC_OFFSET           60                 // analogue circuit DC offset (as close as we can get without using 2 LSB)
#define VOLTS_TO_POT        0.019607843F

// RWD/clock states
#define                 RWD_STATE_INACTIVE              0       // RWD not in use
#define                 RWD_STATE_GO_TO_SLEEP           1       // RWD coil shutdown request
#define                 RWD_STATE_SLEEPING              2       // RWD coil shutdown for sleep period
#define                 RWD_STATE_WAKING                3       // RWD active for pre-determined period after reset
#define                 RWD_STATE_START_SEND            4       // RWD starting send of data
#define                 RWD_STATE_SENDING_GAP           5       // RWD sending a gap
#define                 RWD_STATE_SENDING_BIT           6       // RWD sending a data bit
#define                 RWD_STATE_POST_WAIT             7       // RWD finished sending data, now in forced wait period
#define                 RWD_STATE_ACTIVE                8       // RWD finished, now just clocking a carrier

// reader ISR states
#define                 READER_STOPPED                  0       // reader not in use
#define                 READER_IDLING                   1       // reader ISR running to preserve timing, but not reading
#define                 READER_RUNNING                  2       // reader reading bits


// user interface types
#define INTERFACE_API                   0
#define INTERFACE_CLI                   1

// comms channel
#define COMMS_NONE                      0
#define COMMS_USB                       1
#define COMMS_UART                      2

#define MAX_HISTORY                     2 // disable most of history for now - memory issue

// tag write retries
#define TAG_WRITE_RETRY                 5

// modulation modes - uppdate ModulationSchemes[] in tags.c if you change this
#define MOD_MODE_NONE                   0
#define MOD_MODE_ASK_OOK                1
#define MOD_MODE_FSK1                   2
#define MOD_MODE_FSK2                   3
#define MOD_MODE_PSK1                   4
#define MOD_MODE_PSK2                   5
#define MOD_MODE_PSK3                   6

// TAG types - update TagTypes[] in tags.c if you add to this list
#define TAG_TYPE_NONE                   0
#define TAG_TYPE_ASK_RAW                1
#define TAG_TYPE_FSK1_RAW               2
#define TAG_TYPE_FSK2_RAW               3
#define TAG_TYPE_PSK1_RAW               4
#define TAG_TYPE_PSK2_RAW               5
#define TAG_TYPE_PSK3_RAW               6
#define TAG_TYPE_HITAG1                 7
#define TAG_TYPE_HITAG2                 8
#define TAG_TYPE_EM4X02                 9
#define TAG_TYPE_Q5                     10
#define TAG_TYPE_HID_26                 11
#define TAG_TYPE_INDALA_64              12
#define TAG_TYPE_INDALA_224             13
#define TAG_TYPE_UNIQUE                 14
#define TAG_TYPE_FDXB                   15
#define TAG_TYPE_T55X7                  16      // same as Q5 but different timings and no modulation-defeat
#define TAG_TYPE_AWID_26                17
#define TAG_TYPE_EM4X05                 18
#define TAG_TYPE_TAMAGOTCHI             19
#define TAG_TYPE_HDX                    20      // same underlying data as FDX-B, but different modulation & telegram

// various

#define BINARY                          0
#define HEX                             1

#define NO_ADDRESS                      -1

#define ACK                             TRUE
#define NO_ACK                          FALSE

#define BLOCK                           TRUE
#define NO_BLOCK                        FALSE

#define DATA                            TRUE
#define NO_DATA                         FALSE

#define DEBUG_PIN_ON                    HIGH
#define DEBUG_PIN_OFF                   LOW

#define FAST                            FALSE
#define SLOW                            TRUE

#define NO_TRIGGER                      0

#define LOCK                            TRUE
#define NO_LOCK                         FALSE

#define NFC_MODE                        TRUE
#define NO_NFC_MODE                     FALSE

#define ONESHOT_READ                    TRUE
#define NO_ONESHOT_READ                 FALSE

#define RESET                           TRUE
#define NO_RESET                        FALSE

#define SHUTDOWN_CLOCK                  TRUE
#define NO_SHUTDOWN_CLOCK               FALSE

#define SYNC                            TRUE
#define NO_SYNC                         FALSE

#define VERIFY                          TRUE
#define NO_VERIFY                       FALSE

#define VOLATILE                        FALSE
#define NON_VOLATILE                    TRUE

#define NEWLINE                         TRUE
#define NO_NEWLINE                      FALSE

#define WAIT                            TRUE
#define NO_WAIT                         FALSE

#define WIPER_HIGH                      0
#define WIPER_LOW                       1

// conversion for time to ticks
#define US_TO_TICKS                     1000000L
#define US_OVER_10_TO_TICKS             10000000L
#define US_OVER_100_TO_TICKS            100000000L
// we can't get down to this level on pic, but we want to standardise on timings, so for now we fudge it
#define CONVERT_TO_TICKS(x)             ((x / 10) * (GetSystemClock() / US_OVER_10_TO_TICKS))
#define CONVERT_TICKS_TO_US(x)          (x / (GetSystemClock() / US_TO_TICKS))
#define TIMER5_PRESCALER                16
#define MAX_TIMER5_TICKS                (65535 * TIMER5_PRESCALER)

// other conversions

// bits to hex digits
#define HEXDIGITS(x)                    (x / 4)
#define HEXTOBITS(x)                    (x * 4)
