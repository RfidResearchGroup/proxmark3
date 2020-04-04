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
 * RFIDler is (C) 2013-2014 Aperture Labs Ltd.                             *
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



#ifndef HARDWARE_PROFILE_UBW32_H
#define HARDWARE_PROFILE_UBW32_H

//#include "plib.h"
typedef char BOOL;
typedef char BYTE;
typedef int rtccTime;
typedef int rtccDate;


#ifndef __PIC32MX__
#define __PIC32MX__
#endif

#define GetSystemClock()            (80000000ul)
#define GetPeripheralClock()        (GetSystemClock())
#define GetInstructionClock()       (GetSystemClock())

//#define USE_SELF_POWER_SENSE_IO
#define tris_self_power     TRISAbits.TRISA2    // Input
#define self_power          1

//#define USE_USB_BUS_SENSE_IO
#define tris_usb_bus_sense  TRISBbits.TRISB5    // Input
#define USB_BUS_SENSE       1

// LEDs
#define mLED_1              LATEbits.LATE3

#define mLED_2              LATEbits.LATE2
#define mLED_Comms          mLED_2

#define mLED_3              LATEbits.LATE1
#define mLED_Clock          mLED_3

#define mLED_4              LATEbits.LATE0
#define mLED_Emulate        mLED_4

#define mLED_5              LATGbits.LATG6
#define mLED_Read           mLED_5

#define mLED_6              LATAbits.LATA15
#define mLED_User           mLED_6

#define mLED_7              LATDbits.LATD11
#define mLED_Error          mLED_7

// active low
#define mLED_ON             0
#define mLED_OFF            1

#define mGetLED_1()         mLED_1
#define mGetLED_USB()       mLED_1
#define mGetLED_2()         mLED_2
#define mGetLED_Comms()     mLED_2
#define mGetLED_3()         mLED_3
#define mGetLED_Clock()     mLED_3
#define mGetLED_4()         mLED_4
#define mGetLED_Emulate()   mLED_4
#define mGetLED_5()         mLED_5
#define mGetLED_Read()      mLED_5
#define mGetLED_6()         mLED_6
#define mGetLED_User()      mLED_6
#define mGetLED_7()         mLED_7
#define mGetLED_Error()     mLED_7

#define mLED_1_On()         mLED_1 = mLED_ON
#define mLED_USB_On()       mLED_1_On()
#define mLED_2_On()         mLED_2 = mLED_ON
#define mLED_Comms_On()     mLED_2_On()
#define mLED_3_On()         mLED_3 = mLED_ON
#define mLED_Clock_On()     mLED_3_On()
#define mLED_4_On()         mLED_4 = mLED_ON
#define mLED_Emulate_On()   mLED_4_On()
#define mLED_5_On()         mLED_5 = mLED_ON
#define mLED_Read_On()      mLED_5_On()
#define mLED_6_On()         mLED_6 = mLED_ON
#define mLED_User_On()      mLED_6_On()
#define mLED_7_On()         mLED_7 = mLED_ON
#define mLED_Error_On()     mLED_7_On()

#define mLED_1_Off()        mLED_1 = mLED_OFF
#define mLED_USB_Off()      mLED_1_Off()
#define mLED_2_Off()        mLED_2 = mLED_OFF
#define mLED_Comms_Off()    mLED_2_Off()
#define mLED_3_Off()        mLED_3 = mLED_OFF
#define mLED_Clock_Off()    mLED_3_Off()
#define mLED_4_Off()        mLED_4 = mLED_OFF
#define mLED_Emulate_Off()  mLED_4_Off()
#define mLED_5_Off()        mLED_5 = mLED_OFF
#define mLED_Read_Off()     mLED_5_Off()
#define mLED_6_Off()        mLED_6 = mLED_OFF
#define mLED_User_Off()     mLED_6_Off()
#define mLED_7_Off()        mLED_7 = mLED_OFF
#define mLED_Error_Off()    mLED_7_Off()

#define mLED_1_Toggle()        mLED_1 = !mLED_1
#define mLED_USB_Toggle()      mLED_1_Toggle()
#define mLED_2_Toggle()        mLED_2 = !mLED_2
#define mLED_Comms_Toggle()    mLED_2_Toggle()
#define mLED_3_Toggle()        mLED_3 = !mLED_3
#define mLED_Clock_Toggle()    mLED_3_Toggle()
#define mLED_4_Toggle()        mLED_4 = !mLED_4
#define mLED_Emulate_Toggle()  mLED_4_Toggle()
#define mLED_5_Toggle()        mLED_5 = !mLED_5
#define mLED_Read_Toggle(   )  mLED_5_Toggle()
#define mLED_6_Toggle()        mLED_6 = !mLED_6
#define mLED_User_Toggle()     mLED_6_Toggle()
#define mLED_7_Toggle()        mLED_7 = !mLED_7
#define mLED_Error_Toggle()    mLED_7_Toggle()

#define mLED_All_On()       { mLED_1_On(); mLED_2_On(); mLED_3_On(); mLED_4_On(); mLED_5_On();  mLED_6_On(); mLED_7_On(); }
#define mLED_All_Off()      { mLED_1_Off(); mLED_2_Off(); mLED_3_Off(); mLED_4_Off(); mLED_5_Off(); mLED_6_Off(); mLED_7_Off(); }

// usb status lights
#define mLED_Both_Off()         {mLED_USB_Off();mLED_Comms_Off();}
#define mLED_Both_On()          {mLED_USB_On();mLED_Comms_On();}
#define mLED_Only_USB_On()      {mLED_USB_On();mLED_Comms_Off();}
#define mLED_Only_Comms_On()    {mLED_USB_Off();mLED_Comms_On();}

/** SWITCH *********************************************************/
#define swBootloader        PORTEbits.RE7
#define swUser              PORTEbits.RE6

/** I/O pin definitions ********************************************/
#define INPUT_PIN                   1
#define OUTPUT_PIN                  0

#define TRUE                        1
#define FALSE                       0

#define ENABLE                      1
#define DISABE                      0

#define EVEN                        0
#define ODD                         1

#define LOW                         FALSE
#define HIGH                        TRUE

#define CLOCK_ON                    LOW
#define CLOCK_OFF                   HIGH

// output coil control - select between reader/emulator circuits
#define COIL_MODE                  LATBbits.LATB4
#define COIL_MODE_READER()         COIL_MODE= LOW
#define COIL_MODE_EMULATOR()       COIL_MODE= HIGH

// coil for emulation
#define COIL_OUT                   LATGbits.LATG9
#define COIL_OUT_HIGH()            COIL_OUT=HIGH
#define COIL_OUT_LOW()             COIL_OUT=LOW

// door relay (active low)
#define DOOR_RELAY                  LATAbits.LATA14
#define DOOR_RELAY_OPEN()           DOOR_RELAY= HIGH
#define DOOR_RELAY_CLOSE()          DOOR_RELAY= LOW

// inductance/capacitance freq
#define IC_FREQUENCY               PORTAbits.RA2

#define SNIFFER_COIL               PORTDbits.RD12    // external reader clock detect
#define READER_ANALOGUE            PORTBbits.RB11   // reader coil analogue
#define DIV_LOW_ANALOGUE           PORTBbits.RB12   // voltage divider LOW analogue
#define DIV_HIGH_ANALOGUE          PORTBbits.RB13   // voltage divider HIGH analogue

// clock coil (normally controlled by OC Module, but defined here so we can force it high or low)
#define CLOCK_COIL                 PORTDbits.RD4
#define CLOCK_COIL_MOVED           PORTDbits.RD0 // temporary for greenwire

// digital output after analogue reader circuit
#define READER_DATA                PORTDbits.RD8

// trace / debug
#define DEBUG_PIN_1                 LATCbits.LATC1
#define DEBUG_PIN_1_TOGGLE()        DEBUG_PIN_1= !DEBUG_PIN_1
#define DEBUG_PIN_2                 LATCbits.LATC2
#define DEBUG_PIN_2_TOGGLE()        DEBUG_PIN_2= !DEBUG_PIN_2
#define DEBUG_PIN_3                 LATCbits.LATC3
#define DEBUG_PIN_3_TOGGLE()        DEBUG_PIN_3= !DEBUG_PIN_3
#define DEBUG_PIN_4                 LATEbits.LATE5
#define DEBUG_PIN_4_TOGGLE()        DEBUG_PIN_4= !DEBUG_PIN_4

// spi (sdi1) for sd card (not directly referenced)
//#define SD_CARD_RX                  LATCbits.LATC4
//#define SD_CARD_TX                  LATDbits.LATD0
//#define SD_CARD_CLK                 LATDbits.LATD10
//#define SD_CARD_SS                  LATDbits.LATD9
// spi for SD card
#define SD_CARD_DET                 LATFbits.LATF0
#define SD_CARD_WE                  LATFbits.LATF1      // write enable - unused for microsd but allocated anyway as library checks it
// (held LOW by default - cut solder bridge to GND to free pin if required)
#define SPI_SD                      SPI_CHANNEL1
#define SPI_SD_BUFF                 SPI1BUF
#define SPI_SD_STAT                 SPI1STATbits
// see section below for more defines!

// iso 7816 smartcard
// microchip SC module defines pins so we don't need to, but
// they are listed here to help avoid conflicts
#define ISO_7816_RX                 LATBbits.LATF2 // RX
#define ISO_7816_TX                 LATBbits.LATF8 // TX
#define ISO_7816_VCC                LATBbits.LATB9 // Power
#define ISO_7816_CLK                LATCbits.LATD1 // Clock
#define ISO_7816_RST                LATEbits.LATE8 // Reset

// user LED
#define USER_LED                    LATDbits.LATD7
#define USER_LED_ON()               LATDbits.LATD7=1
#define USER_LED_OFF()              LATDbits.LATD7=0

// LCR
#define LCR_CALIBRATE               LATBbits.LATB5

// wiegand / clock & data
#define WIEGAND_IN_0                PORTDbits.RD5
#define WIEGAND_IN_0_PULLUP         CNPUEbits.CNPUE14
#define WIEGAND_IN_0_PULLDOWN       CNPDbits.CNPD14
#define WIEGAND_IN_1                PORTDbits.RD6
#define WIEGAND_IN_1_PULLUP         CNPUEbits.CNPUE15
#define WIEGAND_IN_1_PULLDOWN       CNPDbits.CNPD15
#define CAND_IN_DATA                WIEGAND_IN_0
#define CAND_IN_CLOCK               WIEGAND_IN_1

#define WIEGAND_OUT_0               LATDbits.LATD3
#define WIEGAND_OUT_1               LATDbits.LATD2
#define WIEGAND_OUT_0_TRIS          TRISDbits.TRISD3
#define WIEGAND_OUT_1_TRIS          TRISDbits.TRISD2
#define CAND_OUT_DATA               WIEGAND_OUT_0
#define CAND_OUT_CLOCK              WIEGAND_OUT_1

// connect/disconnect reader clock from coil - used to send RWD signals by creating gaps in carrier
#define READER_CLOCK_ENABLE         LATEbits.LATE9
#define READER_CLOCK_ENABLE_ON()    READER_CLOCK_ENABLE=CLOCK_ON
#define READER_CLOCK_ENABLE_OFF(x)  {READER_CLOCK_ENABLE=CLOCK_OFF; COIL_OUT=x;}

// these input pins must NEVER bet set to output or they will cause short circuits!
// they can be used to see data from reader before it goes into or gate
#define OR_IN_A                     PORTAbits.RA4
#define OR_IN_B                     PORTAbits.RA5


// CNCON and CNEN are set to allow wiegand input pin weak pullups to be switched on
#define Init_GPIO() { \
     CNCONbits.ON= TRUE; \
     CNENbits.CNEN14= TRUE; \
     CNENbits.CNEN15= TRUE; \
     TRISAbits.TRISA2= INPUT_PIN; \
     TRISAbits.TRISA4= INPUT_PIN; \
     TRISAbits.TRISA5= INPUT_PIN; \
     TRISAbits.TRISA14= OUTPUT_PIN; \
     TRISAbits.TRISA15= OUTPUT_PIN; \
     TRISBbits.TRISB4= OUTPUT_PIN; \
     TRISBbits.TRISB5= OUTPUT_PIN; \
     TRISBbits.TRISB9= OUTPUT_PIN; \
     TRISBbits.TRISB11= INPUT_PIN; \
     TRISBbits.TRISB12= INPUT_PIN; \
     TRISBbits.TRISB13= INPUT_PIN; \
     TRISCbits.TRISC1= OUTPUT_PIN; \
     TRISCbits.TRISC2= OUTPUT_PIN; \
     TRISCbits.TRISC3= OUTPUT_PIN; \
     TRISCbits.TRISC4= INPUT_PIN; \
     TRISDbits.TRISD0= INPUT_PIN; \
     TRISDbits.TRISD1= OUTPUT_PIN; \
     TRISDbits.TRISD2= OUTPUT_PIN; \
     TRISDbits.TRISD3= OUTPUT_PIN; \
     TRISDbits.TRISD4= OUTPUT_PIN; \
     TRISDbits.TRISD5= INPUT_PIN; \
     TRISDbits.TRISD6= INPUT_PIN; \
     TRISDbits.TRISD7= OUTPUT_PIN; \
     TRISDbits.TRISD8= INPUT_PIN; \
     TRISDbits.TRISD11= OUTPUT_PIN; \
     TRISDbits.TRISD12= INPUT_PIN; \
     TRISEbits.TRISE0= OUTPUT_PIN; \
     TRISEbits.TRISE1= OUTPUT_PIN; \
     TRISEbits.TRISE2= OUTPUT_PIN; \
     TRISEbits.TRISE3= OUTPUT_PIN; \
     TRISEbits.TRISE5= OUTPUT_PIN; \
     TRISEbits.TRISE6= INPUT_PIN; \
     TRISEbits.TRISE7= INPUT_PIN; \
     TRISEbits.TRISE8= OUTPUT_PIN; \
     TRISEbits.TRISE9= OUTPUT_PIN; \
     TRISFbits.TRISF0= INPUT_PIN; \
     TRISFbits.TRISF1= INPUT_PIN; \
     TRISFbits.TRISF2= INPUT_PIN; \
     TRISFbits.TRISF8= OUTPUT_PIN; \
     TRISGbits.TRISG6= OUTPUT_PIN; \
     TRISGbits.TRISG12= INPUT_PIN; \
     TRISGbits.TRISG13= INPUT_PIN; \
     TRISGbits.TRISG9= OUTPUT_PIN; \
     LATBbits.LATB9= LOW; \
     LATCbits.LATC1= LOW; \
     LATCbits.LATC2= LOW; \
     LATCbits.LATC3= LOW; \
     LATDbits.LATD2= WIEGAND_IN_1; \
     LATDbits.LATD3= WIEGAND_IN_0; \
     LATEbits.LATE5= LOW; \
     LATEbits.LATE9= HIGH; \
     }

// uart3 (CLI/API) speed
#define BAUDRATE3       115200UL
#define BRG_DIV3        4
#define BRGH3           1

// spi for potentiometer
#define SPI_POT                     SPI_CHANNEL4
#define SPI_POT_BUFF                SPI4BUF
#define SPI_POT_STAT                SPI4STATbits

// spi for sd card - defines required for Microchip SD-SPI libs
// define interface type
#define USE_SD_INTERFACE_WITH_SPI

#define MDD_USE_SPI_1
#define SPI_START_CFG_1     (PRI_PRESCAL_64_1 | SEC_PRESCAL_8_1 | MASTER_ENABLE_ON | SPI_CKE_ON | SPI_SMP_ON)
#define SPI_START_CFG_2     (SPI_ENABLE)
// Define the SPI frequency
#define SPI_FREQUENCY			(20000000)
// Description: SD-SPI Card Detect Input bit
#define SD_CD               PORTFbits.RF0
// Description: SD-SPI Card Detect TRIS bit
#define SD_CD_TRIS          TRISFbits.TRISF0
// Description: SD-SPI Write Protect Check Input bit
#define SD_WE               PORTFbits.RF1
// Description: SD-SPI Write Protect Check TRIS bit
#define SD_WE_TRIS          TRISFbits.TRISF1
// Description: The main SPI control register
#define SPICON1             SPI1CON
// Description: The SPI status register
#define SPISTAT             SPI1STAT
// Description: The SPI Buffer
#define SPIBUF              SPI1BUF
// Description: The receive buffer full bit in the SPI status register
#define SPISTAT_RBF         SPI1STATbits.SPIRBF
// Description: The bitwise define for the SPI control register (i.e. _____bits)
#define SPICON1bits         SPI1CONbits
// Description: The bitwise define for the SPI status register (i.e. _____bits)
#define SPISTATbits         SPI1STATbits
// Description: The enable bit for the SPI module
#define SPIENABLE           SPICON1bits.ON
// Description: The definition for the SPI baud rate generator register (PIC32)
#define SPIBRG              SPI1BRG
// Description: The TRIS bit for the SCK pin
#define SPICLOCK            TRISDbits.TRISD10
// Description: The TRIS bit for the SDI pin
#define SPIIN               TRISCbits.TRISC4
// Description: The TRIS bit for the SDO pin
#define SPIOUT              TRISDbits.TRISD0
#define SD_CS               LATDbits.LATD9
// Description: SD-SPI Chip Select TRIS bit
#define SD_CS_TRIS          TRISDbits.TRISD9
//SPI library functions
#define putcSPI             putcSPI1
#define getcSPI             getcSPI1
#define OpenSPI(config1, config2)   OpenSPI1(config1, config2)

// Define setup parameters for OpenADC10 function
// Turn module on | Ouput in integer format | Trigger mode auto | Enable autosample
#define ADC_CONFIG1     (ADC_FORMAT_INTG | ADC_CLK_AUTO | ADC_AUTO_SAMPLING_ON)
// ADC ref external | Disable offset test | Disable scan mode | Perform 2 samples | Use dual buffers | Use alternate mode
#define ADC_CONFIG2     (ADC_VREF_AVDD_AVSS | ADC_OFFSET_CAL_DISABLE | ADC_SCAN_OFF | ADC_SAMPLES_PER_INT_1 | ADC_ALT_BUF_ON | ADC_ALT_INPUT_ON)

// Use ADC internal clock | Set sample time
#define ADC_CONFIG3     (ADC_CONV_CLK_INTERNAL_RC | ADC_SAMPLE_TIME_0)

// slow sample rate for tuning coils
#define ADC_CONFIG2_SLOW     (ADC_VREF_AVDD_AVSS | ADC_OFFSET_CAL_DISABLE | ADC_SCAN_OFF | ADC_SAMPLES_PER_INT_16 | ADC_ALT_BUF_ON | ADC_ALT_INPUT_ON)
#define ADC_CONFIG3_SLOW     (ADC_CONV_CLK_INTERNAL_RC | ADC_SAMPLE_TIME_31)

// use AN11
#define ADC_CONFIGPORT  ENABLE_AN11_ANA
// Do not assign channels to scan
#define ADC_CONFIGSCAN  SKIP_SCAN_ALL

#define ADC_TO_VOLTS        0.003208F


// flash memory - int myvar = *(int*)(myflashmemoryaddress);

// memory is 0x9D005000 to 0x9D07FFFF

#define NVM_MEMORY_END 0x9D07FFFF
#define NVM_PAGE_SIZE	4096
#define NVM_PAGES       2       // config & VTAG
#define RFIDLER_NVM_ADDRESS (NVM_MEMORY_END - (NVM_PAGE_SIZE * NVM_PAGES))

// UART timeout in us
#define SERIAL_TIMEOUT                  100

#endif
