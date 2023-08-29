<a id="Top"></a>

# Notes on device side clocks
The device side firmware uses a range of different clocks.  Here is an attempt to document the clocks in use and for what they are used.


# Table of Contents
- [Notes on device side clocks](#notes-on-device-side-clocks)
- [Table of Contents](#table-of-contents)
  - [Units](#units)
  - [Slow clock](#slow-clock)
  - [Main Oscillator / MAINCK](#main-oscillator--mainck)
  - [PLL clock](#pll-clock)
  - [Master Clock MCK, Processor Clock PCK, USB clock UDPCK](#master-clock-mck-processor-clock-pck-usb-clock-udpck)
  - [Peripheral clocks](#peripheral-clocks)
  - [1 kHz RTC: TickCount functions](#1-khz-rtc-tickcount-functions)
  - [Occasional PWM timer](#occasional-pwm-timer)
  - [Occasional TC0+TC1 / CountUS functions](#occasional-tc0tc1--countus-functions)
  - [Occasional TC0+TC1+TC2 SSP\_CLK from FPGA / CountSspClk functions](#occasional-tc0tc1tc2-ssp_clk-from-fpga--countsspclk-functions)
  - [Occasional TC0+TC1 / Ticks functions](#occasional-tc0tc1--ticks-functions)


## Units
^[Top](#top)

Good calculator
https://www.unitjuggler.com/convert-frequency-from-MHz-to-ns(p).html?val=3.39

Basic units of time measurment or how long in time is a Hertz?

```
1 hertz   = 1 second                   =  1000 milli seconds
10 Hertz  = 1 / 10         = 0,1       =  100 milli seconds
100 Hertz = 1 / 100        = 0,01      =  10 milli seconds
1 kHz     = 1 / 1000       = 0,001     =  1 milli seconds 
10 kHz    = 1 / 10 000     = 0,000 1   =  100 micro seconds
100 kHz   = 1 / 100 000    = 0,000 01  =  10 micro seconds 
1 MHZ     = 1 / 1 000 000  = 0,000 001 =  1 micro seconds
```

- kHz, Kilo Hertz, 1000 Hertz
- MHz, Mega Hertz, 1000 000 Hertz


Basic units of time you will run into in the RFID world.

```
13.56 MHz = 1 / 13 560 000 = 73,74 nano seconds  = 0,07374 micro seconds
125 kHz   = 1/ 125 000     = 8 micro seconds
```

Given these units the following clocks used by Proxmark3 will make more sense.

Like the SSP Clock running at 3.39 MHz. 
3.39 MHz = 1 / 3 390 000 = 294,98 nano seconds   = 0,2949 micro seconds

1 tick at 3.39 MHz is 294.98 nano seconds.



## Slow clock
^[Top](#top)

~32kHz internal RC clock

Can be between 22 and 42 kHz

## Main Oscillator / MAINCK
^[Top](#top)

cf `PMC_MOR` register

16 MHz, based on external Xtal

## PLL clock
^[Top](#top)

cf `PMC_PLLR` register

96 MHz (MAINCK * 12 / 2)

## Master Clock MCK, Processor Clock PCK, USB clock UDPCK
^[Top](#top)

cf `common_arm/clocks.c`

cf `PMC_MCKR` and `PMC_SCER` registers

* MCK starts with RC slow clock (22 to 42 kHz).
* Then MCK configured from PLL: 48 MHz (PLL / 2)

cf `bootrom.c`:

PCK can be disabled to enter idle mode, but on Proxmark3 it's always on, so PCK is also 48 MHz.

USB need to be clocked at 48 MHz from the PLL, so PLL / 2 (cf `CKGR_PLLR`).


## Peripheral clocks
^[Top](#top)

cf `bootrom.c`:

Distribute MCK/PCK? clock to Parallel I/O controller, ADC, SPI, Synchronous Serial controller, PWM controller, USB.

cf `appmain.c`

Activate PCK0 pin as clock output, based on PLL / 4 = 24 MHz, for the FPGA.

## 1 kHz RTC: TickCount functions
^[Top](#top)

cf `armsrc/ticks.c`

cf `PMC_MCFR` and `RTTC_RTMR` registers for configuration, `RTTC_RTVR` register for reading value.

Characteristics:

* 1 kHz, 32b (49 days), if used with 16b: 65s
* Configured at boot (or TIA) with `StartTickCount()`
* Time events with `GetTickCount()`/`GetTickCountDeltaDelta()`, see example
* Coarse, based on the ~32kHz RC slow clock with some adjustment factor computed by TIA
* Maybe 2.5% error, can increase if temperature conditions change and no TIA is recomputed
* If TimingIntervalAcquisition() is called later, StartTickCount() is called again and RTC is reset

Usage:

```
uint32_t ti = GetTickCount();
...do stuff...
uint32_t delta = GetTickCountDelta(ti);
```

Current usages:

* cheap random for nonces, e.g. `prng_successor(GetTickCount(), 32)`
* rough timing of some operations, only for informative purposes
* timeouts
* USB connection speed measure

## Occasional PWM timer
^[Top](#top)

* `void SpinDelayUs(int us)`
* `void SpinDelay(int ms)` based on SpinDelayUs
* `void SpinDelayUsPrecision(int us)`

Busy wait based on 46.875 kHz PWM Channel 0

* 21.3 us precision and maximum 1.39 s
* *Precision* variant: 0.7 us precision and maximum 43 ms

## Occasional TC0+TC1 / CountUS functions
^[Top](#top)

cf `armsrc/ticks.c`

About 1 us precision

* `void StartCountUS(void)`
* `uint32_t RAMFUNC GetCountUS(void)`

Use two chained timers TC0 and TC1.
TC0 runs at 1.5 MHz and TC1 is clocked when TC0 reaches 0xC000.

Maximal value: 0x7fffffff = 2147 s

Can't be used at the same time as CountSspClk or Ticks functions.

## Occasional TC0+TC1+TC2 SSP_CLK from FPGA / CountSspClk functions
^[Top](#top)

cf `armsrc/ticks.c`

About 1 cycle of 13.56 MHz? precision

* `void StartCountSspClk(void)`
* `void ResetSspClk(void)`
* `uint32_t RAMFUNC GetCountSspClk(void)`
* `uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start)` <= **TODO** could be used more often

Use two chained timers TC0 and TC1.
TC0 runs at SSP_CLK from FPGA (13.56 MHz?) and TC1 is clocked when TC0 loops.

Usage:

* for iso14443 commands to count field cycles
* Also usable with FPGA in LF mode ?? cf `armsrc/legicrfsim.c` SSP Clock is clocked by the FPGA at 212 kHz (sub-carrier frequency)

Can't be used at the same time as CountUS or Ticks functions.

## Occasional TC0+TC1 / Ticks functions
^[Top](#top)

cf `armsrc/ticks.c`

1.5 MHz

* `void StartTicks(void)`
* `uint32_t GetTicks(void)` <= **TODO** why no GetTicksDelta ?
* `void WaitTicks(uint32_t ticks)`
* `void WaitUS(uint32_t us)`
* `void WaitMS(uint32_t ms)`
* `void StopTicks(void)` <= **TODO** why a stop for this timer and not for CountUS / CountSspClk ?

Use two chained timers TC0 and TC1.
TC0 runs at 1.5 MHz and TC1 is clocked when TC0 loops.

Maximal value: 0xffffffff = 2863 s (but don't use high value with WaitTicks else you'll trigger WDT)

Usage:

* Timer for bitbanging, or LF stuff when you need a very precise timer

Can't be used at the same time as CountUS or CountSspClk functions.
