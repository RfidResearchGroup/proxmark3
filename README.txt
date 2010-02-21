INTRO:

This file contains enough software, logic (for the FPGA), and design
documentation for the hardware that you could, at least in theory,
do something useful with a proxmark3. It has commands to:

    * read any kind of 125 kHz unidirectional tag
    * simulate any kind of 125 kHz unidirectional tag

(This is enough to perform all of the silly cloning attacks, like the
ones that I did at the Capitol in Sacramento, or anything involving
a Verichip. From a technical standpoint, these are not that exciting,
although the `software radio' architecture of the proxmark3 makes it
easy and fun to support new formats.)

As a bonus, I include some code to use the 13.56 MHz hardware, so you can:

    * do anything that a (medium-range) ISO 15693 reader could
    * read an ISO 14443 tag, if you know the higher-layer protocol
    * pretend to be an ISO 14443 tag, if you know the higher-layer protocol
    * snoop on an ISO 14443 transaction

I am not actively developing any of this. I have other projects that
seem to be more useful.

USING THE PACKAGE:

The software tools required to build include:

    * cygwin or other unix-like tools for Windows
    * devkitPro (http://wiki.devkitpro.org/index.php/Getting_Started/devkitARM)
    * Xilinx's WebPack tools
    * Modelsim (for test only)
    * perl

When installing devkitPro, you only need to install the compiler itself. Additional
support libraries are  not required.

Documentation is minimal, but see the doc/ directory for what exists. A
previous familiarity with the ARM, with digital signal processing,
and with embedded programming in general is assumed.

The device is used through a specialized command line interface; for
example, to clone a Verichip, you might type:

    loread                          ; this reads the tag, and stores the
                                    ; raw samples in memory on the ARM

    losamples                       ; then we download the samples to
                                    ; the PC

    vchdemod clone                  ; demodulate the ID, and then put it
                                    ; back in a format that we can replay

    losim                           ; and then replay it

To read an ISO 15693 tag, you might type:

    hiread                          ; read the tag; this involves sending a
                                    ; particular command, and then getting
                                    ; the response (which is stored as raw
                                    ; samples in memory on the ARM)

    hisamples                       ; then download those samples to the PC

    hi15demod                       ; and demod them to bits (and check the
                                    ; CRC etc. at the same time)

Notice that in both cases the signal processing mostly happened on the PC
side; that is of course not practical for a real reader, but it is easier
to initially write your code and debug on the PC side than on the ARM. As
long as you use integer math (and I do), it's trivial to port it over
when you're done.

The USB driver and bootloader are documented (and available separately
for download, if you wish to use them in another project) at

    http://cq.cx/trivia.pl


OBTAINING HARDWARE:

Most of the ultra-low-volume contract assemblers that have sprung up
(Screaming Circuits, the various cheap Asian suppliers, etc.) could put
something like this together with a reasonable yield. A run of around
a dozen units is probably cost-effective. The BOM includes (possibly-
outdated) component pricing, and everything is available from Digikey
and the usual distributors.

If you've never assembled a modern circuit board by hand, then this is
not a good place to start. Some of the components (e.g. the crystals)
must not be assembled with a soldering iron, and require hot air.

The schematics are included; the component values given are not
necessarily correct for all situations, but it should be possible to do
nearly anything you would want with appropriate population options.

The printed circuit board artwork is also available, as Gerbers and an
Excellon drill file.


FUTURE PLANS, ENHANCEMENTS THAT YOU COULD MAKE:

At some point I should write software involving a proper real-time
operating system for the ARM. I would then provide interrupt-driven
drivers for many of the peripherals that are polled now (the USB,
the data stream from the FPGA), which would make it easier to develop
complex applications.

It would not be all that hard to implement the ISO 15693 reader properly
(with anticollision, all the commands supported, and so on)--the signal
processing is already written, so it is all straightforward applications
work.

I have basic support for ISO 14443 as well: a sniffer, a simulated
tag, and a reader. It won't do anything useful unless you fill in the
high-layer protocol.

Nicer (i.e., closer-to-optimal) implementations of all kinds of signal
processing would be useful as well.

A practical implementation of the learning-the-tag's-ID-from-what-the-
reader-broadcasts-during-anticollision attacks would be relatively
straightforward. This would involve some signal processing on the FPGA,
but not much else after that.

It would be neat to write a driver that could stream samples from the A/Ds
over USB to the PC, using the full available bandwidth of USB. I am not
yet sure what that would be good for, but surely something. This would
require a kernel-mode driver under Windows, though, which is more work.


LICENSING:

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


Jonathan Westhues
user jwesthues, at host cq.cx

May 2007, Cambridge MA

