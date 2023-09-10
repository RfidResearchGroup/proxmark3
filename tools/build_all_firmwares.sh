#!/bin/bash
# (Need bash because of Bash Arrays)
#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

# These vars can be overridden by env variables
echo "Makefile flags: ${MKFLAGS:=-j8}"
echo "Destination:    ${DEST:=firmware}"
echo "Produce stats?: ${STATS:=false}"

# Which parts to skip for the 256kb version?
SKIPS256="SKIP_HITAG=1 SKIP_LEGICRF=1 SKIP_FELICA=1 SKIP_EM4x50=1 SKIP_ISO14443b=1 SKIP_NFCBARCODE=1 SKIP_ZX8211=1 SKIP_LF=1"

make $MKFLAGS bootrom || exit 1
chmod 644 bootrom/obj/bootrom.elf
mkdir -p "$DEST"
mv bootrom/obj/bootrom.elf "$DEST/PM3BOOTROM.elf"

# cf armsrc/Standalone/Makefile.hal
STANDALONE_MODES=(LF_SKELETON)
STANDALONE_MODES+=(LF_EM4100EMUL LF_EM4100RSWB LF_EM4100RSWW LF_EM4100RWC LF_HIDBRUTE LF_HIDFCBRUTE LF_ICEHID LF_MULTIHID LF_NEDAP_SIM LF_NEXID LF_PROXBRUTE LF_PROX2BRUTE LF_SAMYRUN LF_THAREXDE)
STANDALONE_MODES+=(HF_14ASNIFF HF_14BSNIFF HF_15SNIFF HF_AVEFUL HF_BOG HF_CARDHOPPER HF_COLIN HF_CRAFTBYTE HF_ICECLASS HF_LEGIC HF_LEGICSIM HF_MATTYRUN HF_MFCSIM HF_MSDSAL HF_REBLAY HF_TCPRST HF_TMUDFORD HF_YOUNG)
STANDALONE_MODES+=(DANKARMULTI)
STANDALONE_MODES_REQ_BT=(HF_CARDHOPPER HF_REBLAY)
STANDALONE_MODES_REQ_SMARTCARD=()
STANDALONE_MODES_REQ_FLASH=(LF_HIDFCBRUTE LF_ICEHID LF_NEXID LF_THAREXDE HF_BOG HF_COLIN HF_ICECLASS HF_LEGICSIM HF_MFCSIM)

# PM3GENERIC 256kb, no flash, need to skip some parts to reduce size

# Need to use the "recovery" target to test the size
make $MKFLAGS PLATFORM=PM3GENERIC PLATFORM_SIZE=256 PLATFORM_EXTRAS= STANDALONE= $SKIPS256 recovery || exit 1
chmod 644 armsrc/obj/fullimage.elf
mv armsrc/obj/fullimage.elf "$DEST/PM3GENERIC_256.elf"

# PM3GENERIC, no flash

make $MKFLAGS PLATFORM=PM3GENERIC PLATFORM_EXTRAS= STANDALONE= fullimage || exit 1
chmod 644 armsrc/obj/fullimage.elf
mv armsrc/obj/fullimage.elf "$DEST/PM3GENERIC.elf"
$STATS && ( echo "PM3GENERIC:" > standalones_stats.txt )
$STATS && ( echo "   text	   data	    bss	    dec	    hex	filename" >> standalones_stats.txt )
for mode in "${STANDALONE_MODES[@]}"; do
  [[ " ${STANDALONE_MODES_REQ_BT[*]} " =~ " $mode " ]] && continue
  [[ " ${STANDALONE_MODES_REQ_SMARTCARD[*]} " =~ " $mode " ]] && continue
  [[ " ${STANDALONE_MODES_REQ_FLASH[*]} " =~ " $mode " ]] && continue
  make $MKFLAGS PLATFORM=PM3GENERIC PLATFORM_EXTRAS= STANDALONE=$mode fullimage || exit 1
  chmod 644 armsrc/obj/fullimage.elf
  mv armsrc/obj/fullimage.elf "$DEST/PM3GENERIC_${mode/_/}.elf"
  ! $STATS || ( LANG=C arm-none-eabi-size armsrc/obj/[hl]f_*.o |grep -v "filename" >> standalones_stats.txt )
done

# PM3RDV4

make $MKFLAGS PLATFORM=PM3RDV4 PLATFORM_EXTRAS= STANDALONE= fullimage || exit 1
chmod 644 armsrc/obj/fullimage.elf
mv armsrc/obj/fullimage.elf "$DEST/PM3RDV4.elf"
$STATS && ( echo "PM3RDV4:" >> standalones_stats.txt )
$STATS && ( echo "   text	   data	    bss	    dec	    hex	filename" >> standalones_stats.txt )
for mode in "${STANDALONE_MODES[@]}"; do
  [[ " ${STANDALONE_MODES_REQ_BT[*]} " =~ " $mode " ]] && continue
  make $MKFLAGS PLATFORM=PM3RDV4 PLATFORM_EXTRAS= STANDALONE=$mode fullimage || exit 1
  chmod 644 armsrc/obj/fullimage.elf
  mv armsrc/obj/fullimage.elf "$DEST/PM3RDV4_${mode/_/}.elf"
  ! $STATS || ( LANG=C arm-none-eabi-size armsrc/obj/[hl]f_*.o |grep -v "filename" >> standalones_stats.txt )
done

# PM4RDV4 + BTADDON

make $MKFLAGS PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE= fullimage || exit 1
chmod 644 armsrc/obj/fullimage.elf
mv armsrc/obj/fullimage.elf "$DEST/PM3RDV4_BTADDON.elf"
$STATS && ( echo "PM3RDV4 + BTADDON:" >> standalones_stats.txt )
$STATS && ( echo "   text	   data	    bss	    dec	    hex	filename" >> standalones_stats.txt )
for mode in "${STANDALONE_MODES[@]}"; do
  make $MKFLAGS PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE=$mode fullimage || exit 1
  chmod 644 armsrc/obj/fullimage.elf
  mv armsrc/obj/fullimage.elf "$DEST/PM3RDV4_BTADDON_${mode/_/}.elf"
  ! $STATS || ( LANG=C arm-none-eabi-size armsrc/obj/[hl]f_*.o |grep -v "filename" >> standalones_stats.txt )
done
