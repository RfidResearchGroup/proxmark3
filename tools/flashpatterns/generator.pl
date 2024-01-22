#!/usr/bin/perl
# -----------------------------------------------------------------------------
#  Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  See LICENSE.txt for the text of the license.
# -----------------------------------------------------------------------------
# A loader script builder for testing MCU flash writing issues.
# -----------------------------------------------------------------------------

use strict;
use warnings;

my $bootloader_end = 0x00002000;
my $flash_end      = 0x00080000;
my $physical_addr  = 0x00100000;

# -----------------------------------------------------------------------------

my @parts = split /_/,$ARGV[0];
my $arg_begin = $parts[0] || "";
my $arg_end = $parts[1] || "";
my $arg_pattern = $parts[2] || "";

my $begin;
my $end;

if ($arg_begin =~ m/^[[:xdigit:]]{8}$/ and $arg_end =~ m/^[[:xdigit:]]{8}$/) {
    $begin = hex($arg_begin);
    $end = hex($arg_end);
}
else {
    die "unexpected range specification '$arg_begin'-'$arg_end'";
}

if ($begin < $bootloader_end) {
    die "do you really want to overwrite the bootloader?";
}
if ($end > $flash_end) {
    die "no writing beyond the end of the flash range";
}
if ($begin > $end) {
    die "end address before begin address";
}

my $sequence;
my $sequence_invert = 0;
my $fixedhex;

if ($arg_pattern =~ m/^ADDR(I)?$/) {
    $sequence = "ADDR";
    $sequence_invert = $1 eq "I";
} elsif ($arg_pattern =~ m/^([[:xdigit:]]{2})$/) {
    $fixedhex = $1 x 4;
} elsif ($arg_pattern =~ m/^([[:xdigit:]]{4})$/) {
    $fixedhex = $1 x 2;
} elsif ($arg_pattern =~ m/^([[:xdigit:]]{8})$/) {
    $fixedhex = $1;
} else {
    die "unexpected pattern '$arg_pattern'"
}

my $hex_phys_begin = sprintf("0x%08x", $begin + $physical_addr);
my $hex_size = sprintf("0x%08x", $end - $begin);

print <<EOT;
/*
-----------------------------------------------------------------------------
 Copyright (C) Martijn Plak, Jan 2024
 Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 See LICENSE.txt for the text of the license.
-----------------------------------------------------------------------------

This file was automatically generated.

-----------------------------------------------------------------------------
*/

INCLUDE ../../common_arm/ldscript.common

MEMORY
{
    custom : ORIGIN = $hex_phys_begin, LENGTH = $hex_size
}

PHDRS
{
    text PT_LOAD FLAGS(5);
}

ENTRY(_osimage_entry)

SECTIONS
{
    .text : {
EOT

if (defined $fixedhex) {

    my $swap = substr($fixedhex,6,2).substr($fixedhex,4,2).substr($fixedhex,2,2).substr($fixedhex,0,2);
    print("\t\tFILL(0x$fixedhex);\n");
    print("\t\t. = LENGTH(custom)-4;\n");
    print("\t\tLONG(0x$swap);\n");

} elsif ($sequence eq "ADDR") {

    for (my $i = $begin; $i < $end; $i += 4) {
        # invert every other long. also allow the whole file to be inverted.
        my $inv = (((($i & 4) != 0) xor $sequence_invert) ? 0xFFFFFFFF : 0);
        printf("\t\tLONG(0x%08x);\n", $i ^ $inv);
    }

}
else {
    die "output pattern not defined"
}

print <<EOT;
    } >custom :text
}
EOT
