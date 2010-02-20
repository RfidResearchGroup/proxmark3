#!/usr/bin/perl

# endian-swap S records; we need this because the JTAG tools we're using
# expect the memory image in byte-swapped format
#
# Jonathan Westhues, April 2004

if(@ARGV == 0) {
	die "usage: $0 file-to-endian-swap.s19 > out.s19\n";
}

while(<>) {
	chomp;

	if(/^S0/) {
		next;
	}
	if(/^S7/) {
		print "$_\n";
		next;
	}

	if(not /^S3(..)(........)(.*)(..)$/) {
		die "bad S record at line $.\n";
	}

	$data = $3;
	$checksum = $4;

	print "S3$1$2";
	while($data =~ m#(..)(..)(..)(..)#g) {
		print "$4$3$2$1";
	}
	print "$checksum\n";
}
