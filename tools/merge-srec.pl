# merge the code that initially executes out of flash with the RAM image

($flashFile, $ramFile) = @ARGV;

open(FLASH, $flashFile) or die "$flashFile: $!\n";

while(<FLASH>) {
	print if /^S3/;
	$EOF_record = $_ if /^S[789]/;
}

open(RAM, $ramFile) or die "$ramFile: $!\n";

while(<RAM>) {
	if(/^S3(..)(........)(.*)([0-9a-fA-F]{2})/) {
		$addr = sprintf('%08X', hex($2) - 0x00200000 + 0x200);
		$line = "$1$addr$3";
		$checksum = 0;
		$checksum += $_ foreach map(hex, unpack("a2"x40, $line));
		print "S3$line", sprintf("%02X", ($checksum%256)^0xff ), "\n";
	}
}
print $EOF_record;
