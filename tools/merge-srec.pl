# merge the code that initially executes out of flash with the RAM image

($flashFile, $ramFile) = @ARGV;

open(FLASH, $flashFile) or die "$flashFile: $!\n";

while(<FLASH>) {
	print if /^S3/;
}

open(RAM, $ramFile) or die "$ramFile: $!\n";

while(<RAM>) {
	if(/^S3(..)(........)(.*)/) {
		$addr = sprintf('%08X', hex($2) - 0x00200000 + 0x200);
		print "S3$1$addr$3\n";
	}
}
