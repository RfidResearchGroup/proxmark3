#!/usr/bin/perl

use strict;

die "usage: $0 <pm3.trace/file.wav>\n" unless @ARGV == 1;
# Convert proxmark3 trace to cs8 (complex int8/hackrf fmt) for inspectrum
# From miek

if ($ARGV[0] =~ /wav$/)
{
  system("sox $ARGV[0] -t raw -e signed-integer -b 16 $ARGV[0].cs16");
}
else
{
  #perl -ne 'chomp; print pack "c", $_' p.trace > p.c8
  my $f = "/tmp/pm3.trace." . rand();
  open(F, ">$f") || die $!;
  open(IN, "<$ARGV[0]");
  while (<IN>)
  {
    chomp;
    print F pack "c", $_;
  }
  close(IN);
  close(F);

# upsample 100x and pad 2nd channel with zeroes
  system("sox -t s8 -r 1 -c 1 -v 0.5 $f -t s8 -r 100 -c 2 $f.cs8 remix 1 0");

  open(OUT, ">$ARGV[0].cs8") || die $!;
  open(IN, "<$f.cs8") || die $!;
  print OUT while <IN>;
  print OUT "\0" x (1024 * 1024);
  close(IN);
  close(OUT);

  unlink($f, "$f.cs8");

# pad file since inspectrum doesn't handle small files so well
#system("dd if=/dev/zero of=$f.pad bs=1m count=1 >>/dev/null");

#system("cat $f.cs8 $f.pad > $ARGV[1]");
}