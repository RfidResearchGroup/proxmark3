#!/usr/bin/perl
#
# Convert proxmark3 trace or wav files to formats to be used by Inspectrum
#
# Converts proxmark3 trace to cs8 (Complex 8-bit signed integer samples, eg HackRF IQ format)
# and .wav to cs16 (Complex 16-bit signed integer samples, eg BladeRF IQ format)
#
# -samy kamkar, https://samy.pl

# we use `sox` to convert, set this to full path if preferred
my $SOX = "sox";

use strict;

die "usage: $0 [/path/to/sox (optional)] <pm3.trace or file.wav> [...more traces]\n" unless @ARGV;
$SOX = shift if $ARGV[0] =~ m/(?:[\/\\]|^)sox$/;
trace_conv($_) for @ARGV;

sub trace_conv
{
  my $file = shift;
  if ($file =~ /wav$/i)
  {
    my @run = ($SOX, qw/$file -t raw -e signed-integer -b 16 $file.cs16/);
    run_rewrite($file, @run);
    print "Wrote $file.cs16\n\n";
  }
  else
  {
    my $f = "/tmp/pm3.trace." . rand();
    open(F, ">$f") || die "Can't write to $f: $!";
    open(IN, "<$file") || die "Can't read $file: $!";
    while (<IN>)
    {
      chomp;
      print F pack "c", $_;
    }
    close(IN);
    close(F);

    # upsample 100x and pad 2nd channel with zeroes
    my @run = ($SOX, qw/-t s8 -r 1 -c 1 -v 0.5 $file -t s8 -r 100 -c 2 $file.cs8 remix 1 0/);
    run_rewrite($f, @run);

    # pad file since inspectrum doesn't handle small files so well
    open(OUT, ">$file.cs8") || die $!;
    open(IN, "<$f.cs8") || die $!;
    print OUT while <IN>;
    print OUT "\0" x (1024 * 1024);
    close(IN);
    close(OUT);

    unlink($f, "$f.cs8");
    print "Wrote $file.cs8\n\n";
  }
}

sub run_rewrite
{
  my ($file, @run) = @_;
  s/\$file/$file/ foreach @run;
  print "Running: @run\n";

  my $ret = system(@run);
  die "Failed: $! ($ret)\ndo you have $run[0] installed?\n" if $ret;
}
