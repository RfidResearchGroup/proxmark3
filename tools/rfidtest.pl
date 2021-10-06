#!/usr/bin/perl
# -samy kamkar, rfid@samy.pl

use strict;

die "usage: $0 <file with data> <binary to search for>\n" unless @ARGV == 2;

my ($file, $search) = @ARGV;
$search =~ s/\s//g;

# sure, these aren't perfect, but simplifies usability if you know what you're doing
# if in doubt, use binary

# binary, cool
if ($search =~ /^[01]+$/) { }
# decimal
elsif ($search =~ /^\d+$/)
{
    $search = unpack("B*", pack("N", $search));
    $search =~ s/^0*//;
}
# hex
elsif ($search =~ /^[\da-fA-F]+$/)
{
    $search = unpack("B*", pack("H*", $search));
    $search =~ s/^0*//;
}
# ascii
else
{
    $search = unpack("B*", $search);
    $search =~ s/^0*//;
}


# read file contents
open(F, "<$file") || die "Can't read $file: $!";
my $data = join("", <F>);
close(F);

# convert to binary
$data =~ s/\s//g;
# binary, great
if ($data =~ /^[01]+$/) { }
elsif ($data =~ /^[\da-fA-F]+$/)
{
    $data = unpack("B*", pack("H*", $data));
    $search =~ s/^0*//;
}
else
{
    die "Seriously. What sort of data is this file? Binary or hex only please.\n";
}


# search every method we know how
print "Testing normally...\n";
test_all($data, $search);

print "Testing with flipped bits...\n";
test_all($data, $search, 1);

# now try manchester demodulating
my @bits = split(//, $data);
my $man;
my $last = 0;
for (my $i = 1; $i < @bits; $i++)
{
    # if we changed, flip our bit
    if ($bits[$i-1] == 1)
    {
        $last ^= 1;
    }
    $man .= $last;
}

print "Testing with manchester demodulation...\n";
test_all($man, $search);

print "Testing with flipped manchester demodulation...\n";
test_all($man, $search, 1);


sub test_all
{
    my ($data, $search, $flip) = @_;

    if ($flip)
    {
        $data =~ s/(.)/$1 ^ 1/eg;
    }

    # first just see if our data is in the stream
    if ($data =~ /$search/)
    {
        print "Found $search in our stream ($data)\n";
    }

    # try removing parity every 4 and 8 bits
    foreach my $parity (4, 8)
    {
        # try removing a parity bit every $parity bits
        # test by cutting off a bit at a time in case we're in the wrong bit position
        my $tmp = $data;
        foreach (1 .. $parity)
        {
            my $test = $tmp;
            $test =~ s/(.{$parity})./$1/g;

            if ($test =~ /$search/)
            {
                print "Found $search with parity every " . ($parity + 1) . "th bit, round $_ out of $parity ($test)\n";
            }

            # chop of a bit to change our bit position next round
            $tmp =~ s/^.//;
        }
    }
}
