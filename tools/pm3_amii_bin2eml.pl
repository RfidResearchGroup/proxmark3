#!/usr/bin/perl
#
# Read Amiibo data, decrypt, and produce EML file
# Convert proxmark MFU (MIFARE Ultralight) .bin to .eml format
# for proxmark3 loading and simulation
#
# -samy kamkar 05/28/2017
#
# hf mf eload -f FILENAME_MINUS_EML
# hf 14a sim -t 7 -u UID

# perl -lne 'chomp; s/\s+(\S+)$//;$f=$1;if($f=~s/-(\S+)//){$g=hex($1);}else{$g=hex($f)}$f=hex($f); for$m($f..$g){print "0x" . substr(unpack("H4",pack("n",$m)),1) ." => \"$_\","}' /tmp/game  >> game2
# perl -lne 'if(/^(\S.*?)\s+\w?\w\w\w\w(\s*-\s*\w?\w\w\w\w)?\s*$/){$l=$1} s/(\w{4,5}\s*-\s*)?(\w{4,5})$//; $a=$1;$b=$2; $b=hex($b); $a=$a?hex($a):$b; for$m($a..$b){print "0x" . substr(unpack("H4",pack("n",$m)),0) ." => \"$l\","}' /tmp/g2

my $UIDLOC = -540; # UID is 540 bytes from the end
my $BLOCKSIZE = 4; # in bytes
my $AMIITOOL = '../client/deps/amiitool/amiitool'; # path to amiitool (unless in $PATH)
my $KEYFILE = '../client/resources/key_retail.bin'; # path to retail key file
my $ADDHDR = 1; # add 56 byte header?
my $FIXPWD = 1; # recalculate PWD if dump value is 0
my $FIXACK = 1; # set ACK if dump value is 0
my $DECRYPT = 0; # auto-decrypt

my %game = (
0x000 => "Mario",
0x001 => "Mario",
0x008 => "Yoshi's Woolly World",
0x010 => "The Legend of Zelda",
0x014 => "Breath of the Wild",
0x018 => "Animal Crossing",
0x019 => "Animal Crossing",
0x01a => "Animal Crossing",
0x01b => "Animal Crossing",
0x01c => "Animal Crossing",
0x01d => "Animal Crossing",
0x01e => "Animal Crossing",
0x01f => "Animal Crossing",
0x020 => "Animal Crossing",
0x021 => "Animal Crossing",
0x022 => "Animal Crossing",
0x023 => "Animal Crossing",
0x024 => "Animal Crossing",
0x025 => "Animal Crossing",
0x026 => "Animal Crossing",
0x027 => "Animal Crossing",
0x028 => "Animal Crossing",
0x029 => "Animal Crossing",
0x02a => "Animal Crossing",
0x02b => "Animal Crossing",
0x02c => "Animal Crossing",
0x02d => "Animal Crossing",
0x02e => "Animal Crossing",
0x02f => "Animal Crossing",
0x030 => "Animal Crossing",
0x031 => "Animal Crossing",
0x032 => "Animal Crossing",
0x033 => "Animal Crossing",
0x034 => "Animal Crossing",
0x035 => "Animal Crossing",
0x036 => "Animal Crossing",
0x037 => "Animal Crossing",
0x038 => "Animal Crossing",
0x039 => "Animal Crossing",
0x03a => "Animal Crossing",
0x03b => "Animal Crossing",
0x03c => "Animal Crossing",
0x03d => "Animal Crossing",
0x03e => "Animal Crossing",
0x03f => "Animal Crossing",
0x040 => "Animal Crossing",
0x041 => "Animal Crossing",
0x042 => "Animal Crossing",
0x043 => "Animal Crossing",
0x044 => "Animal Crossing",
0x045 => "Animal Crossing",
0x046 => "Animal Crossing",
0x047 => "Animal Crossing",
0x048 => "Animal Crossing",
0x049 => "Animal Crossing",
0x04a => "Animal Crossing",
0x04b => "Animal Crossing",
0x04c => "Animal Crossing",
0x04d => "Animal Crossing",
0x04e => "Animal Crossing",
0x04f => "Animal Crossing",
0x050 => "Animal Crossing",
0x051 => "Animal Crossing",
0x058 => "Star Fox",
0x05c => "Metroid",
0x060 => "F-Zero",
0x064 => "Pikmin",
0x06c => "Punch Out",
0x070 => "Wii Fit",
0x074 => "Kid Icarus",
0x078 => "Classic Nintendo",
0x07c => "Mii",
0x080 => "Splatoon",
0x09c => "Mario Sports Superstars",
0x09d => "Mario Sports Superstars",
0x190 => "Pokemon",
0x191 => "Pokemon",
0x192 => "Pokemon",
0x193 => "Pokemon",
0x194 => "Pokemon",
0x195 => "Pokemon",
0x196 => "Pokemon",
0x197 => "Pokemon",
0x198 => "Pokemon",
0x199 => "Pokemon",
0x19a => "Pokemon",
0x19b => "Pokemon",
0x19c => "Pokemon",
0x19d => "Pokemon",
0x19e => "Pokemon",
0x19f => "Pokemon",
0x1a0 => "Pokemon",
0x1a1 => "Pokemon",
0x1a2 => "Pokemon",
0x1a3 => "Pokemon",
0x1a4 => "Pokemon",
0x1a5 => "Pokemon",
0x1a6 => "Pokemon",
0x1a7 => "Pokemon",
0x1a8 => "Pokemon",
0x1a9 => "Pokemon",
0x1aa => "Pokemon",
0x1ab => "Pokemon",
0x1ac => "Pokemon",
0x1ad => "Pokemon",
0x1ae => "Pokemon",
0x1af => "Pokemon",
0x1b0 => "Pokemon",
0x1b1 => "Pokemon",
0x1b2 => "Pokemon",
0x1b3 => "Pokemon",
0x1b4 => "Pokemon",
0x1b5 => "Pokemon",
0x1b6 => "Pokemon",
0x1b7 => "Pokemon",
0x1b8 => "Pokemon",
0x1b9 => "Pokemon",
0x1ba => "Pokemon",
0x1bb => "Pokemon",
0x1bc => "Pokemon",
0x1bd => "Pokemon",
0x1d0 => "Pokken",
0x1f0 => "Kirby",
0x1f4 => "BoxBoy!",
0x210 => "Fire Emblem",
0x224 => "Xenoblade",
0x228 => "Earthbound",
0x22c => "Chibi Robo",
0x320 => "Sonic",
0x334 => "Pac-man",
0x348 => "Megaman",
0x34c => "Street fighter",
0x350 => "Monster Hunter",
0x35c => "Shovel Knight",
);

my %type = (
0x00 => "Figure",
0x01 => "Card",
0x02 => "Yarn",
);

my %amiibo = (
0x0000 => "Super Smash Bros.",
0x0001 => "Super Smash Bros.",
0x0002 => "Super Smash Bros.",
0x0003 => "Super Smash Bros.",
0x0004 => "Super Smash Bros.",
0x0005 => "Super Smash Bros.",
0x0006 => "Super Smash Bros.",
0x0007 => "Super Smash Bros.",
0x0008 => "Super Smash Bros.",
0x0009 => "Super Smash Bros.",
0x000a => "Super Smash Bros.",
0x000b => "Super Smash Bros.",
0x000c => "Super Smash Bros.",
0x000d => "Super Smash Bros.",
0x000e => "Super Smash Bros.",
0x000f => "Super Smash Bros.",
0x0010 => "Super Smash Bros.",
0x0011 => "Super Smash Bros.",
0x0012 => "Super Smash Bros.",
0x0013 => "Super Smash Bros.",
0x0014 => "Super Smash Bros.",
0x0015 => "Super Smash Bros.",
0x0016 => "Super Smash Bros.",
0x0017 => "Super Smash Bros.",
0x0018 => "Super Smash Bros.",
0x0019 => "Super Smash Bros.",
0x001a => "Super Smash Bros.",
0x001b => "Super Smash Bros.",
0x001c => "Super Smash Bros.",
0x001d => "Super Smash Bros.",
0x001e => "Super Smash Bros.",
0x001f => "Super Smash Bros.",
0x0020 => "Super Smash Bros.",
0x0021 => "Super Smash Bros.",
0x0022 => "Super Smash Bros.",
0x0023 => "Super Smash Bros.",
0x0024 => "Super Smash Bros.",
0x0025 => "Super Smash Bros.",
0x0026 => "Super Smash Bros.",
0x0027 => "Super Smash Bros.",
0x0028 => "Super Smash Bros.",
0x0029 => "Super Smash Bros.",
0x002a => "Super Smash Bros.",
0x002b => "Super Smash Bros.",
0x002c => "Super Smash Bros.",
0x002d => "Super Smash Bros.",
0x002e => "Super Smash Bros.",
0x002f => "Super Smash Bros.",
0x0030 => "Super Smash Bros.",
0x0031 => "Super Smash Bros.",
0x0032 => "Super Smash Bros.",
0x0033 => "Super Smash Bros.",
0x023d => "Super Smash Bros.",
0x0251 => "Super Smash Bros.",
0x0252 => "Super Smash Bros.",
0x0253 => "Super Smash Bros.",
0x0258 => "Super Smash Bros.",
0x0034 => "Super Mario",
0x0035 => "Super Mario",
0x0036 => "Super Mario",
0x0037 => "Super Mario",
0x0038 => "Super Mario",
0x0039 => "Super Mario",
0x0262 => "Super Mario",
0x0263 => "Super Mario",
0x0028 => "Super Mario",
0x003c => "Super Mario",
0x003d => "Super Mario",
0x003a => "Chibi Robo",
0x003e => "Splatoon",
0x003f => "Splatoon",
0x0040 => "Splatoon",
0x025d => "Splatoon",
0x025e => "Splatoon",
0x025f => "Splatoon",
0x0260 => "Splatoon",
0x0261 => "Splatoon",
0x0044 => "Animal Crossing Cards",
0x0045 => "Animal Crossing Cards",
0x0046 => "Animal Crossing Cards",
0x0047 => "Animal Crossing Cards",
0x0048 => "Animal Crossing Cards",
0x0049 => "Animal Crossing Cards",
0x004a => "Animal Crossing Cards",
0x004b => "Animal Crossing Cards",
0x004c => "Animal Crossing Cards",
0x004d => "Animal Crossing Cards",
0x004e => "Animal Crossing Cards",
0x004f => "Animal Crossing Cards",
0x0050 => "Animal Crossing Cards",
0x0051 => "Animal Crossing Cards",
0x0052 => "Animal Crossing Cards",
0x0053 => "Animal Crossing Cards",
0x0054 => "Animal Crossing Cards",
0x0055 => "Animal Crossing Cards",
0x0056 => "Animal Crossing Cards",
0x0057 => "Animal Crossing Cards",
0x0058 => "Animal Crossing Cards",
0x0059 => "Animal Crossing Cards",
0x005a => "Animal Crossing Cards",
0x005b => "Animal Crossing Cards",
0x005c => "Animal Crossing Cards",
0x005d => "Animal Crossing Cards",
0x005e => "Animal Crossing Cards",
0x005f => "Animal Crossing Cards",
0x0060 => "Animal Crossing Cards",
0x0061 => "Animal Crossing Cards",
0x0062 => "Animal Crossing Cards",
0x0063 => "Animal Crossing Cards",
0x0064 => "Animal Crossing Cards",
0x0065 => "Animal Crossing Cards",
0x0066 => "Animal Crossing Cards",
0x0067 => "Animal Crossing Cards",
0x0068 => "Animal Crossing Cards",
0x0069 => "Animal Crossing Cards",
0x006a => "Animal Crossing Cards",
0x006b => "Animal Crossing Cards",
0x006c => "Animal Crossing Cards",
0x006d => "Animal Crossing Cards",
0x006e => "Animal Crossing Cards",
0x006f => "Animal Crossing Cards",
0x0070 => "Animal Crossing Cards",
0x0071 => "Animal Crossing Cards",
0x0072 => "Animal Crossing Cards",
0x0073 => "Animal Crossing Cards",
0x0074 => "Animal Crossing Cards",
0x0075 => "Animal Crossing Cards",
0x0076 => "Animal Crossing Cards",
0x0077 => "Animal Crossing Cards",
0x0078 => "Animal Crossing Cards",
0x0079 => "Animal Crossing Cards",
0x007a => "Animal Crossing Cards",
0x007b => "Animal Crossing Cards",
0x007c => "Animal Crossing Cards",
0x007d => "Animal Crossing Cards",
0x007e => "Animal Crossing Cards",
0x007f => "Animal Crossing Cards",
0x0080 => "Animal Crossing Cards",
0x0081 => "Animal Crossing Cards",
0x0082 => "Animal Crossing Cards",
0x0083 => "Animal Crossing Cards",
0x0084 => "Animal Crossing Cards",
0x0085 => "Animal Crossing Cards",
0x0086 => "Animal Crossing Cards",
0x0087 => "Animal Crossing Cards",
0x0088 => "Animal Crossing Cards",
0x0089 => "Animal Crossing Cards",
0x008a => "Animal Crossing Cards",
0x008b => "Animal Crossing Cards",
0x008c => "Animal Crossing Cards",
0x008d => "Animal Crossing Cards",
0x008e => "Animal Crossing Cards",
0x008f => "Animal Crossing Cards",
0x0090 => "Animal Crossing Cards",
0x0091 => "Animal Crossing Cards",
0x0092 => "Animal Crossing Cards",
0x0093 => "Animal Crossing Cards",
0x0094 => "Animal Crossing Cards",
0x0095 => "Animal Crossing Cards",
0x0096 => "Animal Crossing Cards",
0x0097 => "Animal Crossing Cards",
0x0098 => "Animal Crossing Cards",
0x0099 => "Animal Crossing Cards",
0x009a => "Animal Crossing Cards",
0x009b => "Animal Crossing Cards",
0x009c => "Animal Crossing Cards",
0x009d => "Animal Crossing Cards",
0x009e => "Animal Crossing Cards",
0x009f => "Animal Crossing Cards",
0x00a0 => "Animal Crossing Cards",
0x00a1 => "Animal Crossing Cards",
0x00a2 => "Animal Crossing Cards",
0x00a3 => "Animal Crossing Cards",
0x00a4 => "Animal Crossing Cards",
0x00a5 => "Animal Crossing Cards",
0x00a6 => "Animal Crossing Cards",
0x00a7 => "Animal Crossing Cards",
0x00a8 => "Animal Crossing Cards",
0x00a9 => "Animal Crossing Cards",
0x00aa => "Animal Crossing Cards",
0x00ab => "Animal Crossing Cards",
0x00ac => "Animal Crossing Cards",
0x00ad => "Animal Crossing Cards",
0x00ae => "Animal Crossing Cards",
0x00af => "Animal Crossing Cards",
0x00b0 => "Animal Crossing Cards",
0x00b1 => "Animal Crossing Cards",
0x00b2 => "Animal Crossing Cards",
0x00b3 => "Animal Crossing Cards",
0x00b4 => "Animal Crossing Cards",
0x00b5 => "Animal Crossing Cards",
0x00b6 => "Animal Crossing Cards",
0x00b7 => "Animal Crossing Cards",
0x00b8 => "Animal Crossing Cards",
0x00b9 => "Animal Crossing Cards",
0x00ba => "Animal Crossing Cards",
0x00bb => "Animal Crossing Cards",
0x00bc => "Animal Crossing Cards",
0x00bd => "Animal Crossing Cards",
0x00be => "Animal Crossing Cards",
0x00bf => "Animal Crossing Cards",
0x00c0 => "Animal Crossing Cards",
0x00c1 => "Animal Crossing Cards",
0x00c2 => "Animal Crossing Cards",
0x00c3 => "Animal Crossing Cards",
0x00c4 => "Animal Crossing Cards",
0x00c5 => "Animal Crossing Cards",
0x00c6 => "Animal Crossing Cards",
0x00c7 => "Animal Crossing Cards",
0x00c8 => "Animal Crossing Cards",
0x00c9 => "Animal Crossing Cards",
0x00ca => "Animal Crossing Cards",
0x00cb => "Animal Crossing Cards",
0x00cc => "Animal Crossing Cards",
0x00cd => "Animal Crossing Cards",
0x00ce => "Animal Crossing Cards",
0x00cf => "Animal Crossing Cards",
0x00d0 => "Animal Crossing Cards",
0x00d1 => "Animal Crossing Cards",
0x00d2 => "Animal Crossing Cards",
0x00d3 => "Animal Crossing Cards",
0x00d4 => "Animal Crossing Cards",
0x00d5 => "Animal Crossing Cards",
0x00d6 => "Animal Crossing Cards",
0x00d7 => "Animal Crossing Cards",
0x00d8 => "Animal Crossing Cards",
0x00d9 => "Animal Crossing Cards",
0x00da => "Animal Crossing Cards",
0x00db => "Animal Crossing Cards",
0x00dc => "Animal Crossing Cards",
0x00dd => "Animal Crossing Cards",
0x00de => "Animal Crossing Cards",
0x00df => "Animal Crossing Cards",
0x00e0 => "Animal Crossing Cards",
0x00e1 => "Animal Crossing Cards",
0x00e2 => "Animal Crossing Cards",
0x00e3 => "Animal Crossing Cards",
0x00e4 => "Animal Crossing Cards",
0x00e5 => "Animal Crossing Cards",
0x00e6 => "Animal Crossing Cards",
0x00e7 => "Animal Crossing Cards",
0x00e8 => "Animal Crossing Cards",
0x00e9 => "Animal Crossing Cards",
0x00ea => "Animal Crossing Cards",
0x00eb => "Animal Crossing Cards",
0x00ec => "Animal Crossing Cards",
0x00ed => "Animal Crossing Cards",
0x00ee => "Animal Crossing Cards",
0x00ef => "Animal Crossing Cards",
0x00f0 => "Animal Crossing Cards",
0x00f1 => "Animal Crossing Cards",
0x00f2 => "Animal Crossing Cards",
0x00f3 => "Animal Crossing Cards",
0x00f4 => "Animal Crossing Cards",
0x00f5 => "Animal Crossing Cards",
0x00f6 => "Animal Crossing Cards",
0x00f7 => "Animal Crossing Cards",
0x00f8 => "Animal Crossing Cards",
0x00f9 => "Animal Crossing Cards",
0x00fa => "Animal Crossing Cards",
0x00fb => "Animal Crossing Cards",
0x00fc => "Animal Crossing Cards",
0x00fd => "Animal Crossing Cards",
0x00fe => "Animal Crossing Cards",
0x00ff => "Animal Crossing Cards",
0x0100 => "Animal Crossing Cards",
0x0101 => "Animal Crossing Cards",
0x0102 => "Animal Crossing Cards",
0x0103 => "Animal Crossing Cards",
0x0104 => "Animal Crossing Cards",
0x0105 => "Animal Crossing Cards",
0x0106 => "Animal Crossing Cards",
0x0107 => "Animal Crossing Cards",
0x0108 => "Animal Crossing Cards",
0x0109 => "Animal Crossing Cards",
0x010a => "Animal Crossing Cards",
0x010b => "Animal Crossing Cards",
0x01d4 => "Animal Crossing Cards",
0x01d5 => "Animal Crossing Cards",
0x01d6 => "Animal Crossing Cards",
0x01d7 => "Animal Crossing Cards",
0x01d8 => "Animal Crossing Cards",
0x0041 => "Yoshi's Woolly World",
0x0042 => "Yoshi's Woolly World",
0x0043 => "Yoshi's Woolly World",
0x023e => "Yoshi's Woolly World",
0x035d => "Yoshi's Woolly World",
0x0238 => "8 - Bit Mario",
0x0239 => "8 - Bit Mario",
0x023a => "Skylanders",
0x023b => "Skylanders",
0x023f => "Animal Crossing Figures",
0x0240 => "Animal Crossing Figures",
0x0241 => "Animal Crossing Figures",
0x0242 => "Animal Crossing Figures",
0x0243 => "Animal Crossing Figures",
0x0244 => "Animal Crossing Figures",
0x0245 => "Animal Crossing Figures",
0x0246 => "Animal Crossing Figures",
0x0247 => "Animal Crossing Figures",
0x0248 => "Animal Crossing Figures",
0x0249 => "Animal Crossing Figures",
0x024a => "Animal Crossing Figures",
0x024f => "The Legend of Zelda",
0x034b => "The Legend of Zelda",
0x034c => "The Legend of Zelda",
0x034d => "The Legend of Zelda",
0x034e => "The Legend of Zelda",
0x034f => "The Legend of Zelda",
0x0350 => "The Legend of Zelda",
0x0351 => "The Legend of Zelda",
0x0352 => "The Legend of Zelda",
0x0353 => "The Legend of Zelda",
0x0354 => "The Legend of Zelda",
0x0355 => "The Legend of Zelda",
0x0356 => "The Legend of Zelda",
0x0357 => "The Legend of Zelda",
0x0358 => "The Legend of Zelda",
0x0359 => "The Legend of Zelda",
0x035a => "The Legend of Zelda",
0x035b => "The Legend of Zelda",
0x035c => "The Legend of Zelda",
0x0250 => "Shovel Knight",
0x0254 => "Kirby",
0x0255 => "Kirby",
0x0256 => "Kirby",
0x0257 => "Kirby",
0x025c => "Pokken",
0x02e1 => "Monster Hunter Stories",
0x02e2 => "Monster Hunter Stories",
0x02e3 => "Monster Hunter Stories",
0x0319 => "Animal Crossing Sanrio",
0x031a => "Animal Crossing Sanrio",
0x031b => "Animal Crossing Sanrio",
0x031c => "Animal Crossing Sanrio",
0x031d => "Animal Crossing Sanrio",
0x031e => "Animal Crossing Sanrio",
0x035e => "BoxBoy!",
0x0360 => "Fire Emblem",
0x0361 => "Fire Emblem",
);

my %amiiboseries = (
0x00 => "Super Smash Bros.",
0x01 => "Super Mario",
0x02 => "Chibi-Robo",
0x03 => "Yoshi's Woolly World",
0x04 => "Splatoon",
0x05 => "Animal Crossing",
0x06 => "8 - Bit Mario",
0x07 => "Skylanders",
0x08 => "???",
0x09 => "The Legend Of Zelda",
0x0A => "Shovel Knight",
0x0B => "??? (Pikmin?)",
0x0C => "Kirby",
0x0D => "Pokken",
0x0E => "Mario Sports Superstars",
0x0F => "Monster Hunter",
0x10 => "BoxBoy!",
0x11 => "???",
0x12 => "Fire Emblem",
);

use strict;
my @err;
sub err { push @err, @_ }

die "usage: $0 <input .bin>\n" unless @ARGV == 1;
my $input = shift;

open(IN, "<$input") || die "Can't read $input$!";
my $file = join "", <IN>;
close(IN);

sub bytes { return substr($file, ((length($file) + $UIDLOC) + $_[0]), $_[1] || 1) }

# check for crypto
#my $dec_check = substr($file, ((length($file) + $UIDLOC) + 3    ), 1) eq "\xE0";
#my $enc_check = substr($file, ((length($file) + $UIDLOC) + 3 + 8), 1) eq "\xE0";
my $dec_check = bytes(3 + 0, 1) eq "\xE0";
my $enc_check = bytes(3 + 8, 1) eq "\xE0";

my $game = (       unpack("H3", bytes(84 + 0, 2)));
my $char = (substr(unpack("H2", bytes(84 + 1)), 1));
my $cvar = (       unpack("H2", bytes(84 + 2)));
my $type = (       unpack("H2", bytes(84 + 3)));
my $amii = (       unpack("H4", bytes(84 + 4, 2)));
my $amis = (       unpack("H2", bytes(84 + 6)));
my $last = (       unpack("H2", bytes(84 + 7)));
err "Character / info: " . join(" ", map { unpack("H2", $_) } split(//, bytes(84, 8)));
err "Game     :  $game $game{hex($game)}";
err "Character:    $char --";
err "Variation:   $cvar --";
err "Type     :   $type $type{hex($type)}";
err "Amiibo   : $amii $amiibo{hex($amii)}";
err "Series   :   $amis $amiiboseries{hex($amis)}";
err "Last     :   $last (should be 02)";
err "";

# looks like encrypted file
my $run;
if ($enc_check && !$dec_check)
{
  if ($DECRYPT)
  {
    $run = "'$AMIITOOL' -d -k '$KEYFILE' -i '$input'";
    err "Looks like encrypted file, decrypting";
    err "Running: $run";
    $file = `$run`;
  }
  else
  {
    err "Looks like encrypted file but setting preventing us from decrypting";
  }
}
elsif ($enc_check && $dec_check)
{
  $run = "'$AMIITOOL' -d -k '$KEYFILE' -i '$input'";
  err "Looks like encrypted AND decrypted file, will try decrypting first";
  err "Running: $run";
  my $tmp = `$run`;
  if (!$tmp)
  {
    err "Decryption failed, assuming file is already decrypted";
  }
  else
  {
    err "Decryption succeeded, loading decrypted contents";
    $file = $tmp;
  }
}
elsif ($dec_check && !$enc_check)
{
  err "Looks like decrypted file, great!";
}
elsif (!$dec_check && !$enc_check)
{
  die "Does not look like proper file format! Exiting.\n";
}

my @blocks = ();
my $uid = unpack("H14",
  substr($file, length($file) + $UIDLOC, 3) .
  substr($file, (length($file) + $UIDLOC) + 4, 4));
my $pwd = unpack("H8", substr($file, length($file) - 8, 4));
my $ack = unpack("H8", substr($file, length($file) - 4, 4));

my $fixedpwd = 0;
if ($FIXPWD && hex($pwd) == 0) {
  # calculate correct amiibo password according to UID
  err "PWD is blank, recalculating";
  my $uid_a = hex(substr $uid, 2, 8);
  my $uid_b = hex(substr $uid, 6, 8);
  $pwd = sprintf("%08x", $uid_a ^ $uid_b ^ 0xaa55aa55);

  $fixedpwd = 1;
}

my $fixedack = 0;
if ($FIXACK && hex($ack) == 0) {
  # this is the command to be sent back to the Switch if
  # the Switch sends the correct PWD
  err "ACK is blank, fixing";
  $ack = "80808080";

  $fixedack = 1;
}

# file does not contain our 56 byte header, let's add it
my $addedhdr = 0;
if ($ADDHDR && length($file) == -1 * $UIDLOC)
{
  err "Does not contain header, adding";
  while (<DATA>)
  {
    chomp; # there may not be a newline so chomp and add below
    push @blocks, $_;
  }

  $addedhdr = 1;
}

my $pages = 0;
while (length($file))
{
  my $out = substr($file, 0, $BLOCKSIZE, ""); # was 16
  $out = unpack("H*", $out);
  push @blocks, $out;

  $pages++;
}

if ($fixedpwd) {
  @blocks[-2] = $pwd;
}

if ($fixedack) {
  @blocks[-1] = $ack;
}

if ($addedhdr) {
  @blocks[2] .= sprintf "%02X", ($pages - 1);
}

# finally, output the data
foreach(@blocks) {
  print "$_\n";
}

print STDERR "\n";
print STDERR "$_\n" for @err;
print STDERR "UID: $uid\n";
print STDERR "PWD: $pwd\n";
print STDERR "ACK: $ack\n";
print STDERR "\n";
$uid = uc $uid;
#print STDERR "amiitool -d -k ../client/amiitool/key_retail.bin -i $input -o $input.decrypted\n";
$input =~ s/\....$//;
print STDERR "hf mfu eload -f $input\n";
print STDERR "hf 14a sim -t 7 -u $uid\n";


__DATA__
00040402
01001103
010000
92580B4C
45A9C42F
A90145CE
5E5F9C43
09A43D47
D232A3D1
68CBADE6
7F8185C6
00000000
00000000
00000000
