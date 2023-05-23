local amiibo_tools = {}

-- curl https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/amiibo.json | jq 'del(.amiibos[].release)' | jq 'del(.characters)' | pbcopy --> transform to table
amiibo_tools.db =
{
  amiibo_series = {
    ["0x00"] = "Super Smash Bros.",
    ["0x01"] = "Super Mario Bros.",
    ["0x02"] = "Chibi-Robo!",
    ["0x03"] = "Yoshi's Woolly World",
    ["0x04"] = "Splatoon",
    ["0x05"] = "Animal Crossing",
    ["0x06"] = "8-bit Mario",
    ["0x07"] = "Skylanders",
    ["0x09"] = "Legend Of Zelda",
    ["0x0a"] = "Shovel Knight",
    ["0x0c"] = "Kirby",
    ["0x0d"] = "Pokemon",
    ["0x0e"] = "Mario Sports Superstars",
    ["0x0f"] = "Monster Hunter",
    ["0x10"] = "BoxBoy!",
    ["0x11"] = "Pikmin",
    ["0x12"] = "Fire Emblem",
    ["0x13"] = "Metroid",
    ["0x14"] = "Others",
    ["0x15"] = "Mega Man",
    ["0x16"] = "Diablo",
    ["0x17"] = "Power Pros",
    ["0x18"] = "Monster Hunter Rise",
    ["0x19"] = "Yu-Gi-Oh!",
    ["0xff"] = "Super Nintendo World"
  },
  amiibos = {
    ["0x0000000000000002"] = {
      name = "Mario"
    },
    ["0x0000000000340102"] = {
      name = "Mario"
    },
    ["0x00000000003c0102"] = {
      name = "Mario - Gold Edition"
    },
    ["0x00000000003d0102"] = {
      name = "Mario - Silver Edition"
    },
    ["0x0000000002380602"] = {
      name = "8-Bit Mario Classic Color"
    },
    ["0x0000000002390602"] = {
      name = "8-Bit Mario Modern Color"
    },
    ["0x0000000003710102"] = {
      name = "Mario - Wedding"
    },
    ["0x00000003039bff02"] = {
      name = "Mario - Power Up Band"
    },
    ["0x000000030430ff02"] = {
      name = "Golden - Power Up Band"
    },
    ["0x0000010000190002"] = {
      name = "Dr. Mario"
    },
    ["0x0000030003a60102"] = {
      name = "Mario - Cat"
    },
    ["0x00010000000c0002"] = {
      name = "Luigi"
    },
    ["0x0001000000350102"] = {
      name = "Luigi"
    },
    ["0x00010003039cff02"] = {
      name = "Luigi - Power Up Band"
    },
    ["0x0002000000010002"] = {
      name = "Peach"
    },
    ["0x0002000000360102"] = {
      name = "Peach"
    },
    ["0x0002000003720102"] = {
      name = "Peach - Wedding"
    },
    ["0x00020003039dff02"] = {
      name = "Peach - Power Up Band"
    },
    ["0x0002010003a70102"] = {
      name = "Peach - Cat"
    },
    ["0x0003000000020002"] = {
      name = "Yoshi"
    },
    ["0x0003000000370102"] = {
      name = "Yoshi"
    },
    ["0x00030003039fff02"] = {
      name = "Yoshi - Power Up Band"
    },
    ["0x0003010200410302"] = {
      name = "Green Yarn Yoshi"
    },
    ["0x0003010200420302"] = {
      name = "Pink Yarn Yoshi"
    },
    ["0x0003010200430302"] = {
      name = "Light Blue Yarn Yoshi"
    },
    ["0x00030102023e0302"] = {
      name = "Mega Yarn Yoshi"
    },
    ["0x0004000002620102"] = {
      name = "Rosalina"
    },
    ["0x0004010000130002"] = {
      name = "Rosalina & Luma"
    },
    ["0x0005000000140002"] = {
      name = "Bowser"
    },
    ["0x0005000000390102"] = {
      name = "Bowser"
    },
    ["0x0005000003730102"] = {
      name = "Bowser - Wedding"
    },
    ["0x0005ff00023a0702"] = {
      name = "Hammer Slam Bowser"
    },
    ["0x0006000000150002"] = {
      name = "Bowser Jr."
    },
    ["0x00070000001a0002"] = {
      name = "Wario"
    },
    ["0x0007000002630102"] = {
      name = "Wario"
    },
    ["0x0008000000030002"] = {
      name = "Donkey Kong"
    },
    ["0x0008000002640102"] = {
      name = "Donkey Kong"
    },
    ["0x0008ff00023b0702"] = {
      name = "Turbo Charge Donkey Kong"
    },
    ["0x00090000000d0002"] = {
      name = "Diddy Kong"
    },
    ["0x0009000002650102"] = {
      name = "Diddy Kong"
    },
    ["0x000a000000380102"] = {
      name = "Toad"
    },
    ["0x000a000303a0ff02"] = {
      name = "Toad - Power Up Band"
    },
    ["0x0013000002660102"] = {
      name = "Daisy"
    },
    ["0x00130000037a0002"] = {
      name = "Daisy"
    },
    ["0x00130003039eff02"] = {
      name = "Daisy - Power Up Band"
    },
    ["0x0014000002670102"] = {
      name = "Waluigi"
    },
    ["0x0015000003670102"] = {
      name = "Goomba"
    },
    ["0x0017000002680102"] = {
      name = "Boo"
    },
    ["0x0023000003680102"] = {
      name = "Koopa Troopa"
    },
    ["0x00240000038d0002"] = {
      name = "Piranha Plant"
    },
    ["0x00800102035d0302"] = {
      name = "Poochy"
    },
    ["0x00c00000037b0002"] = {
      name = "King K. Rool"
    },
    ["0x0100000000040002"] = {
      name = "Link"
    },
    ["0x01000000034b0902"] = {
      name = "Link - Ocarina of Time"
    },
    ["0x01000000034c0902"] = {
      name = "Link - Majora's Mask"
    },
    ["0x01000000034d0902"] = {
      name = "Link - Twilight Princess"
    },
    ["0x01000000034e0902"] = {
      name = "Link - Skyward Sword"
    },
    ["0x01000000034f0902"] = {
      name = "8-Bit Link"
    },
    ["0x0100000003530902"] = {
      name = "Link - Archer"
    },
    ["0x0100000003540902"] = {
      name = "Link - Rider"
    },
    ["0x01000000037c0002"] = {
      name = "Young Link"
    },
    ["0x0100000003990902"] = {
      name = "Link - Link's Awakening"
    },
    ["0x0100000004180902"] = {
      name = "Link - Tears of the Kingdom"
    },
    ["0x0100010000160002"] = {
      name = "Toon Link"
    },
    ["0x0100010003500902"] = {
      name = "Toon Link - The Wind Waker"
    },
    ["0x01010000000e0002"] = {
      name = "Zelda"
    },
    ["0x0101000003520902"] = {
      name = "Toon Zelda - The Wind Waker"
    },
    ["0x0101000003560902"] = {
      name = "Zelda"
    },
    ["0x0101010000170002"] = {
      name = "Sheik"
    },
    ["0x0101030004140902"] = {
      name = "Zelda & Loftwing"
    },
    ["0x01020100001b0002"] = {
      name = "Ganondorf"
    },
    ["0x01030000024f0902"] = {
      name = "Midna & Wolf Link"
    },
    ["0x0105000003580902"] = {
      name = "Daruk"
    },
    ["0x0106000003590902"] = {
      name = "Urbosa"
    },
    ["0x01070000035a0902"] = {
      name = "Mipha"
    },
    ["0x01080000035b0902"] = {
      name = "Revali"
    },
    ["0x0140000003550902"] = {
      name = "Guardian"
    },
    ["0x01410000035c0902"] = {
      name = "Bokoblin"
    },
    ["0x0180000000080002"] = {
      name = "Villager"
    },
    ["0x01810000024b0502"] = {
      name = "Isabelle - Summer Outfit"
    },
    ["0x01810000037d0002"] = {
      name = "Isabelle"
    },
    ["0x0181000100440502"] = {
      name = "Isabelle"
    },
    ["0x0181000101d40502"] = {
      name = "Isabelle - Character Parfait"
    },
    ["0x01810100023f0502"] = {
      name = "Isabelle - Winter Outfit"
    },
    ["0x0181010100b40502"] = {
      name = "Isabelle - Winter"
    },
    ["0x01810201011a0502"] = {
      name = "Isabelle - Kimono"
    },
    ["0x0181030101700502"] = {
      name = "Isabelle - Dress"
    },
    ["0x0181040103aa0502"] = {
      name = "Isabelle"
    },
    ["0x0181050103bf0502"] = {
      name = "Isabelle - Sweater"
    },
    ["0x0182000002400502"] = {
      name = "K. K. Slider"
    },
    ["0x0182000100a80502"] = {
      name = "K.K. Slider"
    },
    ["0x0182000101d80502"] = {
      name = "K. K. Slider - Pikopuri"
    },
    ["0x0182000103b20502"] = {
      name = "K.K. Slider"
    },
    ["0x0182010100460502"] = {
      name = "DJ KK"
    },
    ["0x0183000002420502"] = {
      name = "Tom Nook"
    },
    ["0x0183000100450502"] = {
      name = "Tom Nook"
    },
    ["0x01830101010e0502"] = {
      name = "Tom Nook - Jacket"
    },
    ["0x0183020103a80502"] = {
      name = "Tom Nook"
    },
    ["0x0183030103be0502"] = {
      name = "Tom Nook - Coat"
    },
    ["0x01840000024d0502"] = {
      name = "Timmy & Tommy"
    },
    ["0x0184050103a90502"] = {
      name = "Timmy & Tommy"
    },
    ["0x01850001004b0502"] = {
      name = "Timmy"
    },
    ["0x0185020101170502"] = {
      name = "Timmy - Full Apron"
    },
    ["0x0185040101790502"] = {
      name = "Timmy - Suit"
    },
    ["0x0186010100af0502"] = {
      name = "Tommy - Uniform"
    },
    ["0x0186030101750502"] = {
      name = "Tommy - Suit"
    },
    ["0x0187000100470502"] = {
      name = "Sable"
    },
    ["0x0187000103b00502"] = {
      name = "Sable"
    },
    ["0x0188000002410502"] = {
      name = "Mabel"
    },
    ["0x0188000101120502"] = {
      name = "Mabel"
    },
    ["0x0188000103af0502"] = {
      name = "Mabel"
    },
    ["0x0189000100ab0502"] = {
      name = "Label"
    },
    ["0x0189010103b10502"] = {
      name = "Label"
    },
    ["0x018a000002450502"] = {
      name = "Reese"
    },
    ["0x018a000100a90502"] = {
      name = "Reese"
    },
    ["0x018b000002460502"] = {
      name = "Cyrus"
    },
    ["0x018b000101150502"] = {
      name = "Cyrus"
    },
    ["0x018c000002430502"] = {
      name = "Digby"
    },
    ["0x018c0001004c0502"] = {
      name = "Digby"
    },
    ["0x018c010101180502"] = {
      name = "Digby - Raincoat"
    },
    ["0x018d0000024c0502"] = {
      name = "Rover"
    },
    ["0x018d0001010c0502"] = {
      name = "Rover"
    },
    ["0x018e000002490502"] = {
      name = "Resetti"
    },
    ["0x018e000100490502"] = {
      name = "Resetti"
    },
    ["0x018e010101780502"] = {
      name = "Resetti - Without Hat"
    },
    ["0x018f000100b30502"] = {
      name = "Don Resetti"
    },
    ["0x018f010101190502"] = {
      name = "Don Resetti - Without Hat"
    },
    ["0x0190000101710502"] = {
      name = "Brewster"
    },
    ["0x01910001004e0502"] = {
      name = "Harriet"
    },
    ["0x0192000002470502"] = {
      name = "Blathers"
    },
    ["0x01920001010d0502"] = {
      name = "Blathers"
    },
    ["0x0192000103ad0502"] = {
      name = "Blathers"
    },
    ["0x0193000002480502"] = {
      name = "Celeste"
    },
    ["0x0193000101740502"] = {
      name = "Celeste"
    },
    ["0x0193000103ae0502"] = {
      name = "Celeste"
    },
    ["0x01940000024a0502"] = {
      name = "Kicks"
    },
    ["0x0194000100aa0502"] = {
      name = "Kicks"
    },
    ["0x0194000103b60502"] = {
      name = "Kicks"
    },
    ["0x0195000100b00502"] = {
      name = "Porter"
    },
    ["0x01960000024e0502"] = {
      name = "Kapp'n"
    },
    ["0x0196000100480502"] = {
      name = "Kapp'n"
    },
    ["0x0197000101770502"] = {
      name = "Leilani"
    },
    ["0x0198000100b10502"] = {
      name = "Leila"
    },
    ["0x0199000101160502"] = {
      name = "Grams"
    },
    ["0x019a000100b70502"] = {
      name = "Chip"
    },
    ["0x019b000100b60502"] = {
      name = "Nat"
    },
    ["0x019c000101730502"] = {
      name = "Phineas"
    },
    ["0x019d000100ac0502"] = {
      name = "Copper"
    },
    ["0x019e000100ad0502"] = {
      name = "Booker"
    },
    ["0x019f000101110502"] = {
      name = "Pete"
    },
    ["0x01a00001010f0502"] = {
      name = "Pelly"
    },
    ["0x01a1000101100502"] = {
      name = "Phyllis"
    },
    ["0x01a20001017d0502"] = {
      name = "Gulliver"
    },
    ["0x01a2000103b90502"] = {
      name = "Gulliver"
    },
    ["0x01a30001004a0502"] = {
      name = "Joan"
    },
    ["0x01a40001004d0502"] = {
      name = "Pascal"
    },
    ["0x01a5000101720502"] = {
      name = "Katrina"
    },
    ["0x01a6000100500502"] = {
      name = "Saharah"
    },
    ["0x01a6000103b70502"] = {
      name = "Saharah"
    },
    ["0x01a7000101140502"] = {
      name = "Wendell"
    },
    ["0x01a80001004f0502"] = {
      name = "Redd"
    },
    ["0x01a80101017e0502"] = {
      name = "Redd - Shirt"
    },
    ["0x01a9000101760502"] = {
      name = "Gracie"
    },
    ["0x01aa000100530502"] = {
      name = "Lyle"
    },
    ["0x01ab0001017c0502"] = {
      name = "Pave"
    },
    ["0x01ac0001017f0502"] = {
      name = "Zipper"
    },
    ["0x01ad000100b80502"] = {
      name = "Jack"
    },
    ["0x01ae0001011b0502"] = {
      name = "Franklin"
    },
    ["0x01af0001011c0502"] = {
      name = "Jingle"
    },
    ["0x01b0000100520502"] = {
      name = "Tortimer"
    },
    ["0x01b1000100b20502"] = {
      name = "Shrunk"
    },
    ["0x01b10101017b0502"] = {
      name = "Shrunk - Loud Jacket"
    },
    ["0x01b3000100b50502"] = {
      name = "Blanca"
    },
    ["0x01b4000101130502"] = {
      name = "Leif"
    },
    ["0x01b5000100510502"] = {
      name = "Luna"
    },
    ["0x01b6000100ae0502"] = {
      name = "Katie"
    },
    ["0x01c1000002440502"] = {
      name = "Lottie"
    },
    ["0x01c1000100540502"] = {
      name = "Lottie"
    },
    ["0x01c10101017a0502"] = {
      name = "Lottie - Black Skirt And Bow"
    },
    ["0x01c1020103bb0502"] = {
      name = "Lottie - Island"
    },
    ["0x0200000100a10502"] = {
      name = "Cyrano"
    },
    ["0x02010001016a0502"] = {
      name = "Antonio"
    },
    ["0x0202000101030502"] = {
      name = "Pango"
    },
    ["0x02030001019a0502"] = {
      name = "Anabelle"
    },
    ["0x0206000103120502"] = {
      name = "Snooty"
    },
    ["0x0208000100960502"] = {
      name = "Annalisa"
    },
    ["0x02090001019f0502"] = {
      name = "Olaf"
    },
    ["0x0214000100e40502"] = {
      name = "Teddy"
    },
    ["0x0215000101820502"] = {
      name = "Pinky"
    },
    ["0x0216000100570502"] = {
      name = "Curt"
    },
    ["0x0217000101b30502"] = {
      name = "Chow"
    },
    ["0x02190001007e0502"] = {
      name = "Nate"
    },
    ["0x021a000100da0502"] = {
      name = "Groucho"
    },
    ["0x021b000100800502"] = {
      name = "Tutu"
    },
    ["0x021c000102f70502"] = {
      name = "Ursala"
    },
    ["0x021d000101cd0502"] = {
      name = "Grizzly"
    },
    ["0x021e000101230502"] = {
      name = "Paula"
    },
    ["0x021f000103170502"] = {
      name = "Ike"
    },
    ["0x0220000100fd0502"] = {
      name = "Charlise"
    },
    ["0x02210001013c0502"] = {
      name = "Beardo"
    },
    ["0x0222000101440502"] = {
      name = "Klaus"
    },
    ["0x022d000100f20502"] = {
      name = "Jay"
    },
    ["0x022e000101d30502"] = {
      name = "Robin"
    },
    ["0x022f0001011e0502"] = {
      name = "Anchovy"
    },
    ["0x0230000101d20502"] = {
      name = "Twiggy"
    },
    ["0x02310001006a0502"] = {
      name = "Jitters"
    },
    ["0x0232000102ea0502"] = {
      name = "Piper"
    },
    ["0x0233000103060502"] = {
      name = "Admiral"
    },
    ["0x0235000100840502"] = {
      name = "Midge"
    },
    ["0x0238000102f80502"] = {
      name = "Jacob"
    },
    ["0x023c000100bd0502"] = {
      name = "Lucha"
    },
    ["0x023d000101b50502"] = {
      name = "Jacques"
    },
    ["0x023e000100d10502"] = {
      name = "Peck"
    },
    ["0x023f000101660502"] = {
      name = "Sparro"
    },
    ["0x024a000101d10502"] = {
      name = "Angus"
    },
    ["0x024b000101260502"] = {
      name = "Rodeo"
    },
    ["0x024d000102f60502"] = {
      name = "Stu"
    },
    ["0x024f000100810502"] = {
      name = "T-Bone"
    },
    ["0x0251000100c10502"] = {
      name = "Coach"
    },
    ["0x0252000100fe0502"] = {
      name = "Vic"
    },
    ["0x025d000100550502"] = {
      name = "Bob"
    },
    ["0x025e000101250502"] = {
      name = "Mitzi"
    },
    ["0x025f000101c50502"] = {
      name = "Rosie"
    },
    ["0x025f000101d70502"] = {
      name = "Rosie - Amiibo Festival"
    },
    ["0x0260000100d20502"] = {
      name = "Olivia"
    },
    ["0x0261000100650502"] = {
      name = "Kiki"
    },
    ["0x0262000101370502"] = {
      name = "Tangy"
    },
    ["0x0263000100750502"] = {
      name = "Punchy"
    },
    ["0x0264000101ac0502"] = {
      name = "Purrl"
    },
    ["0x0265000101540502"] = {
      name = "Moe"
    },
    ["0x0266000100680502"] = {
      name = "Kabuki"
    },
    ["0x0267000101080502"] = {
      name = "Kid Cat"
    },
    ["0x02680001007d0502"] = {
      name = "Monique"
    },
    ["0x02690001011f0502"] = {
      name = "Tabby"
    },
    ["0x026a000101460502"] = {
      name = "Stinky"
    },
    ["0x026b000100e90502"] = {
      name = "Kitty"
    },
    ["0x026c000100c30502"] = {
      name = "Tom"
    },
    ["0x026d0001013f0502"] = {
      name = "Merry"
    },
    ["0x026e000100ba0502"] = {
      name = "Felicity"
    },
    ["0x026f000101900502"] = {
      name = "Lolly"
    },
    ["0x0270000100ff0502"] = {
      name = "Ankha"
    },
    ["0x02710001019b0502"] = {
      name = "Rudy"
    },
    ["0x0272000101860502"] = {
      name = "Katt"
    },
    ["0x027d000100630502"] = {
      name = "Bluebear"
    },
    ["0x027e000101690502"] = {
      name = "Maple"
    },
    ["0x027f000100b90502"] = {
      name = "Poncho"
    },
    ["0x0280000100830502"] = {
      name = "Pudge"
    },
    ["0x0281000101200502"] = {
      name = "Kody"
    },
    ["0x0282000101810502"] = {
      name = "Stitches"
    },
    ["0x0282000101d60502"] = {
      name = "Stitches - Amiibo Festival"
    },
    ["0x0283000100c70502"] = {
      name = "Vladimir"
    },
    ["0x0284000102fe0502"] = {
      name = "Murphy"
    },
    ["0x0286000103130502"] = {
      name = "Olive"
    },
    ["0x02870001005a0502"] = {
      name = "Cheri"
    },
    ["0x028a000102e90502"] = {
      name = "June"
    },
    ["0x028b000100e30502"] = {
      name = "Pekoe"
    },
    ["0x028c0001013e0502"] = {
      name = "Chester"
    },
    ["0x028d000101bd0502"] = {
      name = "Barold"
    },
    ["0x028e0001019e0502"] = {
      name = "Tammy"
    },
    ["0x028f0101031a0502"] = {
      name = "Marty"
    },
    ["0x0299000100950502"] = {
      name = "Goose"
    },
    ["0x029a000100ee0502"] = {
      name = "Benedict"
    },
    ["0x029b000100cb0502"] = {
      name = "Egbert"
    },
    ["0x029e0001013d0502"] = {
      name = "Ava"
    },
    ["0x02a2000101ba0502"] = {
      name = "Becky"
    },
    ["0x02a3000102ff0502"] = {
      name = "Plucky"
    },
    ["0x02a4000100720502"] = {
      name = "Knox"
    },
    ["0x02a50001018c0502"] = {
      name = "Broffina"
    },
    ["0x02a6000101240502"] = {
      name = "Ken"
    },
    ["0x02b1000100690502"] = {
      name = "Patty"
    },
    ["0x02b2000100c40502"] = {
      name = "Tipper"
    },
    ["0x02b70001030f0502"] = {
      name = "Norma"
    },
    ["0x02b80001019c0502"] = {
      name = "Naomi"
    },
    ["0x02c3000100dc0502"] = {
      name = "Alfonso"
    },
    ["0x02c4000100670502"] = {
      name = "Alli"
    },
    ["0x02c5000103080502"] = {
      name = "Boots"
    },
    ["0x02c7000101220502"] = {
      name = "Del"
    },
    ["0x02c9000100cd0502"] = {
      name = "Sly"
    },
    ["0x02ca000101ca0502"] = {
      name = "Gayle"
    },
    ["0x02cb000101360502"] = {
      name = "Drago"
    },
    ["0x02d6000100560502"] = {
      name = "Fauna"
    },
    ["0x02d7000101300502"] = {
      name = "Bam"
    },
    ["0x02d8000100e20502"] = {
      name = "Zell"
    },
    ["0x02d9000101c80502"] = {
      name = "Bruce"
    },
    ["0x02da000101330502"] = {
      name = "Deirdre"
    },
    ["0x02db0001005e0502"] = {
      name = "Lopez"
    },
    ["0x02dc000100be0502"] = {
      name = "Fuchsia"
    },
    ["0x02dd000100ea0502"] = {
      name = "Beau"
    },
    ["0x02de0001009c0502"] = {
      name = "Diana"
    },
    ["0x02df000101910502"] = {
      name = "Erik"
    },
    ["0x02e00101031d0502"] = {
      name = "Chelsea"
    },
    ["0x02ea000101800502"] = {
      name = "Goldie"
    },
    ["0x02ea000101d50502"] = {
      name = "Goldie - Amiibo Festival"
    },
    ["0x02eb000100de0502"] = {
      name = "Butch"
    },
    ["0x02ec000101c40502"] = {
      name = "Lucky"
    },
    ["0x02ed0001015a0502"] = {
      name = "Biskit"
    },
    ["0x02ee000101990502"] = {
      name = "Bones"
    },
    ["0x02ef000100580502"] = {
      name = "Portia"
    },
    ["0x02f0000100a70502"] = {
      name = "Walker"
    },
    ["0x02f1000101450502"] = {
      name = "Daisy"
    },
    ["0x02f2000100cc0502"] = {
      name = "Cookie"
    },
    ["0x02f3000102f90502"] = {
      name = "Maddie"
    },
    ["0x02f4000103050502"] = {
      name = "Bea"
    },
    ["0x02f8000101380502"] = {
      name = "Mac"
    },
    ["0x02f9000101020502"] = {
      name = "Marcel"
    },
    ["0x02fa000100970502"] = {
      name = "Benjamin"
    },
    ["0x02fb000100900502"] = {
      name = "Cherry"
    },
    ["0x02fc0001018f0502"] = {
      name = "Shep"
    },
    ["0x0307000100640502"] = {
      name = "Bill"
    },
    ["0x03080001014d0502"] = {
      name = "Joey"
    },
    ["0x0309000100c60502"] = {
      name = "Pate"
    },
    ["0x030a000101c70502"] = {
      name = "Maelle"
    },
    ["0x030b000100790502"] = {
      name = "Deena"
    },
    ["0x030c000101b80502"] = {
      name = "Pompom"
    },
    ["0x030d000101840502"] = {
      name = "Mallary"
    },
    ["0x030e0001012f0502"] = {
      name = "Freckles"
    },
    ["0x030f0001016d0502"] = {
      name = "Derwin"
    },
    ["0x0310000100f80502"] = {
      name = "Drake"
    },
    ["0x0311000100d60502"] = {
      name = "Scoot"
    },
    ["0x0312000103090502"] = {
      name = "Weber"
    },
    ["0x0313000101210502"] = {
      name = "Miranda"
    },
    ["0x0314000102f40502"] = {
      name = "Ketchup"
    },
    ["0x0316000101c00502"] = {
      name = "Gloria"
    },
    ["0x0317000100a60502"] = {
      name = "Molly"
    },
    ["0x03180001006c0502"] = {
      name = "Quillson"
    },
    ["0x0323000100760502"] = {
      name = "Opal"
    },
    ["0x0324000101890502"] = {
      name = "Dizzy"
    },
    ["0x03250001010a0502"] = {
      name = "Big Top"
    },
    ["0x0326000101390502"] = {
      name = "Eloise"
    },
    ["0x0327000101c30502"] = {
      name = "Margie"
    },
    ["0x0328000102eb0502"] = {
      name = "Paolo"
    },
    ["0x03290001009d0502"] = {
      name = "Axel"
    },
    ["0x032a000103070502"] = {
      name = "Ellie"
    },
    ["0x032c000101480502"] = {
      name = "Tucker"
    },
    ["0x032d000100bc0502"] = {
      name = "Tia"
    },
    ["0x032e0101031c0502"] = {
      name = "Chai"
    },
    ["0x03380001011d0502"] = {
      name = "Lily"
    },
    ["0x0339000101b10502"] = {
      name = "Ribbot"
    },
    ["0x033a000101cc0502"] = {
      name = "Frobert"
    },
    ["0x033b000100fa0502"] = {
      name = "Camofrog"
    },
    ["0x033c000101000502"] = {
      name = "Drift"
    },
    ["0x033d0001013a0502"] = {
      name = "Wart Jr."
    },
    ["0x033e000101a20502"] = {
      name = "Puddles"
    },
    ["0x033f0001008f0502"] = {
      name = "Jeremiah"
    },
    ["0x03410001030e0502"] = {
      name = "Tad"
    },
    ["0x0342000101280502"] = {
      name = "Cousteau"
    },
    ["0x0343000102ef0502"] = {
      name = "Huck"
    },
    ["0x0344000100c50502"] = {
      name = "Prince"
    },
    ["0x03450001005f0502"] = {
      name = "Jambette"
    },
    ["0x0347000103020502"] = {
      name = "Raddle"
    },
    ["0x03480001006b0502"] = {
      name = "Gigi"
    },
    ["0x03490001018d0502"] = {
      name = "Croque"
    },
    ["0x034a000101430502"] = {
      name = "Diva"
    },
    ["0x034b0001009f0502"] = {
      name = "Henry"
    },
    ["0x0356000101350502"] = {
      name = "Chevre"
    },
    ["0x0357000100eb0502"] = {
      name = "Nan"
    },
    ["0x0358000102fa0502"] = {
      name = "Billy"
    },
    ["0x035a000100850502"] = {
      name = "Gruff"
    },
    ["0x035c000101290502"] = {
      name = "Velma"
    },
    ["0x035d000100c90502"] = {
      name = "Kidd"
    },
    ["0x035e0001018e0502"] = {
      name = "Pashmina"
    },
    ["0x0369000100d30502"] = {
      name = "Cesar"
    },
    ["0x036a0001019d0502"] = {
      name = "Peewee"
    },
    ["0x036b0001018b0502"] = {
      name = "Boone"
    },
    ["0x036d000103040502"] = {
      name = "Louie"
    },
    ["0x036e000102fb0502"] = {
      name = "Boyd"
    },
    ["0x03700001015d0502"] = {
      name = "Violet"
    },
    ["0x03710001005c0502"] = {
      name = "Al"
    },
    ["0x03720001010b0502"] = {
      name = "Rocket"
    },
    ["0x0373000101340502"] = {
      name = "Hans"
    },
    ["0x0374010103190502"] = {
      name = "Rilla"
    },
    ["0x037e000101560502"] = {
      name = "Hamlet"
    },
    ["0x037f000101aa0502"] = {
      name = "Apple"
    },
    ["0x0380000101870502"] = {
      name = "Graham"
    },
    ["0x0381000100d50502"] = {
      name = "Rodney"
    },
    ["0x03820001016b0502"] = {
      name = "Soleil"
    },
    ["0x03830001009b0502"] = {
      name = "Clay"
    },
    ["0x0384000100860502"] = {
      name = "Flurry"
    },
    ["0x0385000101060502"] = {
      name = "Hamphrey"
    },
    ["0x0390000101850502"] = {
      name = "Rocco"
    },
    ["0x0392000101270502"] = {
      name = "Bubbles"
    },
    ["0x0393000100a00502"] = {
      name = "Bertha"
    },
    ["0x0394000100890502"] = {
      name = "Biff"
    },
    ["0x0395000102fc0502"] = {
      name = "Bitty"
    },
    ["0x0398000100bf0502"] = {
      name = "Harry"
    },
    ["0x0399000101c20502"] = {
      name = "Hippeux"
    },
    ["0x03a40001014f0502"] = {
      name = "Buck"
    },
    ["0x03a50001015b0502"] = {
      name = "Victoria"
    },
    ["0x03a6000100c80502"] = {
      name = "Savannah"
    },
    ["0x03a7000101a10502"] = {
      name = "Elmer"
    },
    ["0x03a8000100910502"] = {
      name = "Rosco"
    },
    ["0x03a9000100710502"] = {
      name = "Winnie"
    },
    ["0x03aa000100e60502"] = {
      name = "Ed"
    },
    ["0x03ab000103160502"] = {
      name = "Cleo"
    },
    ["0x03ac000101880502"] = {
      name = "Peaches"
    },
    ["0x03ad000101b20502"] = {
      name = "Annalise"
    },
    ["0x03ae000100870502"] = {
      name = "Clyde"
    },
    ["0x03af0001012c0502"] = {
      name = "Colton"
    },
    ["0x03b0000101a90502"] = {
      name = "Papi"
    },
    ["0x03b1000100f00502"] = {
      name = "Julian"
    },
    ["0x03bc0001008a0502"] = {
      name = "Yuka"
    },
    ["0x03bd000100f90502"] = {
      name = "Alice"
    },
    ["0x03be000101980502"] = {
      name = "Melba"
    },
    ["0x03bf000101bc0502"] = {
      name = "Sydney"
    },
    ["0x03c0000103100502"] = {
      name = "Gonzo"
    },
    ["0x03c1000100bb0502"] = {
      name = "Ozzie"
    },
    ["0x03c40001012b0502"] = {
      name = "Canberra"
    },
    ["0x03c50001015c0502"] = {
      name = "Lyman"
    },
    ["0x03c6000100930502"] = {
      name = "Eugene"
    },
    ["0x03d1000100c20502"] = {
      name = "Kitt"
    },
    ["0x03d2000100e50502"] = {
      name = "Mathilda"
    },
    ["0x03d3000102f30502"] = {
      name = "Carrie"
    },
    ["0x03d6000101570502"] = {
      name = "Astrid"
    },
    ["0x03d7000101b40502"] = {
      name = "Sylvia"
    },
    ["0x03d9000101a50502"] = {
      name = "Walt"
    },
    ["0x03da000101510502"] = {
      name = "Rooney"
    },
    ["0x03db0001006d0502"] = {
      name = "Marcie"
    },
    ["0x03e6000100ec0502"] = {
      name = "Bud"
    },
    ["0x03e70001012a0502"] = {
      name = "Elvis"
    },
    ["0x03e8000102f50502"] = {
      name = "Rex"
    },
    ["0x03ea0001030b0502"] = {
      name = "Leopold"
    },
    ["0x03ec000101830502"] = {
      name = "Mott"
    },
    ["0x03ed000101a30502"] = {
      name = "Rory"
    },
    ["0x03ee0001008b0502"] = {
      name = "Lionel"
    },
    ["0x03fa000100d00502"] = {
      name = "Nana"
    },
    ["0x03fb000101cf0502"] = {
      name = "Simon"
    },
    ["0x03fc000101470502"] = {
      name = "Tammi"
    },
    ["0x03fd000101580502"] = {
      name = "Monty"
    },
    ["0x03fe000101a40502"] = {
      name = "Elise"
    },
    ["0x03ff000100f40502"] = {
      name = "Flip"
    },
    ["0x04000001006f0502"] = {
      name = "Shari"
    },
    ["0x0401000100660502"] = {
      name = "Deli"
    },
    ["0x040c000101590502"] = {
      name = "Dora"
    },
    ["0x040d000100780502"] = {
      name = "Limberg"
    },
    ["0x040e000100880502"] = {
      name = "Bella"
    },
    ["0x040f000101500502"] = {
      name = "Bree"
    },
    ["0x04100001007f0502"] = {
      name = "Samson"
    },
    ["0x0411000101ab0502"] = {
      name = "Rod"
    },
    ["0x04140001030a0502"] = {
      name = "Candi"
    },
    ["0x0415000101bb0502"] = {
      name = "Rizzo"
    },
    ["0x0416000100fb0502"] = {
      name = "Anicotti"
    },
    ["0x0418000100d80502"] = {
      name = "Broccolo"
    },
    ["0x041a000100e00502"] = {
      name = "Moose"
    },
    ["0x041b000100f10502"] = {
      name = "Bettina"
    },
    ["0x041c000101410502"] = {
      name = "Greta"
    },
    ["0x041d0001018a0502"] = {
      name = "Penelope"
    },
    ["0x041e0001015f0502"] = {
      name = "Chadder"
    },
    ["0x0429000100700502"] = {
      name = "Octavian"
    },
    ["0x042a0001012d0502"] = {
      name = "Marina"
    },
    ["0x042b000101af0502"] = {
      name = "Zucker"
    },
    ["0x0436000101940502"] = {
      name = "Queenie"
    },
    ["0x0437000101050502"] = {
      name = "Gladys"
    },
    ["0x0438000103000502"] = {
      name = "Sandy"
    },
    ["0x0439000103110502"] = {
      name = "Sprocket"
    },
    ["0x043b000103030502"] = {
      name = "Julia"
    },
    ["0x043c000101cb0502"] = {
      name = "Cranston"
    },
    ["0x043d0001007c0502"] = {
      name = "Phil"
    },
    ["0x043e000101490502"] = {
      name = "Blanche"
    },
    ["0x043f000101550502"] = {
      name = "Flora"
    },
    ["0x0440000100ca0502"] = {
      name = "Phoebe"
    },
    ["0x044b0001016c0502"] = {
      name = "Apollo"
    },
    ["0x044c0001008e0502"] = {
      name = "Amelia"
    },
    ["0x044d000101930502"] = {
      name = "Pierce"
    },
    ["0x044e000103150502"] = {
      name = "Buzz"
    },
    ["0x0450000100cf0502"] = {
      name = "Avery"
    },
    ["0x04510001015e0502"] = {
      name = "Frank"
    },
    ["0x0452000100730502"] = {
      name = "Sterling"
    },
    ["0x0453000101040502"] = {
      name = "Keaton"
    },
    ["0x0454000101ae0502"] = {
      name = "Celia"
    },
    ["0x045f000101a80502"] = {
      name = "Aurora"
    },
    ["0x0460000100a50502"] = {
      name = "Roald"
    },
    ["0x0461000101610502"] = {
      name = "Cube"
    },
    ["0x0462000100f60502"] = {
      name = "Hopper"
    },
    ["0x0463000101310502"] = {
      name = "Friga"
    },
    ["0x0464000100c00502"] = {
      name = "Gwen"
    },
    ["0x04650001006e0502"] = {
      name = "Puck"
    },
    ["0x0468000102f20502"] = {
      name = "Wade"
    },
    ["0x0469000101640502"] = {
      name = "Boomer"
    },
    ["0x046a000101d00502"] = {
      name = "Iggly"
    },
    ["0x046b000101970502"] = {
      name = "Tex"
    },
    ["0x046c0001008c0502"] = {
      name = "Flo"
    },
    ["0x046d000100f30502"] = {
      name = "Sprinkle"
    },
    ["0x0478000101630502"] = {
      name = "Curly"
    },
    ["0x0479000100920502"] = {
      name = "Truffles"
    },
    ["0x047a000100600502"] = {
      name = "Rasher"
    },
    ["0x047b000100f50502"] = {
      name = "Hugh"
    },
    ["0x047c000101a00502"] = {
      name = "Lucy"
    },
    ["0x047d0001012e0502"] = {
      name = "Spork/Crackle"
    },
    ["0x04800001008d0502"] = {
      name = "Cobb"
    },
    ["0x0481000102f10502"] = {
      name = "Boris"
    },
    ["0x0482000102fd0502"] = {
      name = "Maggie"
    },
    ["0x0483000101b00502"] = {
      name = "Peggy"
    },
    ["0x04850001014c0502"] = {
      name = "Gala"
    },
    ["0x0486000100fc0502"] = {
      name = "Chops"
    },
    ["0x0487000101bf0502"] = {
      name = "Kevin"
    },
    ["0x0488000100980502"] = {
      name = "Pancetti"
    },
    ["0x0489000100ef0502"] = {
      name = "Agnes"
    },
    ["0x04940001009a0502"] = {
      name = "Bunnie"
    },
    ["0x0495000101920502"] = {
      name = "Dotty"
    },
    ["0x0496000100d90502"] = {
      name = "Coco"
    },
    ["0x04970001007a0502"] = {
      name = "Snake"
    },
    ["0x04980001014a0502"] = {
      name = "Gaston"
    },
    ["0x0499000100df0502"] = {
      name = "Gabi"
    },
    ["0x049a0001014e0502"] = {
      name = "Pippy"
    },
    ["0x049b000100610502"] = {
      name = "Tiffany"
    },
    ["0x049c000101400502"] = {
      name = "Genji"
    },
    ["0x049d000100ed0502"] = {
      name = "Ruby"
    },
    ["0x049e000101b70502"] = {
      name = "Doc"
    },
    ["0x049f000103010502"] = {
      name = "Claude"
    },
    ["0x04a00001016e0502"] = {
      name = "Francine"
    },
    ["0x04a10001016f0502"] = {
      name = "Chrissy"
    },
    ["0x04a2000102e80502"] = {
      name = "Hopkins"
    },
    ["0x04a3000101c90502"] = {
      name = "OHare"
    },
    ["0x04a4000100d40502"] = {
      name = "Carmen"
    },
    ["0x04a5000100740502"] = {
      name = "Bonbon"
    },
    ["0x04a6000100a30502"] = {
      name = "Cole"
    },
    ["0x04a7000101a60502"] = {
      name = "Mira"
    },
    ["0x04a80101031e0502"] = {
      name = "Toby"
    },
    ["0x04b2000101b90502"] = {
      name = "Tank"
    },
    ["0x04b3000100dd0502"] = {
      name = "Rhonda"
    },
    ["0x04b40001030c0502"] = {
      name = "Spike"
    },
    ["0x04b6000102ec0502"] = {
      name = "Hornsby"
    },
    ["0x04b9000101600502"] = {
      name = "Merengue"
    },
    ["0x04ba0001005d0502"] = {
      name = "Renée"
    },
    ["0x04c5000101010502"] = {
      name = "Vesta"
    },
    ["0x04c6000101670502"] = {
      name = "Baabara"
    },
    ["0x04c7000100940502"] = {
      name = "Eunice"
    },
    ["0x04c8000102ed0502"] = {
      name = "Stella"
    },
    ["0x04c90001030d0502"] = {
      name = "Cashmere"
    },
    ["0x04cc000100a40502"] = {
      name = "Willow"
    },
    ["0x04cd000101520502"] = {
      name = "Curlos"
    },
    ["0x04ce000100db0502"] = {
      name = "Wendy"
    },
    ["0x04cf000100e10502"] = {
      name = "Timbra"
    },
    ["0x04d0000101960502"] = {
      name = "Frita"
    },
    ["0x04d10001009e0502"] = {
      name = "Muffy"
    },
    ["0x04d2000101a70502"] = {
      name = "Pietro"
    },
    ["0x04d30101031b0502"] = {
      name = "Étoile"
    },
    ["0x04dd000100a20502"] = {
      name = "Peanut"
    },
    ["0x04de000100ce0502"] = {
      name = "Blaire"
    },
    ["0x04df000100e80502"] = {
      name = "Filbert"
    },
    ["0x04e0000100f70502"] = {
      name = "Pecan"
    },
    ["0x04e1000101be0502"] = {
      name = "Nibbles"
    },
    ["0x04e2000101090502"] = {
      name = "Agent S"
    },
    ["0x04e3000101650502"] = {
      name = "Caroline"
    },
    ["0x04e4000101b60502"] = {
      name = "Sally"
    },
    ["0x04e5000101ad0502"] = {
      name = "Static"
    },
    ["0x04e6000100820502"] = {
      name = "Mint"
    },
    ["0x04e7000101320502"] = {
      name = "Ricky"
    },
    ["0x04e8000101ce0502"] = {
      name = "Cally"
    },
    ["0x04ea000103180502"] = {
      name = "Tasha"
    },
    ["0x04eb000102f00502"] = {
      name = "Sylvana"
    },
    ["0x04ec000100770502"] = {
      name = "Poppy"
    },
    ["0x04ed000100620502"] = {
      name = "Sheldon"
    },
    ["0x04ee0001014b0502"] = {
      name = "Marshal"
    },
    ["0x04ef0001013b0502"] = {
      name = "Hazel"
    },
    ["0x04fa000101680502"] = {
      name = "Rolf"
    },
    ["0x04fb000101c60502"] = {
      name = "Rowan"
    },
    ["0x04fc000102ee0502"] = {
      name = "Tybalt"
    },
    ["0x04fd0001007b0502"] = {
      name = "Bangle"
    },
    ["0x04fe000100590502"] = {
      name = "Leonardo"
    },
    ["0x04ff000101620502"] = {
      name = "Claudia"
    },
    ["0x0500000100e70502"] = {
      name = "Bianca"
    },
    ["0x050b000100990502"] = {
      name = "Chief"
    },
    ["0x050c000101c10502"] = {
      name = "Lobo"
    },
    ["0x050d000101420502"] = {
      name = "Wolfgang"
    },
    ["0x050e000100d70502"] = {
      name = "Whitney"
    },
    ["0x050f000103140502"] = {
      name = "Dobie"
    },
    ["0x0510000101070502"] = {
      name = "Freya"
    },
    ["0x0511000101950502"] = {
      name = "Fang"
    },
    ["0x0513000102e70502"] = {
      name = "Vivian"
    },
    ["0x0514000101530502"] = {
      name = "Skye"
    },
    ["0x05150001005b0502"] = {
      name = "Kyle"
    },
    ["0x0580000000050002"] = {
      name = "Fox"
    },
    ["0x05810000001c0002"] = {
      name = "Falco"
    },
    ["0x05840000037e0002"] = {
      name = "Wolf"
    },
    ["0x05c0000000060002"] = {
      name = "Samus"
    },
    ["0x05c0000003651302"] = {
      name = "Samus Aran"
    },
    ["0x05c0000004121302"] = {
      name = "Samus - Metroid Dread"
    },
    ["0x05c00100001d0002"] = {
      name = "Zero Suit Samus"
    },
    ["0x05c1000003661302"] = {
      name = "Metroid"
    },
    ["0x05c20000037f0002"] = {
      name = "Ridley"
    },
    ["0x05c3000003800002"] = {
      name = "Dark Samus"
    },
    ["0x05c4000004131302"] = {
      name = "E.M.M.I."
    },
    ["0x0600000000120002"] = {
      name = "Captain Falcon"
    },
    ["0x06400100001e0002"] = {
      name = "Olimar"
    },
    ["0x06420000035f1102"] = {
      name = "Pikmin"
    },
    ["0x06c00000000f0002"] = {
      name = "Little Mac"
    },
    ["0x0700000000070002"] = {
      name = "Wii Fit Trainer"
    },
    ["0x0740000000100002"] = {
      name = "Pit"
    },
    ["0x0741000000200002"] = {
      name = "Dark Pit"
    },
    ["0x07420000001f0002"] = {
      name = "Palutena"
    },
    ["0x07800000002d0002"] = {
      name = "Mr. Game & Watch"
    },
    ["0x07810000002e0002"] = {
      name = "R.O.B. - Famicom"
    },
    ["0x0781000000330002"] = {
      name = "R.O.B. - NES"
    },
    ["0x07820000002f0002"] = {
      name = "Duck Hunt"
    },
    ["0x078f000003810002"] = {
      name = "Ice Climbers"
    },
    ["0x07c0000000210002"] = {
      name = "Mii Brawler"
    },
    ["0x07c0010000220002"] = {
      name = "Mii Swordfighter"
    },
    ["0x07c0020000230002"] = {
      name = "Mii Gunner"
    },
    ["0x08000100003e0402"] = {
      name = "Inkling Girl"
    },
    ["0x08000100025f0402"] = {
      name = "Inkling Girl - Lime Green"
    },
    ["0x0800010003690402"] = {
      name = "Inkling Girl - Neon Pink"
    },
    ["0x0800010003820002"] = {
      name = "Inkling"
    },
    ["0x0800010004150402"] = {
      name = "Inkling - Yellow"
    },
    ["0x08000200003f0402"] = {
      name = "Inkling Boy"
    },
    ["0x0800020002600402"] = {
      name = "Inkling Boy - Purple"
    },
    ["0x08000200036a0402"] = {
      name = "Inkling Boy - Neon Green"
    },
    ["0x0800030000400402"] = {
      name = "Inkling Squid"
    },
    ["0x0800030002610402"] = {
      name = "Inkling Squid - Orange"
    },
    ["0x08000300036b0402"] = {
      name = "Inkling Squid - Neon Purple"
    },
    ["0x08010000025d0402"] = {
      name = "Callie"
    },
    ["0x08020000025e0402"] = {
      name = "Marie"
    },
    ["0x0803000003760402"] = {
      name = "Pearl"
    },
    ["0x0804000003770402"] = {
      name = "Marina"
    },
    ["0x08050100038e0402"] = {
      name = "Octoling Girl"
    },
    ["0x08050200038f0402"] = {
      name = "Octoling Boy"
    },
    ["0x08050200041b0402"] = {
      name = "Octoling - Blue"
    },
    ["0x0805030003900402"] = {
      name = "Octoling Octopus"
    },
    ["0x08060100041c0402"] = {
      name = "Smallfry"
    },
    ["0x09c0010102690e02"] = {
      name = "Mario - Soccer"
    },
    ["0x09c00201026a0e02"] = {
      name = "Mario - Baseball"
    },
    ["0x09c00301026b0e02"] = {
      name = "Mario - Tennis"
    },
    ["0x09c00401026c0e02"] = {
      name = "Mario - Golf"
    },
    ["0x09c00501026d0e02"] = {
      name = "Mario - Horse Racing"
    },
    ["0x09c10101026e0e02"] = {
      name = "Luigi - Soccer"
    },
    ["0x09c10201026f0e02"] = {
      name = "Luigi - Baseball"
    },
    ["0x09c1030102700e02"] = {
      name = "Luigi - Tennis"
    },
    ["0x09c1040102710e02"] = {
      name = "Luigi - Golf"
    },
    ["0x09c1050102720e02"] = {
      name = "Luigi - Horse Racing"
    },
    ["0x09c2010102730e02"] = {
      name = "Peach - Soccer"
    },
    ["0x09c2020102740e02"] = {
      name = "Peach - Baseball"
    },
    ["0x09c2030102750e02"] = {
      name = "Peach - Tennis"
    },
    ["0x09c2040102760e02"] = {
      name = "Peach - Golf"
    },
    ["0x09c2050102770e02"] = {
      name = "Peach - Horse Racing"
    },
    ["0x09c3010102780e02"] = {
      name = "Daisy - Soccer"
    },
    ["0x09c3020102790e02"] = {
      name = "Daisy - Baseball"
    },
    ["0x09c30301027a0e02"] = {
      name = "Daisy - Tennis"
    },
    ["0x09c30401027b0e02"] = {
      name = "Daisy - Golf"
    },
    ["0x09c30501027c0e02"] = {
      name = "Daisy - Horse Racing"
    },
    ["0x09c40101027d0e02"] = {
      name = "Yoshi - Soccer"
    },
    ["0x09c40201027e0e02"] = {
      name = "Yoshi - Baseball"
    },
    ["0x09c40301027f0e02"] = {
      name = "Yoshi - Tennis"
    },
    ["0x09c4040102800e02"] = {
      name = "Yoshi - Golf"
    },
    ["0x09c4050102810e02"] = {
      name = "Yoshi - Horse Racing"
    },
    ["0x09c5010102820e02"] = {
      name = "Wario - Soccer"
    },
    ["0x09c5020102830e02"] = {
      name = "Wario - Baseball"
    },
    ["0x09c5030102840e02"] = {
      name = "Wario - Tennis"
    },
    ["0x09c5040102850e02"] = {
      name = "Wario - Golf"
    },
    ["0x09c5050102860e02"] = {
      name = "Wario - Horse Racing"
    },
    ["0x09c6010102870e02"] = {
      name = "Waluigi - Soccer"
    },
    ["0x09c6020102880e02"] = {
      name = "Waluigi - Baseball"
    },
    ["0x09c6030102890e02"] = {
      name = "Waluigi - Tennis"
    },
    ["0x09c60401028a0e02"] = {
      name = "Waluigi - Golf"
    },
    ["0x09c60501028b0e02"] = {
      name = "Waluigi - Horse Racing"
    },
    ["0x09c70101028c0e02"] = {
      name = "Donkey Kong - Soccer"
    },
    ["0x09c70201028d0e02"] = {
      name = "Donkey Kong - Baseball"
    },
    ["0x09c70301028e0e02"] = {
      name = "Donkey Kong - Tennis"
    },
    ["0x09c70401028f0e02"] = {
      name = "Donkey Kong - Golf"
    },
    ["0x09c7050102900e02"] = {
      name = "Donkey Kong - Horse Racing"
    },
    ["0x09c8010102910e02"] = {
      name = "Diddy Kong - Soccer"
    },
    ["0x09c8020102920e02"] = {
      name = "Diddy Kong - Baseball"
    },
    ["0x09c8030102930e02"] = {
      name = "Diddy Kong - Tennis"
    },
    ["0x09c8040102940e02"] = {
      name = "Diddy Kong - Golf"
    },
    ["0x09c8050102950e02"] = {
      name = "Diddy Kong - Horse Racing"
    },
    ["0x09c9010102960e02"] = {
      name = "Bowser - Soccer"
    },
    ["0x09c9020102970e02"] = {
      name = "Bowser - Baseball"
    },
    ["0x09c9030102980e02"] = {
      name = "Bowser - Tennis"
    },
    ["0x09c9040102990e02"] = {
      name = "Bowser - Golf"
    },
    ["0x09c90501029a0e02"] = {
      name = "Bowser - Horse Racing"
    },
    ["0x09ca0101029b0e02"] = {
      name = "Bowser Jr. - Soccer"
    },
    ["0x09ca0201029c0e02"] = {
      name = "Bowser Jr. - Baseball"
    },
    ["0x09ca0301029d0e02"] = {
      name = "Bowser Jr. - Tennis"
    },
    ["0x09ca0401029e0e02"] = {
      name = "Bowser Jr. - Golf"
    },
    ["0x09ca0501029f0e02"] = {
      name = "Bowser Jr. - Horse Racing"
    },
    ["0x09cb010102a00e02"] = {
      name = "Boo - Soccer"
    },
    ["0x09cb020102a10e02"] = {
      name = "Boo - Baseball"
    },
    ["0x09cb030102a20e02"] = {
      name = "Boo - Tennis"
    },
    ["0x09cb040102a30e02"] = {
      name = "Boo - Golf"
    },
    ["0x09cb050102a40e02"] = {
      name = "Boo - Horse Racing"
    },
    ["0x09cc010102a50e02"] = {
      name = "Baby Mario - Soccer"
    },
    ["0x09cc020102a60e02"] = {
      name = "Baby Mario - Baseball"
    },
    ["0x09cc030102a70e02"] = {
      name = "Baby Mario - Tennis"
    },
    ["0x09cc040102a80e02"] = {
      name = "Baby Mario - Golf"
    },
    ["0x09cc050102a90e02"] = {
      name = "Baby Mario - Horse Racing"
    },
    ["0x09cd010102aa0e02"] = {
      name = "Baby Luigi - Soccer"
    },
    ["0x09cd020102ab0e02"] = {
      name = "Baby Luigi - Baseball"
    },
    ["0x09cd030102ac0e02"] = {
      name = "Baby Luigi - Tennis"
    },
    ["0x09cd040102ad0e02"] = {
      name = "Baby Luigi - Golf"
    },
    ["0x09cd050102ae0e02"] = {
      name = "Baby Luigi - Horse Racing"
    },
    ["0x09ce010102af0e02"] = {
      name = "Birdo - Soccer"
    },
    ["0x09ce020102b00e02"] = {
      name = "Birdo - Baseball"
    },
    ["0x09ce030102b10e02"] = {
      name = "Birdo - Tennis"
    },
    ["0x09ce040102b20e02"] = {
      name = "Birdo - Golf"
    },
    ["0x09ce050102b30e02"] = {
      name = "Birdo - Horse Racing"
    },
    ["0x09cf010102b40e02"] = {
      name = "Rosalina - Soccer"
    },
    ["0x09cf020102b50e02"] = {
      name = "Rosalina - Baseball"
    },
    ["0x09cf030102b60e02"] = {
      name = "Rosalina - Tennis"
    },
    ["0x09cf040102b70e02"] = {
      name = "Rosalina - Golf"
    },
    ["0x09cf050102b80e02"] = {
      name = "Rosalina - Horse Racing"
    },
    ["0x09d0010102b90e02"] = {
      name = "Metal Mario - Soccer"
    },
    ["0x09d0020102ba0e02"] = {
      name = "Metal Mario - Baseball"
    },
    ["0x09d0030102bb0e02"] = {
      name = "Metal Mario - Tennis"
    },
    ["0x09d0040102bc0e02"] = {
      name = "Metal Mario - Golf"
    },
    ["0x09d0050102bd0e02"] = {
      name = "Metal Mario - Horse Racing"
    },
    ["0x09d1010102be0e02"] = {
      name = "Pink Gold Peach - Soccer"
    },
    ["0x09d1020102bf0e02"] = {
      name = "Pink Gold Peach - Baseball"
    },
    ["0x09d1030102c00e02"] = {
      name = "Pink Gold Peach - Tennis"
    },
    ["0x09d1040102c10e02"] = {
      name = "Pink Gold Peach - Golf"
    },
    ["0x09d1050102c20e02"] = {
      name = "Pink Gold Peach - Horse Racing"
    },
    ["0x0a00000103ab0502"] = {
      name = "Orville"
    },
    ["0x0a01000103ac0502"] = {
      name = "Wilbur"
    },
    ["0x0a02000103b30502"] = {
      name = "C.J."
    },
    ["0x0a03000103b40502"] = {
      name = "Flick"
    },
    ["0x0a04000103b50502"] = {
      name = "Daisy Mae"
    },
    ["0x0a05000103b80502"] = {
      name = "Harvey"
    },
    ["0x0a06000103ba0502"] = {
      name = "Wisp"
    },
    ["0x0a07000103bc0502"] = {
      name = "Niko"
    },
    ["0x0a08000103bd0502"] = {
      name = "Wardell"
    },
    ["0x0a09000103c00502"] = {
      name = "Sherb"
    },
    ["0x0a0a000103c10502"] = {
      name = "Megan"
    },
    ["0x0a0b000103c20502"] = {
      name = "Dom"
    },
    ["0x0a0c000103c30502"] = {
      name = "Audie"
    },
    ["0x0a0d000103c40502"] = {
      name = "Cyd"
    },
    ["0x0a0e000103c50502"] = {
      name = "Judy"
    },
    ["0x0a0f000103c60502"] = {
      name = "Raymond"
    },
    ["0x0a10000103c70502"] = {
      name = "Reneigh"
    },
    ["0x0a11000103c80502"] = {
      name = "Sasha"
    },
    ["0x0a12000103c90502"] = {
      name = "Ione"
    },
    ["0x0a13000103ca0502"] = {
      name = "Tiansheng"
    },
    ["0x0a14000103cb0502"] = {
      name = "Shino"
    },
    ["0x0a15000103cc0502"] = {
      name = "Marlo"
    },
    ["0x0a16000103cd0502"] = {
      name = "Petri"
    },
    ["0x0a17000103ce0502"] = {
      name = "Cephalobot"
    },
    ["0x0a18000103cf0502"] = {
      name = "Quinn"
    },
    ["0x0a19000103d00502"] = {
      name = "Chabwick"
    },
    ["0x0a1a000103d10502"] = {
      name = "Zoe"
    },
    ["0x0a1b000103d20502"] = {
      name = "Ace"
    },
    ["0x0a1c000103d30502"] = {
      name = "Rio"
    },
    ["0x0a1d000103d40502"] = {
      name = "Frett"
    },
    ["0x0a1e000103d50502"] = {
      name = "Azalea"
    },
    ["0x0a1f000103d60502"] = {
      name = "Roswell"
    },
    ["0x0a20000103d70502"] = {
      name = "Faith"
    },
    ["0x0a400000041d0002"] = {
      name = "Min Min"
    },
    ["0x1902000003830002"] = {
      name = "Ivysaur"
    },
    ["0x1906000000240002"] = {
      name = "Charizard"
    },
    ["0x1907000003840002"] = {
      name = "Squirtle"
    },
    ["0x1919000000090002"] = {
      name = "Pikachu"
    },
    ["0x1927000000260002"] = {
      name = "Jigglypuff"
    },
    ["0x19960000023d0002"] = {
      name = "Mewtwo"
    },
    ["0x19ac000003850002"] = {
      name = "Pichu"
    },
    ["0x1ac0000000110002"] = {
      name = "Lucario"
    },
    ["0x1b92000000250002"] = {
      name = "Greninja"
    },
    ["0x1bd7000003860002"] = {
      name = "Incineroar"
    },
    ["0x1d000001025c0d02"] = {
      name = "Shadow Mewtwo"
    },
    ["0x1d01000003750d02"] = {
      name = "Detective Pikachu"
    },
    ["0x1d40000003870002"] = {
      name = "Pokemon Trainer"
    },
    ["0x1f000000000a0002"] = {
      name = "Kirby"
    },
    ["0x1f00000002540c02"] = {
      name = "Kirby"
    },
    ["0x1f01000000270002"] = {
      name = "Meta Knight"
    },
    ["0x1f01000002550c02"] = {
      name = "Meta Knight"
    },
    ["0x1f02000000280002"] = {
      name = "King Dedede"
    },
    ["0x1f02000002560c02"] = {
      name = "King Dedede"
    },
    ["0x1f03000002570c02"] = {
      name = "Waddle Dee"
    },
    ["0x1f400000035e1002"] = {
      name = "Qbby"
    },
    ["0x21000000000b0002"] = {
      name = "Marth"
    },
    ["0x2101000000180002"] = {
      name = "Ike"
    },
    ["0x2102000000290002"] = {
      name = "Lucina"
    },
    ["0x21030000002a0002"] = {
      name = "Robin"
    },
    ["0x2104000002520002"] = {
      name = "Roy"
    },
    ["0x21050000025a0002"] = {
      name = "Corrin"
    },
    ["0x2105010003630002"] = {
      name = "Corrin - Player 2"
    },
    ["0x2106000003601202"] = {
      name = "Alm"
    },
    ["0x2107000003611202"] = {
      name = "Celica"
    },
    ["0x21080000036f1202"] = {
      name = "Chrom"
    },
    ["0x2108000003880002"] = {
      name = "Chrom"
    },
    ["0x2109000003701202"] = {
      name = "Tiki"
    },
    ["0x210b000003a50002"] = {
      name = "Byleth"
    },
    ["0x22400000002b0002"] = {
      name = "Shulk"
    },
    ["0x22800000002c0002"] = {
      name = "Ness"
    },
    ["0x2281000002510002"] = {
      name = "Lucas"
    },
    ["0x22c00000003a0202"] = {
      name = "Chibi Robo"
    },
    ["0x3200000000300002"] = {
      name = "Sonic"
    },
    ["0x32400000025b0002"] = {
      name = "Bayonetta"
    },
    ["0x3240010003640002"] = {
      name = "Bayonetta - Player 2"
    },
    ["0x3340000000320002"] = {
      name = "Pac-Man"
    },
    ["0x3380000003781402"] = {
      name = "Solaire of Astora"
    },
    ["0x33c0000004200002"] = {
      name = "Kazuya"
    },
    ["0x3480000000310002"] = {
      name = "Mega Man"
    },
    ["0x3480000002580002"] = {
      name = "Mega Man - Gold Edition"
    },
    ["0x3480000003791502"] = {
      name = "Mega Man"
    },
    ["0x34c0000002530002"] = {
      name = "Ryu"
    },
    ["0x34c1000003890002"] = {
      name = "Ken"
    },
    ["0x3500010002e10f02"] = {
      name = "One-Eyed Rathalos and Rider - Male"
    },
    ["0x3500020002e20f02"] = {
      name = "One-Eyed Rathalos and Rider - Female"
    },
    ["0x3501000002e30f02"] = {
      name = "Nabiru"
    },
    ["0x3502010002e40f02"] = {
      name = "Rathian and Cheval"
    },
    ["0x3503010002e50f02"] = {
      name = "Barioth and Ayuria"
    },
    ["0x3504010002e60f02"] = {
      name = "Qurupeco and Dan"
    },
    ["0x35050000040c0f02"] = {
      name = "Razewing Ratha"
    },
    ["0x35060000040d0f02"] = {
      name = "Ena"
    },
    ["0x35070000040e0f02"] = {
      name = "Tsukino"
    },
    ["0x35080000040f1802"] = {
      name = "Magnamalo"
    },
    ["0x3509000004101802"] = {
      name = "Palico"
    },
    ["0x35090100042b1802"] = {
      name = "Palico"
    },
    ["0x350a000004111802"] = {
      name = "Palamute"
    },
    ["0x350a0100042c1802"] = {
      name = "Palamute"
    },
    ["0x350b0000042d1802"] = {
      name = "Malzeno"
    },
    ["0x35c0000002500a02"] = {
      name = "Shovel Knight"
    },
    ["0x35c0000003920a02"] = {
      name = "Shovel Knight - Gold Edition"
    },
    ["0x35c10000036c0a02"] = {
      name = "Plague Knight"
    },
    ["0x35c20000036d0a02"] = {
      name = "Specter Knight"
    },
    ["0x35c30000036e0a02"] = {
      name = "King Knight"
    },
    ["0x3600000002590002"] = {
      name = "Cloud"
    },
    ["0x3600010003620002"] = {
      name = "Cloud - Player 2"
    },
    ["0x3601000004210002"] = {
      name = "Sephiroth"
    },
    ["0x3640000003a20002"] = {
      name = "Hero"
    },
    ["0x3740000103741402"] = {
      name = "Super Mario Cereal"
    },
    ["0x37800000038a0002"] = {
      name = "Snake"
    },
    ["0x37c00000038b0002"] = {
      name = "Simon"
    },
    ["0x37c10000038c0002"] = {
      name = "Richter"
    },
    ["0x3800000103931702"] = {
      name = "Pawapuro"
    },
    ["0x3801000103941702"] = {
      name = "Ikari"
    },
    ["0x3802000103951702"] = {
      name = "Daijobu"
    },
    ["0x3803000103961702"] = {
      name = "Hayakawa"
    },
    ["0x3804000103971702"] = {
      name = "Yabe"
    },
    ["0x3805000103981702"] = {
      name = "Ganda"
    },
    ["0x3840000104241902"] = {
      name = "Yuga Ohdo"
    },
    ["0x3841000104251902"] = {
      name = "Tatsuhisa “Luke” Kamijō"
    },
    ["0x3842000104261902"] = {
      name = "Gakuto Sōgetsu"
    },
    ["0x3843000104271902"] = {
      name = "Romin Kirishima"
    },
    ["0x3844000104281902"] = {
      name = "Roa Kirishima"
    },
    ["0x3845000104291902"] = {
      name = "Nail Saionji"
    },
    ["0x38460001042a1902"] = {
      name = "Asana Mutsuba"
    },
    ["0x38c0000003911602"] = {
      name = "Loot Goblin"
    },
    ["0x3a00000003a10002"] = {
      name = "Joker"
    },
    ["0x3b40000003a30002"] = {
      name = "Banjo & Kazooie"
    },
    ["0x3c80000003a40002"] = {
      name = "Terry"
    },
    ["0x3dc0000004220002"] = {
      name = "Steve"
    },
    ["0x3dc1000004230002"] = {
      name = "Alex"
    }
  },
  game_series = {
    ["0x000"] = "Super Mario",
    ["0x001"] = "Super Mario",
    ["0x002"] = "Super Mario",
    ["0x008"] = "Yoshi's Woolly World",
    ["0x00c"] = "Donkey Kong",
    ["0x010"] = "The Legend of Zelda",
    ["0x014"] = "Breath of the Wild",
    ["0x018"] = "Animal Crossing",
    ["0x019"] = "Animal Crossing",
    ["0x01a"] = "Animal Crossing",
    ["0x01b"] = "Animal Crossing",
    ["0x01c"] = "Animal Crossing",
    ["0x020"] = "Animal Crossing",
    ["0x021"] = "Animal Crossing",
    ["0x022"] = "Animal Crossing",
    ["0x023"] = "Animal Crossing",
    ["0x024"] = "Animal Crossing",
    ["0x025"] = "Animal Crossing",
    ["0x026"] = "Animal Crossing",
    ["0x027"] = "Animal Crossing",
    ["0x028"] = "Animal Crossing",
    ["0x029"] = "Animal Crossing",
    ["0x02a"] = "Animal Crossing",
    ["0x02b"] = "Animal Crossing",
    ["0x02c"] = "Animal Crossing",
    ["0x02d"] = "Animal Crossing",
    ["0x02e"] = "Animal Crossing",
    ["0x02f"] = "Animal Crossing",
    ["0x030"] = "Animal Crossing",
    ["0x031"] = "Animal Crossing",
    ["0x032"] = "Animal Crossing",
    ["0x033"] = "Animal Crossing",
    ["0x034"] = "Animal Crossing",
    ["0x035"] = "Animal Crossing",
    ["0x036"] = "Animal Crossing",
    ["0x037"] = "Animal Crossing",
    ["0x038"] = "Animal Crossing",
    ["0x039"] = "Animal Crossing",
    ["0x03a"] = "Animal Crossing",
    ["0x03b"] = "Animal Crossing",
    ["0x03c"] = "Animal Crossing",
    ["0x03d"] = "Animal Crossing",
    ["0x03e"] = "Animal Crossing",
    ["0x03f"] = "Animal Crossing",
    ["0x040"] = "Animal Crossing",
    ["0x041"] = "Animal Crossing",
    ["0x042"] = "Animal Crossing",
    ["0x043"] = "Animal Crossing",
    ["0x044"] = "Animal Crossing",
    ["0x045"] = "Animal Crossing",
    ["0x046"] = "Animal Crossing",
    ["0x047"] = "Animal Crossing",
    ["0x048"] = "Animal Crossing",
    ["0x049"] = "Animal Crossing",
    ["0x04a"] = "Animal Crossing",
    ["0x04b"] = "Animal Crossing",
    ["0x04c"] = "Animal Crossing",
    ["0x04d"] = "Animal Crossing",
    ["0x04e"] = "Animal Crossing",
    ["0x04f"] = "Animal Crossing",
    ["0x050"] = "Animal Crossing",
    ["0x051"] = "Animal Crossing",
    ["0x0a0"] = "Animal Crossing",
    ["0x0a1"] = "Animal Crossing",
    ["0x0a2"] = "Animal Crossing",
    ["0x058"] = "Star Fox",
    ["0x05c"] = "Metroid",
    ["0x060"] = "F-Zero",
    ["0x064"] = "Pikmin",
    ["0x06c"] = "Punch Out",
    ["0x070"] = "Wii Fit",
    ["0x074"] = "Kid Icarus",
    ["0x078"] = "Classic Nintendo",
    ["0x07c"] = "Mii",
    ["0x080"] = "Splatoon",
    ["0x09c"] = "Mario Sports Superstars",
    ["0x09d"] = "Mario Sports Superstars",
    ["0x0a4"] = "ARMS",
    ["0x190"] = "Pokemon",
    ["0x191"] = "Pokemon",
    ["0x192"] = "Pokemon",
    ["0x199"] = "Pokemon",
    ["0x19a"] = "Pokemon",
    ["0x1ac"] = "Pokemon",
    ["0x1b9"] = "Pokemon",
    ["0x1bd"] = "Pokemon",
    ["0x1d0"] = "Pokemon",
    ["0x1d4"] = "Pokemon",
    ["0x1f0"] = "Kirby",
    ["0x1f4"] = "BoxBoy!",
    ["0x210"] = "Fire Emblem",
    ["0x224"] = "Xenoblade",
    ["0x228"] = "Earthbound",
    ["0x22c"] = "Chibi Robo",
    ["0x320"] = "Sonic",
    ["0x324"] = "Bayonetta",
    ["0x334"] = "Pac-man",
    ["0x338"] = "Dark Souls",
    ["0x33c"] = "Tekken",
    ["0x348"] = "Megaman",
    ["0x34c"] = "Street fighter",
    ["0x350"] = "Monster Hunter",
    ["0x35c"] = "Shovel Knight",
    ["0x360"] = "Final Fantasy",
    ["0x364"] = "Dragon Quest",
    ["0x374"] = "Kellogs",
    ["0x378"] = "Metal Gear Solid",
    ["0x37c"] = "Castlevania",
    ["0x380"] = "Power Pros",
    ["0x384"] = "Yu-Gi-Oh!",
    ["0x38c"] = "Diablo",
    ["0x3a0"] = "Persona",
    ["0x3b4"] = "Banjo Kazooie",
    ["0x3c8"] = "Fatal Fury",
    ["0x3dc"] = "Minecraft"
  },
  types = {
    ["0x00"] = "Figure",
    ["0x01"] = "Card",
    ["0x02"] = "Yarn",
    ["0x03"] = "Band"
  }
}

return amiibo_tools
