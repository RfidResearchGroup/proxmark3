
    
local _keys = {


    --[[

    These keys are from the pm3 c-codebase. 

    --]]
    'ffffffffffff', -- Default key (first key used by program if no user defined key)
    '000000000000', -- Blank key
    'a0a1a2a3a4a5', -- NFCForum MAD key
    'b0b1b2b3b4b5',
    'aabbccddeeff',
    '4d3a99c351dd',
    '1a982c7e459a',
    'd3f7d3f7d3f7',
    '714c5c886e97',
    '587ee5f9350f',
    'a0478cc39091',
    '533cb6c723f6',
    '8fd0a4f256e9',

    
    --[[
    The data below is taken form the Slurp project, 
    https://github.com/4ZM/slurp/blob/master/res/xml/mifare_default_keys.xml
    released as GPLV3. 

    --]]

    '000000000000', -- Default key
    'ffffffffffff', -- Default key
    'b0b1b2b3b4b5', -- Key from mfoc
    '4d3a99c351dd', -- Key from mfoc
    '1a982c7e459a', -- Key from mfoc
    'aabbccddeeff', -- Key from mfoc
    '714c5c886e97', -- Key from mfoc
    '587ee5f9350f', -- Key from mfoc
    'a0478cc39091', -- Key from mfoc
    '533cb6c723f6', -- Key from mfoc
    '8fd0a4f256e9', -- Key from mfoc
    -- Data from: http://pastebin.com/wcTHXLZZ
    'a64598a77478', -- RKF SL Key A
    '26940b21ff5d', -- RKF SL Key A
    'fc00018778f7', -- RKF SL Key A
    '00000ffe2488', -- RKF SL Key B
    '5c598c9c58b5', -- RKF SL Key B
    'e4d2770a89be', -- RKF SL Key B
    -- Data from: http://pastebin.com/svGjN30Q
    '434f4d4d4f41', -- RKF JOJO GROUP Key A
    '434f4d4d4f42', -- RKF JOJO GROUP Key B
    '47524f555041', -- RKF JOJO GROUP Key A
    '47524f555042', -- RKF JOJO GROUP Key B
    '505249564141', -- RKF JOJO PRIVA Key A
    '505249564142', -- RKF JOJO PRIVA Key B
    -- Data from: http://pastebin.com/d7sSetef
    'fc00018778f7', -- RKF Rejskort Danmark Key A
    '00000ffe2488', -- RKF Rejskort Danmark Key B
    '0297927c0f77', -- RKF Rejskort Danmark Key A
    'ee0042f88840', -- RKF Rejskort Danmark Key B
    '722bfcc5375f', -- RKF Rejskort Danmark Key A
    'f1d83f964314', -- RKF Rejskort Danmark Key B
    -- Data from: http://pastebin.com/pvJX0xVS
    '54726176656C', -- Transport Key A
    '776974687573', -- Transport Key B
    '4AF9D7ADEBE4', -- Directory and event log Key A
    '2BA9621E0A36', -- Directory and event log Key B
    -- Data from: http://pastebin.com/Dnnc5dFC
    -- New cards are not encrypted (MF Ultralight)
    'fc00018778f7', -- Västtrafiken Key A
    '00000ffe2488', -- Västtrafiken Key B
    '0297927c0f77', -- Västtrafiken Key A
    'ee0042f88840', -- Västtrafiken Key B
    '54726176656c', -- Västtrafiken Key A
    '776974687573', -- Västtrafiken Key B
    -- Data from: http://pastebin.com/y3PDBWR1
    '000000000001',
    'a0a1a2a3a4a5',
    '123456789abc',
    'b127c6f41436',
    '12f2ee3478c1',
    '34d1df9934c5',
    '55f5a5dd38c9',
    'f1a97341a9fc',
    '33f974b42769',
    '14d446e33363',
    'c934fe34d934',
    '1999a3554a55',
    '27dd91f1fcf1',
    'a94133013401',
    '99c636334433',
    '43ab19ef5c31',
    'a053a292a4af',
    '434f4d4d4f41',
    '434f4d4d4f42',
    '505249565441',
    '505249565442',
    -- Data from,:, http://pastebin.com/TUXj17K3
    'fc0001877bf7', -- RKF ÖstgötaTrafiken Key A
    '00000ffe2488', -- RKF ÖstgötaTrafiken Key B
    '0297927c0f77', -- RKF ÖstgötaTrafiken Key A
    'ee0042f88840', -- RKF ÖstgötaTrafiken Key B
    '54726176656c', -- RKF ÖstgötaTrafiken Key A
    '776974687573', -- RKF ÖstgötaTrafiken Key B

    --[[
    The keys below are taken from from https://code.google.com/p/mifare-key-cracker/downloads/list
    --]]

    'bd493a3962b6',
    '010203040506',
    '111111111111',
    '222222222222',
    '333333333333',
    '444444444444',
    '555555555555',
    '666666666666',
    '777777777777',
    '888888888888',
    '999999999999',
    'aaaaaaaaaaaa',
    'bbbbbbbbbbbb',
    'cccccccccccc',
    'dddddddddddd',
    'eeeeeeeeeeee',
    '0123456789ab',
    '123456789abc',
	
	--[[
    The keys below are taken from from https://github.com/4ZM/mfterm/blob/master/dictionary.txt
    --]]
	
	'abcdef123456', -- Key from ladyada.net

	'000000000001',
	'000000000002',
	'00000000000a',
	'00000000000b',
	'100000000000',
	'200000000000',
	'a00000000000',
	'b00000000000',	
	
	--[[
    Should be for Mifare TNP3xxx tags A KEY.
    --]]
	'4b0b20107ccb',

	--[[
    Kiev metro cards
    --]]	
	'8fe644038790',
	'f14ee7cae863',
	'632193be1c3c',
	'569369c5a0e5',
	'9de89e070277',
	'eff603e1efe9',
	'644672bd4afe',
	'b5ff67cba951',
	
	--[[
    hotel system cards,
	http://www.proxmark.org/forum/viewtopic.php?id=2430
    --]]	
	  '44ab09010845',
      '85fed980ea5a',
	  
	 --[[
	 VIGIK1
	 --]]
	 '314B49474956',
	 '564c505f4d41',
	 
	 --[[
	 BCARD keyB
	 --]]
	 'f4a9ef2afc6d',
	 
	 --[[	 
	 --]]
	 'a9f953def0a3',
}

---
--    The keys above have just been pasted in, for completeness sake. They contain duplicates. 
--    We need to weed the duplicates out before we expose the list to someone who actually wants to use them
--    @param list a list to do 'uniq' on

local function uniq(list)
    
    local foobar = {}
    --print("list length ", #list)
    for _, value in pairs(list) do
        value = value:lower()
        if not foobar[value] then
            foobar[value] = true
            table.insert(foobar, value);
        end
    end
    --print("final list length length ", #foobar)
    return foobar
end

return uniq(_keys)
