    
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
    The Slurp project, 
    Data from: https://github.com/4ZM/slurp/blob/master/res/xml/mifare_default_keys.xml
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

    --[[
    Data from: http://pastebin.com/wcTHXLZZ
    --]]
    'a64598a77478', -- RKF SL Key A
    '26940b21ff5d', -- RKF SL Key A
    'fc00018778f7', -- RKF SL Key A
    '00000ffe2488', -- RKF SL Key B
    '5c598c9c58b5', -- RKF SL Key B
    'e4d2770a89be', -- RKF SL Key B

	--[[	 
    Data from: http://pastebin.com/svGjN30Q
	--]]	
    '434f4d4d4f41', -- RKF JOJO GROUP Key A
    '434f4d4d4f42', -- RKF JOJO GROUP Key B
    '47524f555041', -- RKF JOJO GROUP Key A
    '47524f555042', -- RKF JOJO GROUP Key B
    '505249564141', -- RKF JOJO PRIVA Key A
    '505249564142', -- RKF JOJO PRIVA Key B

	--[[	 
    Data from: http://pastebin.com/d7sSetef
	--]]	
    'fc00018778f7', -- RKF Rejskort Danmark Key A
    '00000ffe2488', -- RKF Rejskort Danmark Key B
    '0297927c0f77', -- RKF Rejskort Danmark Key A
    'ee0042f88840', -- RKF Rejskort Danmark Key B
    '722bfcc5375f', -- RKF Rejskort Danmark Key A
    'f1d83f964314', -- RKF Rejskort Danmark Key B
	
	--[[	 
	Data from: http://pastebin.com/pvJX0xVS
	--]]    
    '54726176656C', -- Transport Key A
    '776974687573', -- Transport Key B
    '4AF9D7ADEBE4', -- Directory and event log Key A
    '2BA9621E0A36', -- Directory and event log Key B

	--[[	 
	Data from: http://pastebin.com/AK9Bftpw
	--]]	
    '48ffe71294a0', -- Länstrafiken i Västerbotten
    'e3429281efc1', -- Länstrafiken i Västerbotten
    '16f21a82ec84', -- Länstrafiken i Västerbotten
    '460722122510', -- Länstrafiken i Västerbotten
	
	--[[	 
    Data from: http://pastebin.com/Dnnc5dFC
	--]]
    'fc00018778f7', -- Västtrafiken Key A
    '00000ffe2488', -- Västtrafiken Key B
    '0297927c0f77', -- Västtrafiken Key A
    'ee0042f88840', -- Västtrafiken Key B
    '54726176656c', -- Västtrafiken Key A
    '776974687573', -- Västtrafiken Key B
	
	--[[	 
    Data from: http://pastebin.com/y3PDBWR1
	 --]]	
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
	
	--[[	 
	Data from: http://pastebin.com/TUXj17K3
	--]]
    'fc0001877bf7', -- RKF ÖstgötaTrafiken Key A
    '00000ffe2488', -- RKF ÖstgötaTrafiken Key B
    '0297927c0f77', -- RKF ÖstgötaTrafiken Key A
    'ee0042f88840', -- RKF ÖstgötaTrafiken Key B
    '54726176656c', -- RKF ÖstgötaTrafiken Key A
    '776974687573', -- RKF ÖstgötaTrafiken Key B

    --[[
    Data from: https://code.google.com/p/mifare-key-cracker/downloads/list
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
    Data from: https://github.com/4ZM/mfterm/blob/master/dictionary.txt
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
    Mifare TNP3xxx tags key A
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
	 
	 --[[
	 mystery Key A and B for Mifare 1k EV1 (S50) Sector 17!
	 --]]
	'75ccb59c9bed',
	'4b791bea7bcc',
	
	--[[
	Here be BIP keys
	Data from: http://pastebin.com/QjUc66Zg
	--]]
	'3A42F33AF429',
	'1FC235AC1309',
	'6338A371C0ED',
	'243F160918D1',
	'F124C2578AD0',
	'9AFC42372AF1',
	'32AC3B90AC13',
	'682D401ABB09',
	'4AD1E273EAF1',
	'067DB45454A9',
	'E2C42591368A',
	'15FC4C7613FE',
	'2A3C347A1200',
	'68D30288910A',
	'16F3D5AB1139',
	'F59A36A2546D',
	'937A4FFF3011',
	'64E3C10394C2',
	'35C3D2CAEE88',
	'B736412614AF',
	'693143F10368',
	'324F5DF65310',
	'A3F97428DD01',
	'643FB6DE2217',
	'63F17A449AF0',
	'82F435DEDF01',
	'C4652C54261C',
	'0263DE1278F3',
	'D49E2826664F',
	'51284C3686A6',
	'3DF14C8000A1',
	'6A470D54127C',
	
	--[[
	3dprinter
	EPI Envisionte
	--]]
	'AAFB06045877',
	
	--[[
	Fysiken
	--]]
	'3E65E4FB65B3',
	'25094DF6F148',

	--[[
	key A 
	--]]
	'454841585443',

	--[[
	Data from: http://pastebin.com/gQ6nk38G
	--]]
	'A0A1A2A3A4A5', 
	'D39BB83F5297', 
	'A27D3804C259', 
	'85675B200017', 
	'528C9DFFE28C', 
	'C82EC29E3235', 
	'3E3554AF0E12', 
	'491CDCFB7752', 
	'22C1BAE1AACD', 
	'5F146716E373', 
	'740E9A4F9AAF', 
	'AC0E24C75527', 
	'97184D136233', 
	'E444D53D359F', 
	'17758856B182', 
	'A8966C7CC54B', 
	'C6AD00254562', 
	'AE3FF4EEA0DB', 
	'5EB8F884C8D1', 
	'FEE470A4CB58', 
	'75D8690F21B6', 
	'871B8C085997', 
	'97D1101F18B0', 
	'75EDE6A84460', 
	'DF27A8F1CB8E', 
	'B0C9DD55DD4D', 

	--[[
	Data from: http://pastebin.com/AK9Bftpw
	--]]
	'48ffe71294a0', 
	'e3429281efc1', 
	'16f21a82ec84', 
	'460722122510', 
	
	--[[
	Data from: http://bit.ly/1bdSbJl
	--]]
	'A0B0C0D0E0F0', 
	'A1B1C1D1E1F1', 
	
	--[[
	Data from: msk three
	Thanks to A.
	--]]
	'ae3d65a3dad4', 
	'a73f5dc1d333', 
	'73068F118C13', 
	
	--[[
	Data from: msk social
	Thanks to A.
	--]]
	'a0a1a2a3a4a5', 
	'2735fc181807', 
	'2aba9519f574', 
	'84fd7f7a12b6', 
	'73068f118c13', 
	'186d8c4b93f9', 
	'3a4bba8adaf0', 
	'8765b17968a2', 
	'40ead80721ce', 
	'0db5e6523f7c', 
	'51119dae5216', 
	'83e3549ce42d', 
	'136bdb246cac', 
	'7de02a7f6025', 
	'bf23a53c1f63', 
	'cb9a1f2d7368', 
	'c7c0adb3284f', 
	'2b7f3253fac5', 
	'9f131d8c2057', 
	'67362d90f973', 
	'6202a38f69e2', 
	'100533b89331', 
	'653a87594079', 
	'd8a274b2e026', 
	'b20b83cb145c', 
	'9afa6cb4fc3d',
	--[[
	Data from:  http://pastebin.com/RRJUEDCM
	
	--]]
	'0d258fe90296',
	'e55a3ca71826',
	'a4f204203f56',
	'eeb420209d0c',
	'911e52fd7ce4',
	'752fbb5b7b45',
	'66b03aca6ee9',
	'48734389edc3',
	'17193709adf4',
	'1acc3189578c',
	'c2b7ec7d4eb1',
	'369a4663acd2',	
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
