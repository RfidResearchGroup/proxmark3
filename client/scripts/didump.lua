---
-- requirements
local cmds = require('commands')
local getopt = require('getopt')
local utils = require('utils')
local lib14a = require('read14a')
local json = require('dkjson')
local toys = require('default_toys_di')

copyright = ''
author = 'Iceman'
version = 'v1.0.1'
desc = [[
This is a script to dump and decrypt the data of a specific type of Mifare Mini token.
The dump is decrypted. If a raw dump is wanted, use the -r parameter
]]
example = [[
    script run didump

    -- selftest
    script run didump -t

    -- Generate raw dump,  into json.
    script run didump -r

    -- load file
    script run didump -i dumpdata.json
]]
usage = [[
script run didump -h -t -r -d -e -v -i dumpdata.json

Arguments:
      h                 this helptext
      r                 raw
      t                 selftest
      d                 decrypt data
      e                 encrypt data
      v                 validate data
      i dumpdata.json   load json dump file
    end
]]

-- Some shortcuts
local band = bit32.band
local bor = bit32.bor
local bnot = bit32.bnot
local bxor = bit32.bxor
local lsh = bit32.lshift
local rsh = bit32.rshift

-- Some globals
local PM3_SUCCESS = 0
local FOO = 'AF62D2EC0491968CC52A1A7165F865FE'
local BAR = '286329204469736E65792032303133'
local MIS = '0A14FD0507FF4BCD026BA83F0A3B89A9'
local outputTemplate = os.date("toydump_%Y-%m-%d_%H%M%S");
local TIMEOUT = 2000
local DEBUG = true
local numBlocks = 20
local numSectors = 5
local CHECKSUM_OFFSET = 12; -- +1???

---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            print('###', args[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR: ', err)
    core.clearCommandBuffer()
    return nil, err
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print('Example usage')
    print(example)
    print(usage)
end
---
--
local function print_info(tagdata)
    --got table with data.
    local h = tagdata[2]:sub(1,8)
    local t = tostring( tonumber( h, 16 ) )
    local item = toys.Find(t)
    print( ("Modelid : %s , %s,  v.%s.0"):format(t, item[3], item[2]))
end
---
-- Get checksum,
-- called: data is string (32 hex digits)
-- returns: number
local function getChecksum(data)
    local chksum = data:sub(25,32)
    return tonumber(chksum,16)
end
---
-- calculate checksum
-- called: data is bytes  (24 hex digits)
-- returns: number
local function calculateChecksum(data)

    -- Generate table
    local _tbl = {}
_tbl[0] = { 0x0 }
_tbl[1] = { 0x77073096 }
_tbl[2] = { 0xEE0E612C }
_tbl[3] = { 0x990951BA }
_tbl[4] = { 0x76DC419 }
_tbl[5] = { 0x706AF48F }
_tbl[6] = { 0xE963A535 }
_tbl[7] = { 0x9E6495A3 }
_tbl[8] = { 0xEDB8832 }
_tbl[9] = { 0x79DCB8A4 }
_tbl[10] = { 0xE0D5E91E }
_tbl[11] = { 0x97D2D988 }
_tbl[12] = { 0x9B64C2B }
_tbl[13] = { 0x7EB17CBD }
_tbl[14] = { 0xE7B82D07 }
_tbl[15] = { 0x90BF1D91 }
_tbl[16] = { 0x1DB71064 }
_tbl[17] = { 0x6AB020F2 }
_tbl[18] = { 0xF3B97148 }
_tbl[19] = { 0x84BE41DE }
_tbl[20] = { 0x1ADAD47D }
_tbl[21] = { 0x6DDDE4EB }
_tbl[22] = { 0xF4D4B551 }
_tbl[23] = { 0x83D385C7 }
_tbl[24] = { 0x136C9856 }
_tbl[25] = { 0x646BA8C0 }
_tbl[26] = { 0xFD62F97A }
_tbl[27] = { 0x8A65C9EC }
_tbl[28] = { 0x14015C4F }
_tbl[29] = { 0x63066CD9 }
_tbl[30] = { 0xFA0F3D63 }
_tbl[31] = { 0x8D080DF5 }
_tbl[32] = { 0x3B6E20C8 }
_tbl[33] = { 0x4C69105E }
_tbl[34] = { 0xD56041E4 }
_tbl[35] = { 0xA2677172 }
_tbl[36] = { 0x3C03E4D1 }
_tbl[37] = { 0x4B04D447 }
_tbl[38] = { 0xD20D85FD }
_tbl[39] = { 0xA50AB56B }
_tbl[40] = { 0x35B5A8FA }
_tbl[41] = { 0x42B2986C }
_tbl[42] = { 0xDBBBC9D6 }
_tbl[43] = { 0xACBCF940 }
_tbl[44] = { 0x32D86CE3 }
_tbl[45] = { 0x45DF5C75 }
_tbl[46] = { 0xDCD60DCF }
_tbl[47] = { 0xABD13D59 }
_tbl[48] = { 0x26D930AC }
_tbl[49] = { 0x51DE003A }
_tbl[50] = { 0xC8D75180 }
_tbl[51] = { 0xBFD06116 }
_tbl[52] = { 0x21B4F4B5 }
_tbl[53] = { 0x56B3C423 }
_tbl[54] = { 0xCFBA9599 }
_tbl[55] = { 0xB8BDA50F }
_tbl[56] = { 0x2802B89E }
_tbl[57] = { 0x5F058808 }
_tbl[58] = { 0xC60CD9B2 }
_tbl[59] = { 0xB10BE924 }
_tbl[60] = { 0x2F6F7C87 }
_tbl[61] = { 0x58684C11 }
_tbl[62] = { 0xC1611DAB }
_tbl[63] = { 0xB6662D3D }
_tbl[64] = { 0x76DC4190 }
_tbl[65] = { 0x1DB7106 }
_tbl[66] = { 0x98D220BC }
_tbl[67] = { 0xEFD5102A }
_tbl[68] = { 0x71B18589 }
_tbl[69] = { 0x6B6B51F }
_tbl[70] = { 0x9FBFE4A5 }
_tbl[71] = { 0xE8B8D433 }
_tbl[72] = { 0x7807C9A2 }
_tbl[73] = { 0xF00F934 }
_tbl[74] = { 0x9609A88E }
_tbl[75] = { 0xE10E9818 }
_tbl[76] = { 0x7F6A0DBB }
_tbl[77] = { 0x86D3D2D }
_tbl[78] = { 0x91646C97 }
_tbl[79] = { 0xE6635C01 }
_tbl[80] = { 0x6B6B51F4 }
_tbl[81] = { 0x1C6C6162 }
_tbl[82] = { 0x856530D8 }
_tbl[83] = { 0xF262004E }
_tbl[84] = { 0x6C0695ED }
_tbl[85] = { 0x1B01A57B }
_tbl[86] = { 0x8208F4C1 }
_tbl[87] = { 0xF50FC457 }
_tbl[88] = { 0x65B0D9C6 }
_tbl[89] = { 0x12B7E950 }
_tbl[90] = { 0x8BBEB8EA }
_tbl[91] = { 0xFCB9887C }
_tbl[92] = { 0x62DD1DDF }
_tbl[93] = { 0x15DA2D49 }
_tbl[94] = { 0x8CD37CF3 }
_tbl[95] = { 0xFBD44C65 }
_tbl[96] = { 0x4DB26158 }
_tbl[97] = { 0x3AB551CE }
_tbl[98] = { 0xA3BC0074 }
_tbl[99] = { 0xD4BB30E2 }
_tbl[100] = { 0x4ADFA541 }
_tbl[101] = { 0x3DD895D7 }
_tbl[102] = { 0xA4D1C46D }
_tbl[103] = { 0xD3D6F4FB }
_tbl[104] = { 0x4369E96A }
_tbl[105] = { 0x346ED9FC }
_tbl[106] = { 0xAD678846 }
_tbl[107] = { 0xDA60B8D0 }
_tbl[108] = { 0x44042D73 }
_tbl[109] = { 0x33031DE5 }
_tbl[110] = { 0xAA0A4C5F }
_tbl[111] = { 0xDD0D7CC9 }
_tbl[112] = { 0x5005713C }
_tbl[113] = { 0x270241AA }
_tbl[114] = { 0xBE0B1010 }
_tbl[115] = { 0xC90C2086 }
_tbl[116] = { 0x5768B525 }
_tbl[117] = { 0x206F85B3 }
_tbl[118] = { 0xB966D409 }
_tbl[119] = { 0xCE61E49F }
_tbl[120] = { 0x5EDEF90E }
_tbl[121] = { 0x29D9C998 }
_tbl[122] = { 0xB0D09822 }
_tbl[123] = { 0xC7D7A8B4 }
_tbl[124] = { 0x59B33D17 }
_tbl[125] = { 0x2EB40D81 }
_tbl[126] = { 0xB7BD5C3B }
_tbl[127] = { 0xC0BA6CAD }
_tbl[128] = { 0xEDB88320 }
_tbl[129] = { 0x9ABFB3B6 }
_tbl[130] = { 0x3B6E20C }
_tbl[131] = { 0x74B1D29A }
_tbl[132] = { 0xEAD54739 }
_tbl[133] = { 0x9DD277AF }
_tbl[134] = { 0x4DB2615 }
_tbl[135] = { 0x73DC1683 }
_tbl[136] = { 0xE3630B12 }
_tbl[137] = { 0x94643B84 }
_tbl[138] = { 0xD6D6A3E }
_tbl[139] = { 0x7A6A5AA8 }
_tbl[140] = { 0xE40ECF0B }
_tbl[141] = { 0x9309FF9D }
_tbl[142] = { 0xA00AE27 }
_tbl[143] = { 0x7D079EB1 }
_tbl[144] = { 0xF00F9344 }
_tbl[145] = { 0x8708A3D2 }
_tbl[146] = { 0x1E01F268 }
_tbl[147] = { 0x6906C2FE }
_tbl[148] = { 0xF762575D }
_tbl[149] = { 0x806567CB }
_tbl[150] = { 0x196C3671 }
_tbl[151] = { 0x6E6B06E7 }
_tbl[152] = { 0xFED41B76 }
_tbl[153] = { 0x89D32BE0 }
_tbl[154] = { 0x10DA7A5A }
_tbl[155] = { 0x67DD4ACC }
_tbl[156] = { 0xF9B9DF6F }
_tbl[157] = { 0x8EBEEFF9 }
_tbl[158] = { 0x17B7BE43 }
_tbl[159] = { 0x60B08ED5 }
_tbl[160] = { 0xD6D6A3E8 }
_tbl[161] = { 0xA1D1937E }
_tbl[162] = { 0x38D8C2C4 }
_tbl[163] = { 0x4FDFF252 }
_tbl[164] = { 0xD1BB67F1 }
_tbl[165] = { 0xA6BC5767 }
_tbl[166] = { 0x3FB506DD }
_tbl[167] = { 0x48B2364B }
_tbl[168] = { 0xD80D2BDA }
_tbl[169] = { 0xAF0A1B4C }
_tbl[170] = { 0x36034AF6 }
_tbl[171] = { 0x41047A60 }
_tbl[172] = { 0xDF60EFC3 }
_tbl[173] = { 0xA867DF55 }
_tbl[174] = { 0x316E8EEF }
_tbl[175] = { 0x4669BE79 }
_tbl[176] = { 0xCB61B38C }
_tbl[177] = { 0xBC66831A }
_tbl[178] = { 0x256FD2A0 }
_tbl[179] = { 0x5268E236 }
_tbl[180] = { 0xCC0C7795 }
_tbl[181] = { 0xBB0B4703 }
_tbl[182] = { 0x220216B9 }
_tbl[183] = { 0x5505262F }
_tbl[184] = { 0xC5BA3BBE }
_tbl[185] = { 0xB2BD0B28 }
_tbl[186] = { 0x2BB45A92 }
_tbl[187] = { 0x5CB36A04 }
_tbl[188] = { 0xC2D7FFA7 }
_tbl[189] = { 0xB5D0CF31 }
_tbl[190] = { 0x2CD99E8B }
_tbl[191] = { 0x5BDEAE1D }
_tbl[192] = { 0x9B64C2B0 }
_tbl[193] = { 0xEC63F226 }
_tbl[194] = { 0x756AA39C }
_tbl[195] = { 0x26D930A }
_tbl[196] = { 0x9C0906A9 }
_tbl[197] = { 0xEB0E363F }
_tbl[198] = { 0x72076785 }
_tbl[199] = { 0x5005713 }
_tbl[200] = { 0x95BF4A82 }
_tbl[201] = { 0xE2B87A14 }
_tbl[202] = { 0x7BB12BAE }
_tbl[203] = { 0xCB61B38 }
_tbl[204] = { 0x92D28E9B }
_tbl[205] = { 0xE5D5BE0D }
_tbl[206] = { 0x7CDCEFB7 }
_tbl[207] = { 0xBDBDF21 }
_tbl[208] = { 0x86D3D2D4 }
_tbl[209] = { 0xF1D4E242 }
_tbl[210] = { 0x68DDB3F8 }
_tbl[211] = { 0x1FDA836E }
_tbl[212] = { 0x81BE16CD }
_tbl[213] = { 0xF6B9265B }
_tbl[214] = { 0x6FB077E1 }
_tbl[215] = { 0x18B74777 }
_tbl[216] = { 0x88085AE6 }
_tbl[217] = { 0xFF0F6A70 }
_tbl[218] = { 0x66063BCA }
_tbl[219] = { 0x11010B5C }
_tbl[220] = { 0x8F659EFF }
_tbl[221] = { 0xF862AE69 }
_tbl[222] = { 0x616BFFD3 }
_tbl[223] = { 0x166CCF45 }
_tbl[224] = { 0xA00AE278 }
_tbl[225] = { 0xD70DD2EE }
_tbl[226] = { 0x4E048354 }
_tbl[227] = { 0x3903B3C2 }
_tbl[228] = { 0xA7672661 }
_tbl[229] = { 0xD06016F7 }
_tbl[230] = { 0x4969474D }
_tbl[231] = { 0x3E6E77DB }
_tbl[232] = { 0xAED16A4A }
_tbl[233] = { 0xD9D65ADC }
_tbl[234] = { 0x40DF0B66 }
_tbl[235] = { 0x37D83BF0 }
_tbl[236] = { 0xA9BCAE53 }
_tbl[237] = { 0xDEBB9EC5 }
_tbl[238] = { 0x47B2CF7F }
_tbl[239] = { 0x30B5FFE9 }
_tbl[240] = { 0xBDBDF21C }
_tbl[241] = { 0xCABAC28A }
_tbl[242] = { 0x53B39330 }
_tbl[243] = { 0x24B4A3A6 }
_tbl[244] = { 0xBAD03605 }
_tbl[245] = { 0xCDD70693 }
_tbl[246] = { 0x54DE5729 }
_tbl[247] = { 0x23D967BF }
_tbl[248] = { 0xB3667A2E }
_tbl[249] = { 0xC4614AB8 }
_tbl[250] = { 0x5D681B02 }
_tbl[251] = { 0x2A6F2B94 }
_tbl[252] = { 0xB40BBE37 }
_tbl[253] = { 0xC30C8EA1 }
_tbl[254] = { 0x5A05DF1B }
_tbl[255] = { 0x2D02EF8D }


    -- Calculate it
    local ret = 0
    for i,item in pairs(data) do
        local tmp =  band(ret, 0xFF)
        local index = band( bxor(tmp, item), 0xFF)
        ret = bxor(rsh(ret,8), _tbl[index][1])
    end
    return ret
end
---
-- update checksum
-- called: data is string, ( >= 24 hex digits )
-- returns: string, (data concat new checksum)
local function updateChecksum(data)
    local part = data:sub(1,24)
    local chksum = calculateChecksum( utils.ConvertHexToBytes(part))
    return string.format("%s%X", part, chksum)
end
---
--
local function keygen(uid)
    local data = MIS..uid..BAR
    local hash = utils.ConvertAsciiToBytes(utils.Sha1Hex(data))
    return string.format("%02X%02X%02X%02X%02X%02X",
        hash[3+1],
        hash[2+1],
        hash[1+1],
        hash[0+1],
        hash[7+1],
        hash[6+1]
        )
end
--- encode 'table' into a json formatted string
--
local function convert_to_json( obj )
    if type(obj) == "table" then
        return json.encode (obj, { indent = true })
    end
    return oops('[fail] input object must be a lua-TABLE')
end
--
-- Save
local function save_json(filename, data)
    jsondata = convert_to_json(data)
    filename = filename or 'dumpdata.json'
    local f = io.open(filename, "w")
    if not f then return oops(string.format("Could not write to file %s", tostring(filename))) end
    f:write(jsondata)
    io.close(f)
    return filename
end
--- loads a json formatted text file with
--
-- @param filename the file containing the json-dump  (defaults to dumpdata.json)
local function load_json(filename)
    filename = filename or 'dumpdata.json'
    local f = io.open(filename, "rb")
    if not f then return oops(string.format("Could not read file %s", tostring(filename))) end

    -- Read file
    local t = f:read("*all")
    io.close(f)

    local obj, pos, err = json.decode(t, 1, nil)
    if err then return oops(string.format("importing json file failed. %s", err)) end

    dbg(string.format('loaded file %s', input))
    return obj

--  local len, hex = bin.unpack( ("H%d"):format(#t), t)
end
---
-- Generate encryption key
local function create_key(uid)
    local key = ''
    local sha = utils.Sha1Hex( FOO..BAR..uid )
    sha  = utils.ConvertBytesToHex( utils.ConvertAsciiToBytes(sha:sub(1,16)) )
    key = utils.SwapEndiannessStr( sha:sub(1,8) , 32 )
    key = key..utils.SwapEndiannessStr( sha:sub(9,16), 32 )
    key = key..utils.SwapEndiannessStr( sha:sub(17,24), 32 )
    key = key..utils.SwapEndiannessStr( sha:sub(25,32), 32 )
    return key
end
---
-- decode response and get the blockdata from a normal mifare read command
local function getblockdata(response)
    if not response then
        return nil, 'No response from device'
    end
    if response.Status == PM3_SUCCESS then
        return response.Data
    else
        return nil, "Couldn't read block.. ["..response.Status.."]"
    end
end

local function readblock( blockno, key )
    -- Read block N
    local keytype = '00'
    local data = ('%02x%s%s'):format(blockno, keytype, key)
    local c = Command:newNG{cmd = cmds.CMD_MIFARE_READBL, data = data}
    local b, err = getblockdata(c:sendNG(false))
    if not b then return oops(err) end
    return b
end
--- reads all blocks from tag
--
local function readtag(mfkey, aeskey )

    local tagdata = {}

    for blockNo = 0, numBlocks-1 do

        if core.ukbhit() then
            print("[fail] aborted by user")
            return nil
        end

        -- read block from tag.
        local blockdata = readblock(blockNo, mfkey)
        if not blockdata then return oops('[!] failed reading block') end

        -- rules:
        -- the following blocks is NOT encrypted
        -- block 0 (manufacturing) and 18
        -- block with all zeros
        -- sector trailor
        if blockNo == 0 or blockNo == 18 then

        elseif  blockNo%4 ~= 3 then

            if not string.find(blockdata, '^0+$') then
                if aeskey then
                    local decrypted, err = core.aes128_decrypt_ecb(aeskey, blockdata)
                    if err then dbg(err) end
                    blockdata  =  utils.ConvertAsciiToHex(decrypted)
                end
            end
        else
            -- Sectorblocks, not encrypted, but we add our known key to it since it is normally zeros.
            blockdata = mfkey..blockdata:sub(13,20)..mfkey
        end
        table.insert(tagdata, blockdata)
    end
    return tagdata
end
---
-- simple selftest of functionality
local function selftest()
    local testdata = '000F42430D0A14000001D11F'..'5D738517'
    local chksum = getChecksum(testdata)
    local calc = calculateChecksum( utils.ConvertHexToBytes(testdata:sub(1,24)))
    print (  testdata:sub(1,24) )
    print (  ('%x - %x'):format(chksum, calc))

    local isValid = false
    local validStr = "FAIL"
    if calc == chksum then
        isValid = true
        validStr = "OK"
    end
    local newtestdata = updateChecksum(testdata)
    local revalidated = "FAIL"
    if newtestdata == testdata then
        revalidated = "OK"
    end
    print  ('TESTDATA      :: '..testdata)
    print  ('DATA          :: '..testdata:sub(1,24))
    print (('VALID CHKSUM  :: %s'):format(validStr ))
    print (('UPDATE CHKSUM :: %s'):format(revalidated))

    local testkey = keygen('0456263a873a80')
    print ('TEST KEY       :: '..testkey)
    print ('VALID KEY      :: 29564af75805')
end
local function setdevicedebug( status )
    local c = 'hw dbg '
    if status then
        c = c..'1'
    else
        c = c..'0'
    end
    core.console(c)
end
---
-- The main entry point
-- -d decrypt
-- -e encrypt
-- -v validate
function main(args)

    local cmd, tag, err, blockNo, mfkey
    local shall_validate = false
    local shall_dec = false
    local shall_enc = false
    local blocks = {}
    local aeskey = ''
    local input = ''

    -- Read the parameters
    for o, a in getopt.getopt(args, 'htdevi:') do
        if o == 'h' then help() return end
        if o == 't' then return selftest() end
        if o == 'd' then shall_dec = true end
        if o == 'e' then shall_enc = true end
        if o == 'v' then shall_validate = true end
        if o == 'i' then input = load_json(a) end
    end

    -- Turn off Debug
    setdevicedebug(false)

    -- GET TAG UID
    tag, err = lib14a.read(false, true)
    if err then
        lib14a.disconnect()
        return oops(err)
    end
    core.clearCommandBuffer()

    -- simple tag check
    if 0x09 ~= tag.sak then
        if 0x4400 ~= tag.atqa then
            return oops(('[fail] found tag %s :: looking for Mifare Mini 0.3k'):format(tag.name))
        end
            end
    dbg ('[ok] found '..tag.name)

    -- tag key
    mfkey = keygen(tag.uid)
    dbg('[ok] using mf keyA : '.. mfkey)

    -- AES key
    aeskey = create_key(tag.uid)
    dbg('[ok] using AES key : '.. aeskey)

    -- read tag data, complete, enc/dec
    tagdata = readtag(mfkey, aeskey)
    dbg('[ok] read card data')

    -- show information?
    print_info(tagdata)

    -- save
    res = save_json(nil, tagdata)
    if not res then return oops('[fail] saving json file') end

    dbg('[ok] read card data')
end

main(args)
