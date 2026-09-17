local cmds = require('commands')
local getopt = require('getopt')
local utils = require('utils')
local json = require('dkjson')
local ac = require('ansicolors')

copyright = ''
author = "Christian Herrmann"
version = 'v1.0.1'
desc = [[
This script loads a json format file,  with the field "data" and a hexbyte array of data. Ie t55x7 dump,
it tries to identify which system based on block1,  and detect block0 settings.
The script returns a file with the new identification added, in json format.  The output is save in 'dumpdata.json'
]]
example = [[
    script run lf_ident_json -i lf_t55xx.json
]]
usage = [[
script run lf_ident_json.lua [-h] [-c] [-p password] [-s <start cn>] [-v]
]]
arguments = [[
    -h      : this help
    -i      : infile ( .json format )

    ]]

-- Some globals
local DEBUG = false

string.startswith = function(self, str)
    return self:find('^' .. str) ~= nil
end

---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, errr
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ac.cyan..'Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'Arguments'..ac.reset)
    print(arguments)
    print(ac.cyan..'Example usage'..ac.reset)
    print(example)
end
---
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

--- loads a json formatted text file with
--
-- @param input the file containing the json-dump  (defaults to dumpdata.json)
local function load_json(input)
    input = input or 'dumpdata.json'
    local infile = io.open(input, "rb")
    if not infile then return oops(string.format("Could not read file %s", tostring(input)))    end

    -- Read file
    local t = infile:read("*all")
    io.close(infile)

    local obj, pos, err = json.decode(t, 1, nil)
    if err then return oops(string.format("importing json file failed. %s", err)) end

    print(string.format('loaded file %s', input))
    return obj
end
--
-- Save
local function save_json(data, filename)
    filename = filename or 'dumpdata.json'
    local outfile = io.open(filename, "w")
    if not outfile then return oops(string.format("Could not write to file %s", tostring(filename))) end
    outfile:write(data)
    io.close(outfile)
    return filename
end

local function encode(blocks)
    return json.encode (blocks, { indent = true })
end
--
-- map config blocks
local function getDefault(block0)

    block0 = block0:upper()

    local T55X7_DEFAULT_CONFIG_BLOCK    =   '000880E8' --// compat mode, RF/32, manchester, STT, 7 data blocks
    local T55X7_RAW_CONFIG_BLOCK        =   '000880E0' --// compat mode, RF/32, manchester, 7 data blocks
    local T55X7_EM_UNIQUE_CONFIG_BLOCK  =   '00148040' --// emulate em4x02/unique - compat mode, manchester, RF/64, 2 data blocks
    -- FDXB requires data inversion and BiPhase 57 is simply BipHase 50 inverted, so we can either do it using the modulation scheme or the inversion flag
    -- we've done both below to prove that it works either way, and the modulation value for BiPhase 50 in the Atmel data sheet of binary "10001" (17) is a typo,
    -- and it should actually be "10000" (16)
    --local T55X7_FDXB_CONFIG_BLOCK         903F8080  // emulate fdx-b - xtended mode, biPhase ('57), RF/32, 4 data blocks
    local T55X7_FDXB_CONFIG_BLOCK       =   '903F0082' --// emulate fdx-b - xtended mode, biPhase ('50), invert data, RF/32, 4 data blocks
    local T55X7_HID_26_CONFIG_BLOCK     =   '00107060' --// hid 26 bit - compat mode, FSK2a, RF/50, 3 data blocks
    local T55X7_PYRAMID_CONFIG_BLOCK    =   '00107080' --// Pyramid 26 bit - compat mode, FSK2a, RF/50, 4 data blocks
    local T55X7_INDALA_64_CONFIG_BLOCK  =   '00081040' --// emulate indala 64 bit - compat mode, PSK1, psk carrier FC * 2, RF/32, 2 data block
    local T55X7_INDALA_224_CONFIG_BLOCK  =  '000810E0' --// emulate indala 224 bit - compat mode, PSK1, psk carrier FC * 2, RF/32, 7 data block
    local T55X7_GUARDPROXII_CONFIG_BLOCK =  '00150060' --// Direct modulation, Biphase, RF/64, 3 data blocks
    local T55X7_VIKING_CONFIG_BLOCK     =   '00088040' --// compat mode, manchester, RF/32, 2 data blocks
    local T55X7_NORALYS_CONFIG_BLOCK    =   '00088C6A' --// NORALYS (KCP3000) -- compat mode, manchester, inverse, RF/32, STT, 3 data blocks
    local T55X7_IOPROX_CONFIG_BLOCK     =   '00147040' --// HID FSK2a, RF/64, 2 data blocks
    local T55X7_PRESCO_CONFIG_BLOCK     =   '00088088' --// manchester, RF/32, STT, 5 data blocks
    local T5555_DEFAULT_CONFIG_BLOCK    =   '6001F004' --// ask, manchester, RF/64, 2 data blocks?
    local T55X7_STARPROX                =   '00088C42' --// manchester, inverse, RF/32, 2 data blocks
    local T55X7_VISA2K_CONFIG_BLOCK     =   '00148068' --// VISA2000 - manchester, RF/64, STT, 3 data blocks
    local T55X7_SECURAKEY_CONFIG_BLOCK  =   'F00C8060' --// Securakey - manchester, RF/40, 3 data blocks
    local T55X7_ST = 'F0088058' --// manchester, RF/32, STT, pwd, 2 data blocks


    if block0 == T55X7_DEFAULT_CONFIG_BLOCK then return 'T55X7_DEFAULT_CONFIG_BLOCK :: compat mode, manchester, RF/32, STT, 7 data blocks'
    elseif block0 == T55X7_RAW_CONFIG_BLOCK then return 'T55X7_RAW_CONFIG_BLOCK :: compat mode, manchester, RF/32, 7 data blocks'
    elseif block0 == T55X7_EM_UNIQUE_CONFIG_BLOCK then return 'T55X7_EM_UNIQUE_CONFIG_BLOCK :: emulate em4x02/unique - compat mode, manchester, RF/64, 2 data blocks'
    elseif block0 == T55X7_FDXB_CONFIG_BLOCK then return 'T55X7_FDXB_CONFIG_BLOCK :: emulate fdx-b - xtended mode, BiPhase (50, invert data, RF/32, 4 data blocks'
    elseif block0 == T55X7_PYRAMID_CONFIG_BLOCK then return 'T55X7_PYRAMID_CONFIG_BLOCK ::  Pyramid 26 bit - compat mode, FSK2a, RF/50, 4 data blocks'
    elseif block0 == T55X7_HID_26_CONFIG_BLOCK then return 'T55X7_HID_26_CONFIG_BLOCK :: hid 26 bit - compat mode, FSK2a, RF/50, 3 data blocks'
    elseif block0 == T55X7_INDALA_64_CONFIG_BLOCK then return 'T55X7_INDALA_64_CONFIG_BLOCK :: emulate indala 64 bit - compat mode, PSK1, psk carrier FC * 2, RF/32, 2 data blocks'
    elseif block0 == T55X7_INDALA_224_CONFIG_BLOCK then return 'T55X7_INDALA_224_CONFIG_BLOCK :: emulate indala 224 bit - compat mode, PSK1, psk carrier FC * 2, RF/32, 7 data blocks'
    elseif block0 == T55X7_GUARDPROXII_CONFIG_BLOCK then return 'T55X7_GUARDPROXII_CONFIG_BLOCK ::  biphase, direct modulation, RF/64, 3 data blocks'
    elseif block0 == T55X7_VIKING_CONFIG_BLOCK then return 'T55X7_VIKING_CONFIG_BLOCK :: compat mode, manchester, RF/32, 2 data blocks'
    elseif block0 == T55X7_NORALYS_CONFIG_BLOCK then return 'T55X7_NORALYS_CONFIG_BLOCK :: NORALYS (KCP3000) -- compat mode, manchester, inverse, RF/32, STT, 3 data blocks'
    elseif block0 == T55X7_IOPROX_CONFIG_BLOCK then return 'T55X7_IOPROX_CONFIG_BLOCK :: HID FSK2a, RF/64, 2 data blocks'
    elseif block0 == T55X7_PRESCO_CONFIG_BLOCK then return 'T55X7_PRESCO_CONFIG_BLOCK :: manchester, RF/32, STT, 5 data blocks'
    elseif block0 == T5555_DEFAULT_CONFIG_BLOCK then return 'T5555_DEFAULT_CONFIG_BLOCK :: ask, manchester, RF/64, 2 data blocks?'
    elseif block0 == T55X7_STARPROX then return 'T55X7_STARPROX :: manchester, inverse, RF/32, 2 data blocks'
    elseif block0 == T55X7_VISA2K_CONFIG_BLOCK then return 'T55X7_VISA2K_CONFIG_BLOCK :: manchester, RF/64, STT, 3 data blocks'
    elseif block0 == T55X7_SECURAKEY_CONFIG_BLOCK then return 'T55X7_SECURAKEY_CONFIG_BLOCK :: manchester, RF/40, 3 data blocks'
    else return 'unknown configblock'..'  '..block0
    end

end
--
-- map first block0 with name
local function getConfigBlock(block)

    block = block:lower()
    local result = nil

    if block:startswith("f20000") then
        return '00088C42', 'Card is a Viking / Starprox'
    end
    if block:startswith('9522') then
        return '00088048', 'Card is an unknown badge'
    end
    if  block:startswith('56495332') then
        return '00148068', 'Card is VISA2000'
    end
    if  block:startswith('1d555955') then
        return '00107060', 'Card is HID Prox, (Prastel MTAG, sold by ABMatic)'
    end
    if  block:startswith('bb0214ff') or  block:startswith('bb0314ff') then
        return '00088C6A', 'Card is Noralsy Blue, KCP3000'
    end
    --#If the block starts with ff8/9/a/b/c
    if block:find('^(ff[8-9a-c])') then
        dbg('#This is a regular EM 410 tag, using a FF pattern (from FF8 to FFF)')
        dbg('#Covering from tag 1 to tag id 9FFFFFFFFF')
        return '00148040', 'Old rectangular Noralsy'
    end
    if  block:startswith('011db') then
        return '00107060', 'Card is AWID'
    end
    if block:startswith('f98c7038') then
        return '00150060', 'Card is Guard All/ verex'
    end
    if block:startswith('ffff0000') then
        return '00158040', 'Card is Jablotron'
    end
    if  block:startswith('10d00000') then
        return '00088088', 'Card is Presco'
    end
    if  block:startswith('00010101') then
        return '00107080', 'Card is Pyramid'
    end

    return result, 'unknown tag'
end

--
-- The main entry point
function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end


    local lines
    local out = {}
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hi:') do
        if o == "h" then return help() end
        if o == "i" then lines = load_json(a) end
    end

    --for i = 1, #data do
    for _,i in pairs(lines) do

        local index = 0
        local one = {}
        for ix = 1, #i.data, 8 do
            one['blk_'..index] = i.data:sub(ix,ix+7)
            index = index + 1
        end

        local mconf, msg = getConfigBlock(one["blk_1"])
        one["identification"] =  msg
        one["config_desc"] = getDefault(one["blk_0"])

        if msg:find('badge') then
            print (msg, i.data)
        end
        table.insert(out, one)
    end
    save_json( encode(out) , nil)
end

main(args)
