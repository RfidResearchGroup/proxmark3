local getopt = require('getopt')
local utils =  require('utils')

copyright = ''
author = "Iceman"
version = 'v1.0.1'
desc = [[
This script tries to set UID on a mifare Ultralight magic card which either
 - answers to chinese backdoor commands
 - brickable magic tag  (must write in one session)
]]
example = [[
     -- backdoor magic tag
     script run ul_uid -u 11223344556677

     -- brickable magic tag
     script run ul_uid -b -u 11223344556677
]]
usage = [[
script run ul_uid -h -b -u <uid>

Arguments:
    -h             : this help
    -u <UID>       : UID (14 hexsymbols)
    -b             : write to brickable magic tag
]]

local DEBUG = true
local bxor = bit32.bxor
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
--
--- Set UID on magic command enabled
function magicUID(b0, b1, b2)

    print('Using backdoor Magic tag function')

    -- write block 0
    core.console('hf 14a raw -p -a -b 7 40')
    core.console('hf 14a raw -p -a 43')
    core.console('hf 14a raw -c -a A200'..b0)

    -- write block 1
    core.console('hf 14a raw -p -a -b 7 40')
    core.console('hf 14a raw -p -a 43')
    core.console('hf 14a raw -c -a A201'..b1)

    -- write block 2
    core.console('hf 14a raw -p -a -b 7 40')
    core.console('hf 14a raw -p -a 43')
    core.console('hf 14a raw -c -a A202'..b2)
end
--
--- Set UID on magic but brickable
function brickableUID(b0, b1, b2)

    print('Using BRICKABLE Magic tag function')

    core.console('hf 14a raw -p -s -3')

    -- write block 0
    core.console('hf 14a raw -p -c A200'..b0)

    -- write block 1
    core.console('hf 14a raw -p -c A201'..b1)

    -- write block 2
    core.console('hf 14a raw -p -c A202'..b2)
end
---
-- The main entry point
function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local uid = '04112233445566'
    local tagtype = 1

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hu:b') do
        if o == 'h' then return help() end
        if o == 'u' then uid = a end
        if o == 'b' then tagtype = 2 end
    end

    -- uid string checks
    if uid == nil then return oops('empty uid string') end
    if #uid == 0 then return oops('empty uid string') end
    if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end

    local uidbytes = utils.ConvertHexToBytes(uid)

    local bcc1 = bxor(0x88, uidbytes[1], uidbytes[2], uidbytes[3])
    local bcc2 = bxor(uidbytes[4], uidbytes[5], uidbytes[6], uidbytes[7])

    local block0 = string.format('%02X%02X%02X%02X', uidbytes[1], uidbytes[2], uidbytes[3], bcc1)
    local block1 = string.format('%02X%02X%02X%02X', uidbytes[4], uidbytes[5], uidbytes[6], uidbytes[7])
    local block2 = string.format('%02X%02X%02X%02X', bcc2, 0x48, 0x00, 0x00)

    print('new UID | '..uid)

    core.clearCommandBuffer()

    if tagtype == 2 then
        brickableUID(block0, block1, block2)
    else
        magicUID(block0, block1, block2)
    end

        --halt
    core.console('hf 14a raw -c -a 5000')
end

main(args)
