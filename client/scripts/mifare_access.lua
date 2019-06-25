local getopt = require('getopt')

copyright = ''
author = "Neuromancer"
version = 'v1.0.1'
desc = [[
This script tries to decode Mifare Classic Access bytes
]]
example = [[
    1. script run mifare_access -a 7F0F0869
]]
usage = [[
script run mifare_access -h -a <access bytes>

Arguments:
    -h                   : this help
    -a <access bytes>    : 4 bytes ACCESS CONDITIONS
]]

local DEBUG = true
local bxor = bit32.bxor
local band = bit32.band
local rshift = bit32.rshift

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

local access_condition_sector_trailer = {}
access_condition_sector_trailer[0x0] = {'never','key A','key A','never','key A','key A'}
access_condition_sector_trailer[0x2] = {'never','never','key A','never','key A','never'}
access_condition_sector_trailer[0x4] = {'never','key B','key A|B','never','never','key B'}
access_condition_sector_trailer[0x6] = {'never','never','key A|B','never','never','never'}
access_condition_sector_trailer[0x1] = {'never','key A','key A','key A','key A','key A'}
access_condition_sector_trailer[0x3] = {'never','key B','key A|B','key B','never','key B'}
access_condition_sector_trailer[0x5] = {'never','never','key A|B','key B','never','never'}
access_condition_sector_trailer[0x7] = {'never','never','key A|B','never','never','never'}

local access_condition_data_block = {}
access_condition_data_block[0x0] = {'key A|B','key A|B','key A|B','key A|B'}
access_condition_data_block[0x2] = {'key A|B','never','never','never'}
access_condition_data_block[0x4] = {'key A|B','key B','never','never'}
access_condition_data_block[0x6] = {'key A|B','key B','key B','key A|B'}
access_condition_data_block[0x1] = {'key A|B','never','never','key A|B'}
access_condition_data_block[0x3] = {'key B','key B','never','never'}
access_condition_data_block[0x5] = {'key B','never','never','never'}
access_condition_data_block[0x7] = {'never','never','never','never'}

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local access = ''

    -- Read the parameters
    for o, a in getopt.getopt(args, 'ha:') do
        if o == 'h' then return help() end
        if o == 'a' then access = a end
    end

    if access == nil then return oops('empty ACCESS CONDITIONS') end
    if #access == 0 then return oops('empty ACCESS CONDITIONS') end
    if #access ~= 8 then return oops('Wrong length. Should be 4 hex bytes ACCESS CONDITIONS (e.g. 7F0F0869)') end

    local c2_b = tonumber(string.sub(access, 1, 1), 16)
    local c1_b = tonumber(string.sub(access, 2, 2), 16)
    local c1 = tonumber(string.sub(access, 3, 3), 16)
    local c3_b = tonumber(string.sub(access, 4, 4), 16)
    local c3 = tonumber(string.sub(access, 5, 5), 16)
    local c2 = tonumber(string.sub(access, 6, 6), 16)
    local gpb = string.sub(access, 7, 8)

    if bxor(c1, c1_b) ~= 0xF then print('!!! bitflip in c1') end
    if bxor(c2, c2_b) ~= 0xF then print('!!! bitflip in c2') end
    if bxor(c3, c3_b) ~= 0xF then print('!!! bitflip in c3') end

    local ab = c1 * 256 + c2 * 16 + c3

    for block = 0,3 do
        print('--> block '..block)
        -- mask bits for block
        local abi = band(rshift(ab, block), 0x111)
        -- compress bits
        abi = band(abi + rshift(abi, 3) + rshift(abi, 6),7)
        -- print(abi)
        if block == 3 then
            print('     KEYSECXA read: '..access_condition_sector_trailer[abi][1])
            print('    KEYSECXA write: '..access_condition_sector_trailer[abi][2])
            print(' ACCESS COND. read: '..access_condition_sector_trailer[abi][3])
            print('ACCESS COND. write: '..access_condition_sector_trailer[abi][4])
            print('     KEYSECXB read: '..access_condition_sector_trailer[abi][5])
            print('    KEYSECXB write: '..access_condition_sector_trailer[abi][6])
        else
            print('                   read: '..access_condition_data_block[abi][1])
            print('                  write: '..access_condition_data_block[abi][2])
            print('                    inc: '..access_condition_data_block[abi][3])
            print('decr, transfer, restore: '..access_condition_data_block[abi][4])
        end
    end

    print('GPB: '..gpb)
end
main(args)
