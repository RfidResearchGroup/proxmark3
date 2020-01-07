local bin = require('bin')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')

copyright = ''
author = "Iceman"
version = 'v1.0.0'
desc = [[
This script calculates mifare keys based on uid diversification for DI.
Algo not found by me.
]]
example = [[
     -- if called without, it reads tag uid
     script run calc_di

     --
     script run calc_di -u 11223344556677
]]
usage = [[
script run calc_di -h -u <uid>

Arguments:
    -h             : this help
    -u <UID>       : UID
]]

local DEBUG = true
local BAR = '286329204469736E65792032303133'
local MIS = '0A14FD0507FF4BCD026BA83F0A3B89A9'
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
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
---
-- dumps all keys to file
local function dumptofile(uid, keys)
    dbg('dumping keys to file')

    if utils.confirm('Do you wish to save the keys to dumpfile?') then

        local filename = ('hf-mf-%s-key.bin'):format(uid);

        local destination = utils.input('Select a filename to store to', filename)
        local file = io.open(destination, 'wb')
        if file == nil then
            print('Could not write to file ', destination)
            return
        end

        -- Mifare Mini has 5 sectors,
        local key_a = ''
        local key_b = ''

        for sector = 0, #keys do
            local keyA, keyB = unpack(keys[sector])
            key_a = key_a .. bin.pack('H', keyA);
            key_b = key_b .. bin.pack('H', keyB);
        end
        file:write(key_a)
        file:write(key_b)
        file:close()
    end
end
---
-- create key
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
---
-- print keys
local function printKeys(keys)
    print('|---|----------------|---|----------------|---|')
    print('|sec|key A           |res|key B           |res|')
    print('|---|----------------|---|----------------|---|')
    for sector = 0, #keys do
        local keyA, keyB = unpack(keys[sector])
        print(('|%03d|  %s  | %s |  %s  | %s |'):format(sector, keyA, 1, keyB, 1))
    end
    print('|---|----------------|---|----------------|---|')
end
---
-- createfull set of keys
local function createKeys(uid)
    local key = keygen(uid)
    local k = {}
    for i = 0,4 do
        k[i] = { key, key }
    end
    return k
end
---
-- main
local function main(args)

    print( string.rep('==', 30) )
    print()

    local uid
    local useUID = false

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hu:') do
        if o == 'h' then return help() end
        if o == 'u' then uid = a; useUID = true end
    end

    if useUID then
        -- uid string checks if supplied
        if uid == nil then return oops('empty uid string') end
        if #uid == 0 then return oops('empty uid string') end
        if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end
    else
        -- GET TAG UID
        local tag, err = lib14a.read(false, true)
        if not tag then return oops(err) end
        core.clearCommandBuffer()

        -- simple tag check
        if 0x09 ~= tag.sak then
            if 0x4400 ~= tag.atqa then
                return oops(('[!] found tag %s :: looking for Mifare Mini 0.3k'):format(tag.name))
            end
        end
        uid = tag.uid
    end

    print('|UID|', uid)

    local keys, err = createKeys( uid )
    printKeys( keys )
    dumptofile( uid, keys )
end

main(args)
