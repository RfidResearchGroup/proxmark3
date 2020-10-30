local bin = require('bin')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.2'
desc = [[
This script calculates mifare keys based on uid diversification for mizip.
Algo not found by me.
]]
example = [[
     -- if called without, it reads tag uid
     script run hf_mf_uidkeycalc-mizip

     --
     script run hf_mf_uidkeycalc-mizip -u 11223344
]]
usage = [[
script run hf_mf_uidkeycalc-mizip -h -u <uid>
]]
arguments = [[
    -h             : this help
    -u <UID>       : UID
]]
local DEBUG = true
local bxor = bit32.bxor
local _xortable = {
    --[[ sector key A/B, 6byte xor
    --]]
    {1, '09125a2589e5', 'F12C8453D821'},
    {2, 'AB75C937922F', '73E799FE3241'},
    {3, 'E27241AF2C09', 'AA4D137656AE'},
    {4, '317AB72F4490', 'B01327272DFD'},
}
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
--
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
--
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
-- key bytes to string
local function keyStr(p1, p2, p3, p4, p5, p6)
    return string.format('%02X%02X%02X%02X%02X%02X',p1, p2, p3, p4, p5, p6)
end
---
-- create key
local function calckey(uid, xorkey, keytype)
    local p1,p2,p3,p4,p5,p6
    if keytype == 'A' then
        p1 = bxor( uid[1], xorkey[1])
        p2 = bxor( uid[2], xorkey[2])
        p3 = bxor( uid[3], xorkey[3])
        p4 = bxor( uid[4], xorkey[4])
        p5 = bxor( uid[1], xorkey[5])
        p6 = bxor( uid[2], xorkey[6])
    else
        p1 = bxor( uid[3], xorkey[1])
        p2 = bxor( uid[4], xorkey[2])
        p3 = bxor( uid[1], xorkey[3])
        p4 = bxor( uid[2], xorkey[4])
        p5 = bxor( uid[3], xorkey[5])
        p6 = bxor( uid[4], xorkey[6])
    end
    return keyStr(p1,p2,p3,p4,p5,p6)
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
-- create a full set of keys
local function createKeys(uid)
    local uidbytes = utils.ConvertHexToBytes(uid)

    local k = {}
    k[0] = { keyStr(0xA0,0xA1,0xA2,0xA3,0xA4,0xA5), keyStr(0xB4,0xC1,0x32,0x43,0x9e,0xef) }

    for _, v in pairs(_xortable) do
        local keyA = calckey(uidbytes, utils.ConvertHexToBytes(v[2]), 'A')
        local keyB = calckey(uidbytes, utils.ConvertHexToBytes(v[3]), 'B')
        k[v[1]] = { keyA, keyB }
    end
    return k
end
---
-- main
local function main(args)

    print( string.rep('==', 30) )
    print()

    local uid = '11223344'
    local useUID = false

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hu:') do
        if o == 'h' then return help() end
        if o == 'u' then uid = a ; useUID = true end
    end

    if useUID then
        -- uid string checks
        if uid == nil then return oops('empty uid string') end
        if #uid == 0 then return oops('empty uid string') end
        if #uid ~= 8 then return oops('uid wrong length. Should be 4 hex bytes') end
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
