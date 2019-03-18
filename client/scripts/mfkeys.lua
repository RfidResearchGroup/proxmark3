--[[
    This is an example of Lua-scripting within proxmark3. This is a lua-side
    implementation of hf mf chk

    This code is licensed to you under the terms of the GNU GPL, version 2 or,
    at your option, any later version. See the LICENSE.txt file for the text of
    the license.

    Copyright (C) 2013 m h swende <martin at swende.se>
--]]
-- Loads the commands-library
local cmds = require('commands')
-- Load the default keys
local keylist = require('mf_default_keys')
-- Ability to read what card is there
local lib14a = require('read14a')
local getopt = require('getopt')
-- Asks the user for input
local utils = require('utils')

example =[[
     script run mfkeys
]]
author = "Holiman"
usage = "script run mfkeys"
desc = ("This script implements Mifare check keys.\
It utilises a large list of default keys (currently %d keys).\
If you want to add more, just put them inside /lualibs/mf_default_keys.lua\n"):format(#keylist) ..
[[

Arguments:
    -h             : this help
    -p             : print keys
]]

local TIMEOUT = 10000 -- 10 seconds
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR: ',err)
    return nil,err
end
---
-- Usage help
local function help()
    print(desc)
    print("Example usage")
    print(example)
end
--
-- waits for answer from pm3 device
local function checkCommand(command)
    core.clearCommandBuffer()
    local usb = command:getBytes()
    core.SendCommand(usb)
    local result = core.WaitForResponseTimeout(cmds.CMD_ACK, TIMEOUT)
    if result then
        local count, cmd, arg0 = bin.unpack('LL',result)
        if(arg0==1) then
            local count, arg1, arg2, data = bin.unpack('LLH511',result,count)
            key = data:sub(1,12)
            return key
        else
            return nil
        end
    else
        print("Timeout while waiting for response. Increase TIMEOUT in mfkeys.lua to wait longer")
        return nil, "Timeout while waiting for device to respond"
    end
end

local function checkBlock(blockno, testkeys, keytype)

    -- The command data is only 512 bytes, each key is 6 bytes, meaning that we can send max 85 keys in one go.
    -- If there's more, we need to split it up
    local arg1 = bit32.bor(bit32.lshift(keytype, 8), blockno)

    local start, remaining = 1, #testkeys
    local chunksize = remaining
    if remaining > 85 then chunksize = 85 end
    local n = chunksize

    while remaining > 0 do
        --print('start', start, 'chunksize', chunksize, 'testkeys kvar', remaining, 'N-index=', n)

        local d1 = table.concat(testkeys, "", start, n)

        print(("Testing block %d, keytype %d, with %d keys"):format(blockno, keytype, chunksize))
        local command = Command:new{cmd = cmds.CMD_MIFARE_CHKKEYS,
                                arg1 =  arg1,
                                arg2 = 0,
                                arg3 = chunksize,
                                data = d1}
        local status = checkCommand(command)
        if status then return status, blockno end
        start = start + chunksize
        remaining = remaining - chunksize

        if remaining < 85 then chunksize = remaining end
        n = n + chunksize
    end
    return nil
end

-- A function to display the results
local function display_results(keys)
    local sector, keyA, keyB, succA, succB
    print('')
    print('|---|----------------|---|----------------|---|')
    print('|sec|key A           |res|key B           |res|')
    print('|---|----------------|---|----------------|---|')

    for sector = 0, #keys do
        succA, succB, keyA, keyB = unpack(keys[sector])
        print(('|%03d|  %s  | %s |  %s  | %s |'):format(sector, keyA, succA, keyB, succB))
    end
    print('|---|----------------|---|----------------|---|')
end
-- A little helper to place an item first in the list
local function placeFirst(akey, list)
    akey = akey:lower()
    if list[1] == akey then
        -- Already at pole position
        return list
    end
    local result = {akey}
    --print(("Putting '%s' first"):format(akey))
    for i,v in ipairs(list) do
        if v ~= akey then
            result[#result+1] = v
        end
    end
    return result
end
--[[
The mifare Classic 1k card has 16 sectors of 4 data blocks each.
The first 32 sectors of a mifare Classic 4k card consists of 4 data blocks and the remaining
8 sectors consist of 16 data blocks.
--]]
local function get_blockno(s)

    local b, sector

    if type(s) == 'string' then
        sector = tonumber(s)
    else
        sector = s
    end

    if sector < 32 then
        b = sector * 4
    else
        b = 32 * 4 + (sector - 32) * 16
end
    return ('%02x'):format(b)
end
--
-- dumps all keys to file
local function dumptofile(keys)
    if utils.confirm('Do you wish to save the keys to dumpfile?') then
        local destination = utils.input('Select a filename to store to', 'dumpkeys.bin')
        local file = io.open(destination, 'wb')
        if file == nil then
            print('Could not write to file ', destination)
            return
        end

        local key_a = ''
        local key_b = ''

        --for sector,_ in pairs(keys) do
        for sector = 0, #keys do
            local succA, succB, keyA, keyB = unpack(keys[sector])
            key_a = key_a .. bin.pack('H', keyA);
            key_b = key_b .. bin.pack('H', keyB);
        end
        file:write(key_a)
        file:write(key_b)
        file:close()
    end
end
local function printkeys()
    for i=1, #keylist do
        print(i, keylist[i])
    end
    print ('Number of keys: '..#keylist)
end
local function perform_check(numsectors)

    local keyType = 0 -- A=0, B=1

    -- empty list of found keys
    local keys = {}
    for i = 0, numsectors-1 do
        keys[i] = {0,0,'',''}
    end

    for sector = 0, #keys do
        -- Check if user aborted
        if core.ukbhit() then
            print('Aborted by user')
            break
        end

        local targetblock = tonumber(get_blockno(sector), 16)

        local succA, succB, keyA, keyB = unpack(keys[sector])

        local keyA = checkBlock(targetblock, keylist, 0)
        if keyA then succA = 1; keylist = placeFirst(keyA, keylist) end
        keyA = keyA or '------------'

        local keyB = checkBlock(targetblock, keylist, 1)
        if keyB then succB = 1; keylist = placeFirst(keyB, keylist) end
        keyB = keyB or '------------'

        keys[sector] = {succA, succB, keyA, keyB}
    end

    display_results(keys)

    -- save to dumpkeys.bin
    dumptofile(keys)
end
--
-- shows tag information
local function taginfo(tag)

    local sectors = 16
    -- Show tag info
    print((' Found tag %s'):format(tag.name))

    if 0x18 == tag.sak then --NXP MIFARE Classic 4k | Plus 4k
        -- MIFARE Classic 4K offers 4096 bytes split into forty sectors,
        -- of which 32 are same size as in the 1K with eight more that are quadruple size sectors.
        sectors = 40
    elseif 0x08 == tag.sak then -- NXP MIFARE CLASSIC 1k | Plus 2k
        -- 1K offers 1024 bytes of data storage, split into 16 sector
        sectors = 16
    elseif 0x09 == tag.sak then -- NXP MIFARE Mini 0.3k
        -- MIFARE Classic mini offers 320 bytes split into five sectors.
        sectors = 5
    elseif  0x10 == tag.sak then-- "NXP MIFARE Plus 2k"
        sectors = 32
    else
        print("I don't know how many sectors there are on this type of card, defaulting to 16")
    end
    return sectors
end
---
-- The main entry point
local function main(args)

    local start_time = os.time()
    local numSectors = 16

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hp') do
        if o == "h" then return help() end
        if o == "p" then return printkeys() end
    end
    -- identify tag
    tag, err = lib14a.read(false, true)
    if not tag then return oops(err) end

    -- detect sectors and print taginfo
    numsectors = taginfo(tag)

    perform_check(numsectors)

    local end_time = os.time()
    print('mfkeys - Total execution time: '..os.difftime(end_time, start_time)..' sec')
end

main( args)
