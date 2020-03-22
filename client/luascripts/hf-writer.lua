local utils = require('utils')
local getopt = require('getopt')
local read14a = require('read14a')

--[[
---Suggestions of improvement:
--- Add support another types of dumps: BIN, JSON
--- Maybe it will be not only as `mfc_gen3_writer`, like a universal dump manager.
--- Add undependence from the operation system. At the moment code not working in Linux.
--- Add more chinesse backdoors RAW commands for UID changing (find RAW for the 4 byte familiar chinese card, from native it soft: http://bit.ly/39VIDsU)
--- Hide system messages when you writing a dumps, replace it to some of like [#####----------] 40%

-- iceman notes:
--  doesn't take consideration filepaths for dump files.
--  doesn't allow A keys for authenticating when writing
--  doesn't verify that card is magic gen3.
--  doesn't take several versions of same dump ( -1, -2, -3 ) styles.
--]]

copyright = ''
author = 'Winds'
version = 'v1.0.0'
desc = [[
    The script gives you a easy way to write your *.eml dumps onto normal MFC and magic Gen3 cards.

    Works with both 4 and 7 bytes NXP MIFARE Classic 1K cards.
    The script also has the possibility to change UID and permanent lock uid on magic Gen3 cards.
    
    It supports the following functionality.

    1. Write it to the same  of current card UID.
    2. Write it to magic Gen3 card.
    3. Change uid to match dump on magic Gen3 card.
    4. Permanent lock UID on magic Gen3 card.
    5. Erase all data at the card and set the FF FF FF FF FF FF keys, and Access Conditions to 78778800.
    
    Script works in a wizard styled way.
]]
example = [[
    1. script run mfc_gen3_writer
]]
usage = [[
    Select your *.eml dump from list to write to the card.
]]

-- Some globals
local DEBUG = false -- the debug flag

-------------------------------
-- Some utilities
-------------------------------

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
---
-- GetUID
local function GetUID()
    return read14a.read(true, true).uid
end
---
-- 
local function dropfield()
    read14a.disconnect()
    core.clearCommandBuffer()
end
---
-- Wait for tag (MFC)
local function wait()
    read14a.waitFor14443a()
end
---
--
local function main(args)

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hd') do
        if o == 'h' then return help() end
        if o == 'd' then DEBUG = true end
    end

    local files = {} -- Array for eml files
    local b_keys = {} -- Array for B keys
    local eml = {} -- Array for data in block 32
    local num_dumps = 0 -- num of found eml dump files

    local tab = string.rep('-', 64)
    --
    wait()
    print(tab)

    local length = 25
    local e = 16
    -- Detect 7 byte card
    if string.len(GetUID()) == 14 then
        length = 40
        e = 31
    end 
    dropfield()

    ---List all EML files in /client
    local dumpEML = 'find "." "*dump.eml"'
    local p = assert(io.popen(dumpEML))    
    for _ in p:lines() do
        -- The length of eml file
        if string.len(_) == length then 
            num_dumps = num_dumps + 1
             -- cut UID from eml file
            files[num_dumps] = string.sub(_, 18, e)
            print(' '..num_dumps..' | '..files[num_dumps])
        end
    end 
    p.close()

    if num_dumps == 0 then return oops("Didn't find any dump files") end

    print(tab)
    print(' Your card has UID '..GetUID())
    print('')
    print(' Select which dump to write (1 until '..num_dumps..')')
    print(tab)
    io.write(' --> ')

    local no = tonumber(io.read())
    print(tab)
    print(' You have been selected card dump ' .. no .. ', with UID : '..files[no])  

    --- Load eml file
    local dumpfile = assert(io.open('./hf-mf-' .. files[no] .. '-dump.eml', 'r'))
    for _ in dumpfile:lines() do table.insert(eml, _); end
    dumpfile.close()

    --- Extract B key from EML file    
    local b = 0
    for i = 1, #eml do
        if (i % 4 == 0) then
            repeat
                b = b + 1
                -- Cut key from block
                b_keys[b] = string.sub(eml[i], (#eml[i] - 11), #eml[i]) 
            until b % 4 == 0
        end
    end 
    print(tab)
    dbg(b_keys)
    dbg(eml)

    --- Change UID on certain version of magic Gen3 card.  
    if (utils.confirm(' Change UID ?') == true) then
        wait()
        --core.console('hf 14a raw -s -c -t 2000 90f0cccc10'..tostring(eml[1]))
        print('hf 14a raw -s -c -t 2000 90f0cccc10'..tostring(eml[1]))
        print(tab)
        print(' The new card UID : ' .. GetUID())
    end 
    print(tab)  
    
    --- Lock UID
    if (utils.confirm(' Permanent lock UID ? (card can never change uid again) ') == true) then
        wait()
        core.console('hf 14a raw -s -c -t 2000 90fd111100')
    end 
    print(tab)
    
    --- Writing blocks
    local default_key = 'FFFFFFFFFFFF'
    local default_key_blk = 'FFFFFFFFFFFF78778800FFFFFFFFFFFF'
    local empty = string.rep('0', 32)
    local cmd_wrbl = 'hf mf wrbl %d B %s %s'

    if (utils.confirm(' Are you using a empty card with default key?') == true) then
        wait()
        for i = 1, #eml do
            core.console(string.format(cmd_wrbl, (i-1), default_key, eml[i]))
        end
    else
        print(tab)
        if (utils.confirm(' Delete ALL data and write all keys to 0x'..default_key..' ?') == true) then
            wait()
            for i = 1, #eml do
                if (i % 4 == 0) then
                    core.console(string.format(cmd_wrbl, (i-1), b_keys[i], default_key_blk))
                else
                    core.console(string.format(cmd_wrbl, (i-1), b_keys[i], empty))
                end
            end
        else
            print(tab)
            print('Writing to card')
            wait()
            for i = 1, #eml do
                core.console(string.format(cmd_wrbl, (i-1), b_keys[i], eml[i]))
            end
        end
    end
    dropfield()
    print(tab)
    print('Done')
end

main(args)
