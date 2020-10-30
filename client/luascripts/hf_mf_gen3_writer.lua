local utils = require('utils')
local getopt = require('getopt')
local cmds = require('commands')
local read14a = require('read14a')
--
---
-------------------------------
-- Notes
-------------------------------
---
--
--[[
---Suggestions of improvement:
--- Add support another types of dumps: BIN, JSON
--- Maybe it will be not only as `hf_mf_gen3_writer`, like a universal dump manager.
--- Hide system messages when you writing a dumps, replace it to some of like [#####----------] 40%

-- iceman notes:
--  doesn't take consideration filepaths for dump files.
--  doesn't allow A keys for authenticating when writing
--  doesn't verify that card is magic gen3.
--  doesn't take several versions of same dump ( -1, -2, -3 ) styles.
--]]
--
---
-------------------------------
-- Script hat
-------------------------------
---
--
copyright = 'RRG Team'
author = 'Winds'
version = 'v1.0.0'
desc = [[
    This script gives you an easy way to write your *.eml dumps into normal MIFARE Classic and Magic Gen3 cards.

    Works with both 4 and 7 bytes NXP MIFARE Classic 1K cards.
    The script also has the possibility to change UID and permanent lock uid on magic Gen3 cards.

    It supports the following functionality.

    1. Write it to the same  of current card UID.
    2. Write it to magic Gen3 card.
    3. Change uid to match dump on magic Gen3 card.
    4. Permanent lock UID on magic Gen3 card.
    5. Erase all data at the card and set the FF FF FF FF FF FF keys, and Access Conditions to 78778800.

    Script works in a wizard styled way.

    Author Youtube channel: https://yev.ooo/

    Many Thanks,
    Best Regards
]]
example = [[
    1. script run mfc_gen3_writer
]]
usage = [[
    Give script to know if you uses an Windows OS
    Select your *.eml dump from list to write to the card.
    Follow the wizard.
]]
--
---
-------------------------------
-- Global variables
-------------------------------
---
--
local DEBUG = false -- the debug flag
local dumpEML -- Find all *.EML files
local files = {} -- Array for eml files
local b_keys = {} -- Array for B keys
local eml = {} -- Array for data in block 32
local num_dumps = 0 -- num of found eml dump files
local tab = string.rep('-', 64)
local empty = string.rep('0', 32) -- Writing blocks
local default_key = 'FFFFFFFFFFFF' -- Writing blocks
local default_key_type = '01' --KeyA: 00, KeyB: 01
local default_key_blk = 'FFFFFFFFFFFF7C378800FFFFFFFFFFFF' -- Writing blocks
local piswords_uid_lock = 'hf 14a raw -s -c -t 2000 90fd111100'
local piswords_uid_change = 'hf 14a raw -s -c -t 2000 90f0cccc10'
local cmd_wrbl_a = 'hf mf wrbl %d A %s %s' -- Writing blocks by A key
local cmd_wrbl_b = 'hf mf wrbl %d B %s %s' -- Writing blocks by B key
--
---
-------------------------------
-- A debug printout-function
-------------------------------
---
--
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
--
---
-------------------------------
-- This is only meant to be used when errors occur
-------------------------------
---
--
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end
--
---
-------------------------------
-- Usage help
-------------------------------
---
--
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
---
-------------------------------
-- GetUID
-------------------------------
---
--
local function GetUID()
    return read14a.read(true, true).uid
end
--
local function dropfield()
    read14a.disconnect()
    core.clearCommandBuffer()
end
--
---
-------------------------------
-- Wait for tag (MFC)
-------------------------------
---
--
local function wait()
    read14a.waitFor14443a()
end
--
---
-------------------------------
-- Return key code 00/01 to string
-------------------------------
---
--
local function KeyAB()
    if default_key_type == '00' then
        return 'KeyA'
    else
        return 'KeyB'
    end
end
--
---
-------------------------------
-- Check response from Proxmark
-------------------------------
---
--
local function getblockdata(response)
    if response.Status == 0 then
        return true
    else
        return false
    end
end
--
---
-------------------------------
-- Check 0xFFFFFFFFFFFF key for tag (MFC)
-------------------------------
---
--
local function checkkey()
    local status = 0
    for i = 1, #eml do
        cmd = Command:newNG{cmd = cmds.CMD_HF_MIFARE_READBL, data = ('%02x%02x%s'):format((i-1), default_key_type, default_key)}
        if (getblockdata(cmd:sendNG(false)) == true) then
            status = status + 1
                print(('%s %02s %s %s %s'):format(' ', (i-1), KeyAB(), default_key, 'OK'))
        else
            break
        end
    end
    if status == #eml then
        return true
    end
end
--
---
-------------------------------
-- Check user input A or B for blank tag (MFC)
-------------------------------
---
--
local function check_user_key(user_key_type)
    if user_key_type == 'A' then
        return cmd_wrbl_a
    elseif user_key_type == 'B' then
        return cmd_wrbl_b
    end
end
--
---
-------------------------------
-- Main function
-------------------------------
---
--
local function main(args)
    --
    ---
    -------------------------------
    -- Arguments for script
    -------------------------------
    ---
    --
    for o, a in getopt.getopt(args, 'hd') do
        if o == 'h' then return help() end
        if o == 'd' then DEBUG = true end
    end
    --
    wait()
    print(tab)
    --
    ---
    -------------------------------
    -- Detect 7/4 byte card
    -------------------------------
    ---
    --
    if (utils.confirm(' Are you use a Windwos OS ?') == true) then
        dumpEML = 'find "." "*dump.eml"'
        if string.len(GetUID()) == 14 then
            eml_file_uid_start = 18
            eml_file_uid_end = 31
            eml_file_lengt = 40
        else
            eml_file_uid_start = 18
            eml_file_uid_end = 25
            eml_file_lengt = 34
        end
    else
        dumpEML = "find '.' -iname '*dump.eml' -type f"
        if string.len(GetUID()) == 14 then
            eml_file_uid_start = 9
            eml_file_uid_end = 22
            eml_file_lengt = 31
        else
            eml_file_uid_start = 9
            eml_file_uid_end = 16
            eml_file_lengt = 25
        end
    end
    print(tab)
    dropfield()
    --
    ---
    -------------------------------
    -- List all EML files in /client
    -------------------------------
    ---
    --
    local p = assert(io.popen(dumpEML))
    for _ in p:lines() do
        -- The length of eml file
        if string.len(_) == eml_file_lengt then
            num_dumps = num_dumps + 1
            -- cut UID from eml file
            files[num_dumps] = string.sub(_, eml_file_uid_start, eml_file_uid_end) -- cut numeretic UID
            print(' '..num_dumps..' | '..files[num_dumps])
        end
    end
    --
    p.close()
    --
    if num_dumps == 0 then return oops("Didn't find any dump files") end
    --
    print(tab)
    print(' Your card has UID '..GetUID())
    print('')
    print(' Select which dump to write (1 until '..num_dumps..')')
    print(tab)
    io.write(' --> ')
    --
    local uid_no = tonumber(io.read())
    print(tab)
    print(' You have been selected card dump No ' .. uid_no .. ', with UID: ' .. files[uid_no] .. '. Your card UID: ' .. GetUID())
    --
    --
    ---
    -------------------------------
    -- Load eml file
    -------------------------------
    ---
    --
    local dumpfile = assert(io.open('hf-mf-' .. files[uid_no] .. '-dump.eml', 'r'))
    for _ in dumpfile:lines() do table.insert(eml, _); end
    dumpfile.close()
    --
    ---
    -------------------------------
    -- Extract B key from EML file
    -------------------------------
    ---
    --
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
    --
    ---
    -------------------------------
    -- Change UID on certain version of magic Gen3 card.
    -------------------------------
    ---
    --
    if (utils.confirm(' Change UID ?') == true) then
        wait()
        core.console(piswords_uid_change .. tostring(eml[1]))
        print(tab)
        print(' The new card UID : ' .. GetUID())
    end
    print(tab)
    --
    ---
    -------------------------------
    -- Lock UID
    -------------------------------
    ---
    --
    if (utils.confirm(' Permanent lock UID ? (card can never change uid again) ') == true) then
        wait()
        core.console(piswords_uid_lock)
    end
    --
    print(tab)
    print(' Going to check the all ' .. KeyAB() .. ' by ' .. default_key)
    print(tab)
    --
    if checkkey() == true then
        print(tab)
        if (utils.confirm(' Card is Empty. Write selected dump to card ?') == true) then
            for i = 1, #eml do
                core.console(string.format(cmd_wrbl_b, (i-1), default_key, eml[i]))
            end
        end
    else
        print(tab)
        if (utils.confirm(' It this is a new blank card ? Do you wishing to change Access Conditions to using B key ' .. default_key .. ' as main ?') == true) then
            print(tab)
            print(' With one key type we will use, A or B ?')
            print(tab)
            io.write(' --> ')
            local user_key_type = tostring(io.read())
            print(tab)
            print(' Enter 12 HEX chars of the key for access to card. By default ' .. default_key .. '.')
            print(tab)
            io.write(' --> ')
            local user_key_input = tostring(io.read())
            wait()
            for i = 1, #eml do
                if (i % 4 == 0) then
                    core.console(string.format(check_user_key(user_key_type), (i-1), user_key_input, default_key_blk))
                else
                    core.console(string.format(check_user_key(user_key_type), (i-1), user_key_input, empty))
                end
            end
        else
            print(tab)
            if (utils.confirm(' Write selected dump to card ?') == true) then
                print(tab)
                wait()
                for i = 1, #eml do
                    core.console(string.format(cmd_wrbl_b, (i-1), b_keys[i], eml[i]))
                end
            else
                print(tab)
                if (utils.confirm(' Delete ALL data and write all keys to 0x' .. default_key .. ' ?') == true) then
                    wait()
                    for i = 1, #eml do
                        if (i % 4 == 0) then
                            core.console(string.format(cmd_wrbl_b, (i-1), b_keys[i], default_key_blk))
                        else
                            core.console(string.format(cmd_wrbl_b, (i-1), b_keys[i], empty))
                        end
                    end
                end
            end
        end
    end
    dropfield()
    print(tab)
    print('You are welcome')
end
--
---
-------------------------------
-- Start Main function
-------------------------------
---
--
main(args)
