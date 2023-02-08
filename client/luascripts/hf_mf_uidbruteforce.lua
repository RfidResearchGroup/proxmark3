-- Run me like this (connected via USB): ./pm3 -l hf_mf_uidbruteforce.lua
-- Run me like this (connected via Blueshark addon): ./client/proxmark3 /dev/rfcomm0 -l ./hf_mf_uidbruteforce.lua

local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Daniel Underhay (updated), Keld Norman(original)'
version = 'v2.0.1'
desc =[[
This script bruteforces 4 or 7 byte UID Mifare classic card numbers.
]]
example =[[
Bruteforce a 4 bytes UID Mifare classic card number, starting at 11223344, ending at 11223346.

    script run hf_mf_uidbruteforce -s 0x11223344 -e 0x11223346 -t 1000 -x mfc

Bruteforce a 7 bytes UID Mifare Ultralight card number, starting at 11223344556677, ending at 11223344556679.

    script run hf_mf_uidbruteforce -s 0x11223344556677 -e 0x11223344556679 -t 1000 -x mfu
]]
usage = [[
script run hf_mf_uidbruteforce [-s <start_id>] [-e <end_id>] [-t <timeout>] [-x <mifare_card_type>]
]]
arguments = [[
    -h       this help
    -s       0-0xFFFFFFFF         start id
    -e       0-0xFFFFFFFF         end id
    -t       0-99999, pause       timeout (ms) between cards
                                  (use the word 'pause' to wait for user input)
    -x       mfc, mfc4, mfu       mifare type:
                                    mfc for Mifare Classic (default)
                                    mfc4 for Mifare Classic 4K
                                    mfu for Mifare Ultralight EV1
]]

local DEBUG = true
---
-- Debug print function
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
-- When errors occur
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
---
--- Print user message
local function msg(msg)
 print( string.rep('--',20) )
 print('')
 print(msg)
 print('')
 print( string.rep('--',20) )
end
---
-- Start
local function main(args)

    local timeout = 0
    local start_id = 0
    local end_id = 0xFFFFFFFFFFFFFF
    local mftype = 'mfc'
    local uid_format = '%14x'

    for o, a in getopt.getopt(args, 'e:s:t:x:h') do
        if o == 's' then start_id = a end
        if o == 'e' then end_id = a end
        if o == 't' then timeout = a end
        if o == 'x' then mftype = a end
        if o == 'h' then return help() end
    end

    -- template
    local command = ''

    -- if the end_id is equals or inferior to 0xFFFFFFFF then use the 4 bytes UID format by default
    if string.len(end_id) <= 10 then
        uid_format = '%08x'
    end

    if mftype == 'mfc' then
        command = 'hf 14a sim -t 1 -u ' .. uid_format
        msg('Bruteforcing Mifare Classic card numbers')
    elseif mftype == 'mfc4' then
        command = 'hf 14a sim -t 8 -u ' .. uid_format
        msg('Bruteforcing Mifare Classic 4K card numbers')
    elseif mftype == 'mfu' then
        command = 'hf 14a sim -t 2 -u ' .. uid_format
        msg('Bruteforcing Mifare Ultralight card numbers')
    else
        return print(usage)
    end

    if command == '' then return print(usage) end

    for n = start_id, end_id do
        local c = string.format( command, n )
        print('Running: "'..c..'"')
        core.console(c)
        core.console('msleep '..timeout);
        core.console('hw ping')
    end

end
main(args)
