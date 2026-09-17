local cmds = require('commands')
local lib15 = require('read15')
local getopt = require('getopt')
local utils =  require('utils')
local ansicolors  = require('ansicolors')

copyright = 'Copyright (c) 2018 IceSQL AB. All rights reserved.'
author = 'Christian Herrmann'
version = 'v1.0.6'
desc = [[
This script tries to set UID on a IS15693 SLIX magic card
Remember the UID  ->MUST<- start with 0xE0
 ]]
example = [[

     -- ISO15693 slix magic tag

     script run hf_15_magic -u E004013344556677

     script run hf_15_magic -u E004013344556677 -a
]]
usage = [[
script run hf_15_magic -h -u <uid>
]]
arguments = [[
    -h             : this help
    -u <UID>       : UID (16 hexsymbols)
    -a             : use official pm3 repo ISO15 commands instead of iceman fork.
]]

local DEBUG = true
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
--
--- Set UID on magic command enabled on a ICEMAN based REPO
local function magicUID_iceman(b0, b1)
    print('Using backdoor Magic tag function')
    core.console('hf 15 raw -2 -c -d 02213E00000000')
    core.console('hf 15 raw -2 -c -d 02213F69960000')
    core.console('hf 15 raw -2 -c -d 022138'..b1)
    core.console('hf 15 raw -2 -c -d 022139'..b0)
end
--
--- Set UID on magic command enabled,  OFFICIAL REPO
local function magicUID_official(b0, b1)
    print('Using backdoor Magic tag function OFFICIAL REPO')
    core.console('hf 15 cmd raw -c 02213E00000000')
    core.console('hf 15 cmd raw -c 02213F69960000')
    core.console('hf 15 cmd raw -c 022138'..b1)
    core.console('hf 15 cmd raw -c 022139'..b0)
end
---
-- The main entry point
function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local uid = 'E004013344556677'
    local use_iceman = true

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hu:a') do
        if o == 'h' then return help() end
        if o == 'u' then uid = a end
        if o == 'a' then use_iceman = false end
    end

    -- uid string checks
    if uid == nil then return oops('empty uid string') end
    if #uid == 0 then return oops('empty uid string') end
    if #uid ~= 16 then return oops('uid wrong length. Should be 8 hex bytes') end

    local bytes = utils.ConvertHexToBytes(uid)

    local block0 = string.format('%02X%02X%02X%02X', bytes[4], bytes[3], bytes[2], bytes[1])
    local block1 = string.format('%02X%02X%02X%02X', bytes[8], bytes[7], bytes[6], bytes[5])

    print('new UID | '..uid)

    core.clearCommandBuffer()

    if use_iceman then
        magicUID_iceman(block0, block1)
    else
        magicUID_official(block0, block1)
    end
end

main(args)
