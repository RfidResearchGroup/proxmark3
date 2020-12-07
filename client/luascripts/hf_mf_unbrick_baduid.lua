local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = ''
author = 'cyberpunk-re'
version = 'v1.0.0'
desc = [[
This script brings back to life a mifare UID modifiable card which has bad data written to block 0 or block 1, typically having a bad BCC (Block Check Character). It should workd on Mifare classic 1k/4k and Mifare Ultralight UID Modifiable and Direct write tags.
]]
example = [[
    -- target a Ultralight based card
    1. script run hf_mf_unbrick_baduid -u

]]
usage = [[
script run hf_mf_unbrick_baduid [-h] [-u]
]]
arguments = [[
    -h      this help
    -u      unbrick UID Modifiable/Direct Write Ultralight tag with 7 bytes UID.
]]

-- Helper functions borrowed from Iceman script hf_mf_magicrevive.lua

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

local function cmdUltralight()
    return {
    [0] = 'hf 14a config b 2',
    [1] = 'hf 14a raw -k -a 43',
    [2] = 'hf 14a raw -c -a A2005380712A',
    [3] = 'hf 14a raw -k -a -b 7 40',
    [4] = 'hf 14a raw -k -a 43',
    [5] = 'hf 14a raw -c -a A2010200D980',
    [6] = 'hf 14a raw -k -a -b 7 40',
    [7] = 'hf 14a raw -k -a 43',
    [8] = 'hf 14a raw -c -a A2025B480000',
    [9] = 'hf 14a config b 0',
    }
end
local function cmdClassic()
    return {
    [0] = 'hf 14a raw -k -a -b 7 40',
    [1] = 'hf 14a raw -k -a 43',
    [2] = 'hf 14a raw -c -k -a A000',
    [3] = 'hf 14a raw -c -k -a 01020304049802000000000000001001',
    [4] = 'hf 14a raw -c -a 5000',
    }
end
local function cmdRestoreST()
    local arr = {}
    for i = 0, 15 do
        local blk = 3 + (4*i)
        arr[i] = 'hf mf csetbl '..blk..' FFFFFFFFFFFFFF078000FFFFFFFFFFFF'
    end
    return arr
end
local function sendCmds( cmds )
    for i = 0, #cmds do
        if cmds[i]  then
            print ( cmds[i]  )
            core.console( cmds[i] )
            core.clearCommandBuffer()
        end
    end
end
---
-- The main entry point
function main(args)

    local i
    local cmds = {}
    local isUltralight = false

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hu') do
        if o == 'h' then return help() end
        if o == 'u' then isUltralight = true end
    end

    core.clearCommandBuffer()

    if isUltralight then
        sendCmds ( cmdUltralight() )
    else
        sendCmds( cmdClassic() )
        sendCmds( cmdRestoreST() )
    end
end

main(args)
