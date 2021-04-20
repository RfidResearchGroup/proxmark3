local getopt = require('getopt')
local lib14a = require('read14a')
local cmds = require('commands')
local ansicolors = require('ansicolors')

copyright = 'Copyright 2020 A. Ozkal, released under GPLv2+.'
author = 'Ave'
version = 'v0.1.2'
desc = [[
This script writes a bunch of random blocks to a Mifare Classic card
 ]]
example = [[
    script run mfc_hammerlite -w 1000 -k FFFFFFFFFFFF
]]
usage = [[
    script run mfc_hammerlite [-h] [-w <writecount>] [-k <key>]
]]
arguments = [[
    -h                   : This help
    -w <writeroundcount> : Amount of write rounds to be done to each block (optional, default: 100)
    -k <key>             : A key for the sectors
]]

local function help()
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

function randhex(len)
    result = ""
    for i = 1,len,1
    do
        -- 48-57 numbers, 65-70 a-f
        hex = math.random(0, 15)
        if hex >= 10 then
            hex = hex + 7
        end
        result = result..string.char(48 + hex)
    end
    return result
end

---
-- The main entry point
function main(args)
    -- param defaults
    loopcount = 100
    verifyevery = 10
    key = "FFFFFFFFFFFF"

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hw:k:') do
        if o == 'h' then return help() end
        if o == 'w' then loopcount = tonumber(a) end
	if o == 'k' then key = a end
    end

    starttime = os.time()

    for i = 1,loopcount,1
    do
	for a = 1,63,1
	do
	    if ((a + 1) % 4 ~= 0) and a ~= 0 then  -- :)
                data = randhex(32)
	        -- core.console('hf mf rdbl --blk '..a..' -k FFFFFFFFFFFF')
	        core.console('hf mf wrbl --blk '..a..' -k '..key..' -d '..data)
	    end
        end
    end

    print("Hammering complete.")
end

main(args)
