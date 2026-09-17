local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Equip'
version = 'v1.0.1'
desc = [[
This script tries to recover soft bricked ntag i2c tags through the use of raw commands
]]
example = [[
    1. script run hf_14a_i2crevive
]]
usage = [[
script run hf_14a_i2crevive
]]
arguments = [[
    -h      this help
]]
---
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

local function i2cR()
    return {
    [0] = 'hf 14a raw -k -a -b 7 40',
    [1] = 'hf 14a raw -k -a 43',
    [2] = 'hf 14a raw -c -a A203E1106D00',
    [3] = 'hf 14a raw -k -a -b 7 40',
    [4] = 'hf 14a raw -k -a 43',
    [5] = 'hf 14a raw -c -a A20244000F00',
    [6] = 'hf 14a raw -k -a -b 7 40',
    [7] = 'hf 14a raw -k -a 43',
    [8] = 'hf 14a raw -c -a A2E20000FF00',
    [9] = 'hf 14a raw -k -a -b 7 40',
    [10] = 'hf 14a raw -k -a 43',
    [11] = 'hf 14a raw -c -a A2E3000000E3',
    [12] = 'hf 14a raw -c -a 5000',
    }
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

function main(args)

    local i
    local cmds = {}
    --check for params
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    core.clearCommandBuffer()
        sendCmds( i2cR() )
end
main(args)
