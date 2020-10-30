local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.2'
desc = [[
This script will program a T55x7 TAG with the configuration: block 0x00 data 0x00010040
The outlined procedure is as following:

--BIPHASE 00010040
--

"lf t55xx write b 0 d 00010040"
"lf t55xx detect"
"lf t55xx info"

Loop:
    change the configuretion block 0 with:
    -xx01xxxx = RF/8
    -xx05xxxx = RF/16
    -xx09xxxx = RF/32
    -xx0Dxxxx = RF/40
    -xx11xxxx = RF/50
    -xx15xxxx = RF/64
    -xx19xxxx = RF/100
    -xx1Dxxxx = RF/128


testsuit for the BIPHASE demod
]]
example = [[
    1. script run lf_t55xx_defaultbi
]]
usage = [[
script run lf_t55xx_defaultbi [-h]
]]
arguments = [[
    -h             : this help
]]

local DEBUG = true -- the debug flag
local TIMEOUT = 1500

--BLOCK 0 = 00010040 BIPHASE
local config1 = '00'
local config2 = '0040'

local procedurecmds = {
    [1] = '%s%02X%s',
    [2] = 'lf t55xx detect',
    [3] = 'lf t55xx info',
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
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

local function test()
    local y
    local password = '00000000'
    local block = '00'
    local flags = '00'
    for y = 1, 0x1D, 4 do
        for _ = 1, #procedurecmds do
            local pcmd = procedurecmds[_]

            if #pcmd == 0 then

            elseif _ == 1 then

                local config = pcmd:format(config1, y, config2)
                dbg(('lf t55xx write b 0 d %s'):format(config))

                local data = ('%s%s%s%s'):format(utils.SwapEndiannessStr(config, 32), password, block, flags)

                local wc = Command:newNG{cmd = cmds.CMD_LF_T55XX_WRITEBL, data = data}
                local response, err = wc:sendNG(false, TIMEOUT)

                if not response then return oops(err) end
            else
                dbg(pcmd)
                core.console( pcmd )
            end
        end
        core.clearCommandBuffer()
    end
    print( string.rep('--',20) )

end

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    -- Arguments for the script
    for o, arg in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    core.clearCommandBuffer()
    test()
    print( string.rep('--',20) )
end
main(args)
