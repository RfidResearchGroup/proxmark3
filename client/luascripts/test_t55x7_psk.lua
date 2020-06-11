local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.3'
desc = [[
This script will program a T55x7 TAG with the configuration: block 0x00 data 0x00088040
The outlined procedure is as following:

"lf t55xx write b 0 d 00088040"
"lf t55xx detect"
"lf t55xx info"

Loop OUTER:
    change the configuretion block 0 with:
    -xxxx8xxx = PSK RF/2 with Manchester modulation
    -xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
    -xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
    -xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)
    Loop INNER
        for each outer configuration, also do
            XXXXX0XX = PSK RF/2
            XXXXX4XX = PSK RF/4
            XXXXX8XX = PSK RF/8

In all 12 individual test for the PSK demod
]]
example = [[
    1. script run test_t55x7_psk
]]
usage = [[
script run test_t55x7_psk [-h]
]]
arguments = [[
    -h             : this help
]]

local DEBUG = true -- the debug flag
local TIMEOUT = 1500

-- --BLOCK 0 = 00 08 80 40 PSK
             -- -----------
               -- 08------- bitrate
                  -- 8----- modulation PSK1
                   -- 0---- PSK ClockRate
                      -- 40 max 2 blocks

local procedurecmds = {
    [1] = '00%02X%X%X40',
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

local function test(modulation)
    local bitrate
    local clockrate
    local password = '00000000'
    local block = '00'
    local flags = '00'
    for bitrate = 0x0, 0x1d, 0x4 do

        for clockrate = 0,8,4 do

            for _ = 1, #procedurecmds do
                local cmd = procedurecmds[_]

                if #cmd == 0 then

                elseif _ == 1 then

                    dbg('Writing to T55x7 TAG')

                    local config = cmd:format(bitrate, modulation, clockrate)
                    dbg(('lf t55xx write b 0 d %s'):format(config))

                    local data = ('%s%s%s%s'):format(utils.SwapEndiannessStr(config, 32), password, block, flags)

                    local wc = Command:newNG{cmd = cmds.CMD_LF_T55XX_WRITEBL, data = data}
                    local response, err = wc:sendNG(false, TIMEOUT)
                    if not response then return oops(err) end
                else
                    dbg(cmd)
                    core.console( cmd )
                end
            end
            core.clearCommandBuffer()
        end
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

    test(1)  -- PSK1
    --test(2) -- PSK2
    --test(3) -- PSK3

    print( string.rep('--',20) )
end
main(args)

-- Where it iterates over
  -- xxxx8xxx = PSK RF/2 with Manchester modulation
  -- xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
  -- xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
  -- xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)

    -- XXXXX0XX = PSK RF/2
    -- XXXXX4XX = PSK RF/4
    -- XXXXX8XX = PSK RF/8
