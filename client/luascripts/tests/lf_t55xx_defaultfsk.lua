local getopt = require('getopt')
local ansicolors = require('ansicolors')
local t55 = require('t55xx_config')

copyright = ''
author = 'Iceman'
version = 'v1.1.1'
desc = [[
Testsuite for the FSK demodulation.

Writes block 0 with each of the four FSK variants selected and sweeps the bit
rate, reads the configuration back with `lf t55xx detect` and reports, per
configuration, whether what came back is what went in.

    00 xx y0 40
    --       -- max 2 blocks
          -- FSK1 4, FSK2 5, FSK1a 6, FSK2a 7
       -- bit rate, 00 04 08 0C 10 14 18 1C = RF/8 16 32 40 50 64 100 128

Needs a T5577 in the field.
]]
example = [[
    1. script run tests/lf_t55xx_defaultfsk
    2. script run tests/lf_t55xx_defaultfsk -v
]]
usage = [[
script run tests/lf_t55xx_defaultfsk [-h] [-v]
]]
arguments = [[
    -h             : this help
    -v             : also run `lf t55xx info` for each configuration
]]

local MODULATIONS = {
    [4] = 'FSK1',
    [5] = 'FSK2',
    [6] = 'FSK1a',
    [7] = 'FSK2a',
}

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

local function main(args)

    local opts = {}

    for o, _ in getopt.getopt(args, 'hv') do
        if o == 'h' then return help() end
        if o == 'v' then opts.verbose = true end
    end

    core.clearCommandBuffer()

    local report = t55.report('T55x7 FSK,  four variants x bit rate sweep')
    local aborted = false

    for modulation = 4, 7 do
        for bitrate = 0x0, 0x1d, 0x4 do

            t55.check(report, ('00%02X%X040'):format(bitrate, modulation), opts)

            if core.kbd_enter_pressed() then
                print('aborted by user')
                aborted = true
                break
            end
        end
        if aborted then break end
    end

    return report:summary()
end

main(args)
