local getopt = require('getopt')
local ansicolors = require('ansicolors')
local t55 = require('t55xx_config')

copyright = ''
author = 'Iceman'
version = 'v1.1.1'
desc = [[
Testsuite for the PSK demodulation.

Writes block 0 with PSK selected and sweeps the bit rate and the PSK
subcarrier, reads the configuration back with `lf t55xx detect` and reports,
per configuration, whether what came back is what went in.

    00 xx y z 40
    --         -- max 2 blocks
            -- subcarrier, 0 4 8 = RF/2 RF/4 RF/8
          -- PSK1 1, PSK2 2, PSK3 3
       -- bit rate, 00 04 08 0C 10 14 18 1C = RF/8 16 32 40 50 64 100 128

Needs a T5577 in the field.
]]
example = [[
    1. script run tests/lf_t55xx_defaultpsk
    2. script run tests/lf_t55xx_defaultpsk -a
]]
usage = [[
script run tests/lf_t55xx_defaultpsk [-h] [-a] [-v]
]]
arguments = [[
    -h             : this help
    -a             : sweep PSK2 and PSK3 as well, not just PSK1
    -v             : also run `lf t55xx info` for each configuration
]]

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
    local last_mod = 1

    for o, _ in getopt.getopt(args, 'hav') do
        if o == 'h' then return help() end
        if o == 'a' then last_mod = 3 end
        if o == 'v' then opts.verbose = true end
    end

    core.clearCommandBuffer()

    local title = (last_mod == 1) and 'T55x7 PSK1,  bit rate x subcarrier sweep'  or 'T55x7  PSK1/2/3,  bit rate x subcarrier sweep'
    local report = t55.report(title)
    local aborted = false

    for modulation = 1, last_mod do
        for bitrate = 0x0, 0x1d, 0x4 do
            for subcarrier = 0, 8, 4 do

                t55.check(report, ('00%02X%X%X40'):format(bitrate, modulation, subcarrier), opts)

                if core.kbd_enter_pressed() then
                    print('aborted by user')
                    aborted = true
                    break
                end
            end
            if aborted then break end
        end
        if aborted then break end
    end

    return report:summary()
end

main(args)
