local getopt = require('getopt')
local ansicolors = require('ansicolors')
local t55 = require('t55xx_config')

copyright = ''
author = 'Iceman'
version = 'v1.1.1'
desc = [[
Testsuite for the ASK / BIPHASE demodulation.

Writes block 0 with ASK/Biphase selected and sweeps the bit rate, reads the
configuration back with `lf t55xx detect` and reports, per configuration,
whether what came back is what went in.

    00 xx 00 40
    --       -- max 2 blocks
       -- bit rate in the top bits, biphase in the low bit
          00 04 08 0C 10 14 18 1C = RF/8 16 32 40 50 64 100 128, plus 1

Needs a T5577 in the field.
]]
example = [[
    1. script run tests/lf_t55xx_defaultbi
    2. script run tests/lf_t55xx_defaultbi -v
]]
usage = [[
script run tests/lf_t55xx_defaultbi [-h] [-v]
]]
arguments = [[
    -h             : this help
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

    for o, _ in getopt.getopt(args, 'hv') do
        if o == 'h' then return help() end
        if o == 'v' then opts.verbose = true end
    end

    core.clearCommandBuffer()

    local report = t55.report('T55x7 ASK / Biphase,  bit rate sweep')

    for bitrate = 0x0, 0x1d, 0x4 do
        t55.check(report, ('00%02X0040'):format(bitrate + 1), opts)
        if core.kbd_enter_pressed() then
            print('aborted by user')
            break
        end
    end

    return report:summary()
end

main(args)
