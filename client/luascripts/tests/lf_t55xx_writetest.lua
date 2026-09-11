local getopt = require('getopt')
local ansicolors = require('ansicolors')
local t55 = require('t55xx_config')
local R = require('testresult')

local format = string.format

copyright = ''
author = 'Iceman'
version = 'v1.1.1'
desc = [[
Writes a configuration and four data blocks to a T55x7, then detects the tag
and reads those blocks back, comparing what came off the tag with what went on.

A strict T55x7 test suite:

    lf t55xx wipe
    lf t55xx write -b 1 -d 00000000
    lf t55xx write -b 2 -d aa5500ff
    lf t55xx write -b 3 -d 80000000
    lf t55xx write -b 4 -d 00000001

Each row names the configuration word, what it means, what `lf t55xx detect`
made of it and how many of the four data blocks read back intact.  Markers are
also written into the session log ( `rem [ERR:...]` and `rem [SUMMARY:...]` )

Every block is read three times.  A block that reads back differently between
those is marked `unstable`, which is the fault a single read cannot see: the
value is silently wrong rather than missing.  A block that is wrong the same way
each time is named where it can be - `rol1`, `ror5`, `inverted`, `shr1` - because
a rotation points at the word boundary and an inversion at psk phase, and the two
want different fixes.  Block 1 is `00000000`, which is equal to all of its own
rotations, so a rotated read of it cannot be told from a correct one.

Note: that the card is wiped before each modulation.

Needs a T5577 in the field.
]]
example = [[
    1. script run tests/lf_t55xx_writetest
    2. script run tests/lf_t55xx_writetest -t PSK1
    3. script run tests/lf_t55xx_writetest -t all
]]
usage = [[
script run tests/lf_t55xx_writetest [-h] [-t <modulation>]
]]
arguments = [[
    -h       this help
    -t       modulation to test, defaults to ASK
             'PSK1', 'PSK2', 'PSK3', 'FSK1', 'FSK2', 'FSK1A', 'FSK2A', 'ASK', 'BI', or 'ALL'
]]

local TIMEOUT = 1500

local DATA_BLOCKS = {
    [1] = '00000000',
    [2] = 'aa5500ff',
    [3] = '80000000',
    [4] = '00000001',
}

local ALL_MODULATIONS = { 'ASK', 'BI', 'PSK1', 'PSK2', 'PSK3', 'FSK1', 'FSK2', 'FSK1A', 'FSK2A' }

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
-- The configuration words to sweep for each modulation.  A PSK subcarrier that
-- does not divide the bit rate into a whole number of cycles is not a
-- configuration the tag can hold, so those are absent rather than expected to
-- fail: RF/50 with an RF/4 subcarrier would be 12.5 cycles a bit.
local function GetConfigs(modulation)

    local t = {}

    t['PSK1'] = {
        -- subcarrier RF/2
        '00001040', '00041040', '00081040', '000c1040',
        '00101040', '00141040', '00181040', '001c1040',
        -- subcarrier RF/4, no RF/50
        '00001440', '00041440', '00081440', '000c1440',
        '00141440', '00181440', '001c1440',
        -- subcarrier RF/8, no RF/50 and no RF/100
        '00001840', '00041840', '00081840', '000c1840',
        '00141840', '001c1840',
    }

    t['PSK2'] = {
        '00002040', '00042040', '00082040', '000c2040',
        '00102040', '00142040', '00182040', '001c2040',
        '00002440', '00042440', '00082440', '000c2440',
        '00142440', '00182440', '001c2440',
        '00002840', '00042840', '00082840', '000c2840',
        '00142840', '001c2840',
    }

    t['PSK3'] = {
        '00003040', '00043040', '00083040', '000c3040',
        '00103040', '00143040', '00183040', '001c3040',
        '00003440', '00043440', '00083440', '000c3440',
        '00143440', '00183440', '001c3440',
        '00003840', '00043840', '00083840', '000c3840',
        '00143840', '001c3840',
    }

    t['FSK1'] = {
        '00004040', '00044040', '00084040', '000c4040',
        '00104040', '00144040', '00184040', '001c4040',
    }

    t['FSK2'] = {
        '00005040', '00045040', '00085040', '000c5040',
        '00105040', '00145040', '00185040', '001c5040',
    }

    t['FSK1A'] = {
        '00006040', '00046040', '00086040', '000c6040',
        '00106040', '00146040', '00186040', '001c6040',
    }

    t['FSK2A'] = {
        '00007040', '00047040', '00087040', '000c7040',
        '00107040', '00147040', '00187040', '001c7040',
    }

    t['ASK'] = {
        '00008040', '00048040', '00088040', '000c8040',
        '00108040', '00148040', '00188040', '001c8040',
    }

    -- biphase is 16, which spans the modulation field rather than sitting in a
    -- nibble of it, so it is the low bit of the bit rate byte
    t['BI'] = {
        '00010040', '00050040', '00090040', '000d0040',
        '00110040', '00150040', '00190040', '001d0040',
    }

    return t[modulation:upper()]
end

---
-- Wipe, then lay down the four data blocks.  Returns false with a reason when
-- the tag is not there or cannot be read back at all, which is a fact about
-- the run rather than about any one configuration.
local function prepare()

    core.console('lf t55xx wipe', false, true)

    if not core.t55xx_detect() then
        core.console('rem [ERR:DETECT:WIPED] Failed to detect after wipe', false, true)
        return false, 'tag not detected after wipe'
    end

    for block, val in ipairs(DATA_BLOCKS) do
        core.console(format('lf t55xx write -b %d -d %s', block, val), false, true)
    end
    return true
end

-- a block is read this many times, so that a value which is silently wrong on
-- only some reads is not mistaken for one that is right
local READS = 3

local function rol32(v, n)
    n = n % 32
    if n == 0 then return v end
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF
end

---
-- Name how `got` differs from `want`, when it can be named.  A rotation says the
-- word boundary moved, an inversion says psk picked the opposite phase, and a
-- shift says a demodulation opened a bit early and padded with zero - different
-- faults wanting different fixes, so worth telling apart.  A word equal to all of
-- its own rotations carries no boundary information and only gets 'differs'.
local function classify(want, got)

    if got == want then return 'ok' end

    if rol32(want, 1) == want then return 'differs' end

    for n = 1, 31 do
        if rol32(want, n) == got then
            return (n <= 16) and ('rol' .. n) or ('ror' .. (32 - n))
        end
    end

    if (want ~ 0xFFFFFFFF) == got then return 'inverted' end

    for n = 1, 31 do
        if (rol32(want, n) ~ 0xFFFFFFFF) == got then
            return 'inv+' .. ((n <= 16) and ('rol' .. n) or ('ror' .. (32 - n)))
        end
    end

    for n = 1, 8 do
        if ((want >> n) & 0xFFFFFFFF) == got then return 'shr' .. n end
        if ((want << n) & 0xFFFFFFFF) == got then return 'shl' .. n end
    end

    return 'differs'
end

---
-- Read blocks 1-4 back, READS times each.  Returns how many matched on every
-- read and a short note naming what went wrong with the ones that did not.
local function read_back(config)

    local good, bad = 0, {}

    for block, want in ipairs(DATA_BLOCKS) do

        local wantv = tonumber(want, 16)
        local seen, first, stable = {}, nil, true

        for _ = 1, READS do
            local data = core.t55xx_readblock(block, '0', '0', '')
            local v = data and (data & 0xFFFFFFFF) or nil
            table.insert(seen, v)
            if first == nil then
                first = v
            elseif v ~= first then
                stable = false
            end
        end

        if stable and first == wantv then
            good = good + 1
        else
            local what
            if stable == false then
                what = 'unstable'
            else
                what = classify(wantv, first)
            end

            table.insert(bad, format('b%d %s', block, what))

            local reads = {}
            for _, v in ipairs(seen) do
                table.insert(reads, v and ('%08X'):format(v) or '----')
            end
            core.console(format('rem [ERR:READ:%s:%d] block %d: %s, wanted %s, read %s',
                                config, block, block, what, want,
                                table.concat(reads, ' ')), false, true)
        end
    end

    local note = ''
    if #bad > 0 then
        note = table.concat(bad, ' ')
    end
    return good, note
end

local function test(modulation, report)

    local configs = GetConfigs(modulation)
    if configs == nil then
        print('[!] no configurations known for modulation ' .. modulation)
        return false
    end

    local ok, err = prepare()
    if ok == false then
        print('[!] ' .. err)
        print('[?] this suite writes to a tag, it needs a T5577 on the antenna')
        return false
    end

    for _, config in ipairs(configs) do

        core.clearCommandBuffer()

        local written, werr = t55.write(config, '00000000', TIMEOUT)
        if written == false then
            report:add(config, nil, { note = 'write failed', extra = '-' })

        else
            local found = t55.detect()

            if found == nil then
                core.console(format('rem [SUMMARY:%s] FAIL detection', config), false, true)
                report:add(config, nil, { extra = '0/' .. #DATA_BLOCKS })

            else
                local good, note = read_back(config)
                local all = (good == #DATA_BLOCKS) and (found.block0:upper() == config:upper())

                core.console(format('rem [SUMMARY:%s] %s', config,
                                    all and 'PASS all tests'
                                    or format('FAIL %d test%s', #DATA_BLOCKS - good,
                                              (#DATA_BLOCKS - good) == 1 and '' or 's')), false, true)

                report:add(config, found.block0, {
                    ok = all,
                    extra = ('%d/%d'):format(good, #DATA_BLOCKS),
                    note = note,
                })
            end
        end

        if core.kbd_enter_pressed() then
            print('aborted by user')
            return false
        end
    end
    return true
end

local function main(args)

    local modulation = 'ASK'

    for o, a in getopt.getopt(args, 'ht:') do
        if o == 'h' then return help() end
        if o == 't' then modulation = a end
    end

    core.clearCommandBuffer()

    local modes = { modulation }
    if modulation:upper() == 'ALL' then modes = ALL_MODULATIONS end

    local report = t55.report(
        ('T55x7 write and read back,  %s'):format(
            (#modes > 1) and 'every modulation' or modes[1]:upper()),
        'blocks')

    for _, m in ipairs(modes) do
        if test(m, report) == false then break end
    end

    local fails = report:summary()

    core.console(format('rem [SUMMARY] Success rate: %d/%d tests passed%s',
                        report.count.pass, report.count:total(),
                        (fails == 0) and ' \\o/' or ', help me improving that number!'), false, true)
    return fails
end

main(args)
