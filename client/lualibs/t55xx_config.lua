--[[
    T55x7 block 0 configuration word, in the terms `lf t55xx info` uses.

    Bit numbering is MSB first, matching CmdT55xxInfo() in cmdlft55xx.c:

        0 - 3    safer key ( 6 or 9 selects extended mode )
        4 - 10   reserved  ( 4 - 7 only in extended mode )
       11 - 13   data bit rate  ( 8 - 13 in extended mode )
            14   extended mode
       15 - 19   modulation
       20 - 21   PSK carrier frequency
            22   answer on request
            23   one time pad
       24 - 26   max block
            27   password mode
            28   sequence terminator / start marker
            29   fast write
            30   inverse data
            31   power on reset delay
--]]

local Config = {}

local BITRATE = {
    [0] = 'RF/8', [1] = 'RF/16', [2] = 'RF/32', [3] = 'RF/40',
    [4] = 'RF/50', [5] = 'RF/64', [6] = 'RF/100', [7] = 'RF/128',
}

local MODULATION = {
    [0] = 'DIRECT (ASK/NRZ)',
    [1] = 'PSK1',
    [2] = 'PSK2',
    [3] = 'PSK3',
    [4] = 'FSK1  RF/8 RF/5',
    [5] = 'FSK2  RF/8 RF/10',
    [6] = 'FSK1a RF/5 RF/8',
    [7] = 'FSK2a RF/10 RF/8',
    [8] = 'Manchester',
    [16] = 'Biphase',
    [24] = 'Biphase a (CDP)',
}

local PSKCF = { [0] = 'RF/2', [1] = 'RF/4', [2] = 'RF/8', [3] = 'reserved' }

-- `hi` and `lo` are inclusive MSB first bit positions
local function field(word, hi, lo)
    local width = lo - hi + 1
    return math.floor(word / 2 ^ (31 - lo)) % 2 ^ width
end

---
-- Split a block 0 word into its fields.  `word` is a number or a hex string.
function Config.parse(word)

    if type(word) == 'string' then
        word = tonumber(word, 16)
    end
    if word == nil then return nil end

    local c = {}
    c.block0 = word
    c.safer = field(word, 0, 3)
    c.extended = (c.safer == 6 or c.safer == 9) and field(word, 14, 14) == 1

    if c.extended then
        c.reserved = field(word, 4, 7)
        c.bitrate = field(word, 8, 13)
    else
        c.reserved = field(word, 4, 10)
        c.bitrate = field(word, 11, 13)
    end

    c.modulation = field(word, 15, 19)
    c.pskcf = field(word, 20, 21)
    c.aor = field(word, 22, 22)
    c.otp = field(word, 23, 23)
    c.maxblock = field(word, 24, 26)
    c.pwd = field(word, 27, 27)
    c.st = field(word, 28, 28)
    c.fastwrite = field(word, 29, 29)
    c.inverse = field(word, 30, 30)
    c.por = field(word, 31, 31)
    return c
end

---
-- One line saying what the tag was asked to do.  This is the "description its
-- settings" a reader needs next to a pass or a fail, so that a failure names
-- the configuration rather than a hex word to go and look up.
function Config.describe(word)

    local c = Config.parse(word)
    if c == nil then return '(unparsable)' end

    local mod = MODULATION[c.modulation] or ('unknown 0x%02X'):format(c.modulation)
    local rate = c.extended and ('RF/%d'):format(2 * (c.bitrate + 1))
                 or (BITRATE[c.bitrate] or ('unknown %d'):format(c.bitrate))

    local parts = { ('%-16s %-7s'):format(mod, rate) }

    -- only worth showing when it means something
    if c.modulation >= 1 and c.modulation <= 3 then
        table.insert(parts, 'subcarrier ' .. (PSKCF[c.pskcf] or '?'))
    end

    table.insert(parts, ('maxblk %d'):format(c.maxblock))

    if c.extended == true then table.insert(parts, 'extended') end
    if c.st == 1 then table.insert(parts, 'ST') end
    if c.pwd == 1 then table.insert(parts, 'pwd') end
    if c.inverse == 1 then table.insert(parts, 'inverted') end
    if c.aor == 1 then table.insert(parts, 'AOR') end

    return table.concat(parts, '  ')
end

---
-- Run `lf t55xx detect` and hand back what it decided, without printing any of
-- it.  `offline` replays whatever is already in the GraphBuffer instead of
-- going to a tag, which is what makes these suites runnable against saved
-- traces.  Returns nil when nothing was detected.
function Config.detect(offline)

    local out = core.console('lf t55xx detect' .. (offline and ' -1' or ''), true, true)

    -- An older client ignores the capture arguments and returns nothing.  The
    -- usual cause is a pm3 session started before the client was rebuilt,
    -- which keeps running the binary it was launched with.
    if type(out) ~= 'string' then
        error('this client does not hand command output back to scripts.  '
              .. 'Rebuild with `make client` and start a new pm3 session', 0)
    end

    local block0 = out:match('Block0%.+%s*(%x%x%x%x%x%x%x%x)')
    if block0 == nil then return nil, out end

    return {
        block0 = block0,
        modulation = out:match('Modulation%.+%s*([^\n]-)%s*\n'),
        bitrate = out:match('Bit rate%.+%s*([^\n]-)%s*\n'),
        offset = out:match('Offset%.+%s*(%d+)'),
        inverted = out:match('Inverted%.+%s*(%S+)'),
    }, out
end

---
-- Write a configuration word into block 0.  Returns true, or false and a
-- reason - a missing tag is a result to be recorded against this one
-- configuration, not grounds for abandoning the whole sweep.
function Config.write(block0, password, timeout)

    local cmds = require('commands')
    local utils = require('utils')

    password = password or '00000000'

    local data = ('%s%s%s%s'):format(utils.SwapEndiannessStr(block0, 32), password, '00', '00')
    local wc = Command:newNG{cmd = cmds.CMD_LF_T55XX_WRITEBL, data = data}

    local response, err = wc:sendNG(false, timeout or 1500)
    if not response then
        -- the device layer returns a sentence and a half; one clause is
        -- plenty next to a table of eight of them
        err = tostring(err):match('^[^:]+') or tostring(err)
        return false, err
    end
    return true
end

--
-- Report accumulator.  Every suite prints the same columns - the word that was
-- written, what that word means, and what came back - so a failure can be read
-- without going and looking anything up.  The verdict is last on the line.
local R = require('testresult')

local Report = {}
Report.__index = Report

-- an optional extra column sits between `detected` and the note
local function row(want, desc, got, extra, note, width)
    return ('%-9s %-52s %-9s'):format(want, desc, got)
           .. ((width > 0) and (' ' .. ('%-'..width..'s'):format(extra)) or '')
           .. (' %-17s '):format(note)
end

function Config.report(title, extra_title)

    local r = setmetatable({
        title = title,
        extra_title = extra_title,
        width = extra_title and #extra_title or 0,
        count = R.counter(),
        wrote = true,
        rows = {},
    }, Report)

    print(R.RULE)
    print(title)
    print(R.RULE)
    print('    ' .. row('block0', 'configuration', 'detected', extra_title or '', 'note', r.width) .. 'verdict')
    print(R.RULE)
    return r
end

---
-- `got` is the block0 that came back, or nil when nothing was detected.
-- `opts.note` explains a failure, `opts.extra` fills the extra column, and
-- `opts.ok` overrides the plain "did it come back unchanged" test for suites
-- that also read data blocks back.
function Report:add(want, got, opts)

    opts = opts or {}

    local ok = opts.ok
    if ok == nil then
        ok = (got ~= nil and got:upper() == want:upper())
    end

    local note = opts.note or ((got == nil) and 'not detected' or (ok and '' or 'MISMATCH'))
    if opts.note ~= nil and got == nil then self.wrote = false end

    self.count:add(ok)

    print(((ok and '[+] ') or '[!] ')
          .. row(want, Config.describe(want), got or '--------', opts.extra or '', note, self.width)
          .. (ok and R.OK or R.FAIL))

    table.insert(self.rows, { want = want, got = got, ok = ok, note = note })
    return ok
end

---
-- Returns the number that failed, so a caller can use it as an exit status.
function Report:summary()

    print(R.RULE)

    if self.wrote == false and self.count.pass == 0 then
        -- nothing was ever written, so nothing here says anything about the
        -- demodulators.  Say that once instead of listing it per row.
        print(('[!] none of the %d configurations could be written to a tag'):format(self.count:total()))
        print('[?] this suite needs a T5577 on the antenna')
        print(R.RULE)
        return self.count.fail
    end

    local fails = self.count:summary()
    print(R.RULE)
    return fails
end

---
-- Write one configuration, read it back, and record the outcome.
function Config.check(report, block0, opts)

    opts = opts or {}

    if opts.offline ~= true then
        local ok, err = Config.write(block0, opts.password, opts.timeout)
        if ok == false then
            return report:add(block0, nil, { note = 'write failed' })
        end
    end

    local found = Config.detect(opts.offline)
    core.clearCommandBuffer()

    local res = report:add(block0, found and found.block0 or nil)

    if opts.verbose then
        core.console('lf t55xx info')
    end
    return res
end

return Config
