local getopt = require('getopt')
local ac = require('ansicolors')
local green = ac.green
local red = ac.red
local yellow = ac.yellow
local res = ac.reset

copyright = ''
author = ''
version = 'v1.00'
desc = [[
    Sweeps the EM4x50 reader timings (`lf em 4x50 config`) one at a time,
    reads a block several times per value and reports the success rate.
    For each setting the centre of the widest fully working range is
    suggested, then all suggestions are checked together.
    Keep the tag still on the antenna while the script runs. To find the
    most robust values, place it where reading is hardest (edge, distance).
]]
example = [[
    script run lf_em4x50_tune
    script run lf_em4x50_tune -n 20 -s rm
    script run lf_em4x50_tune -b 3 -p 12345678 -a
]]
usage = [[
    script run lf_em4x50_tune [-h] [-b block] [-p password] [-n tries] [-s setting] [-f] [-a]
]]
arguments = [[
    -h            this help
    -b block      block to read, 0..33 (default: 32, serial number)
    -p password   8 hex digits (default: none)
    -n tries      reads per value (default: 10)
    -s setting    sweep only this one: rm, gs, ge, thr, tol (default: all)
    -f            fine sweep, smaller steps
    -a            keep the suggested settings (default: restore defaults)
]]

-- swept values, ordered by importance; fine = step with -f
local sweeps = {
    { key = 'rm',  name = 'rm delay',     from = 64, to = 248, step = 8, fine = 4 },
    { key = 'gs',  name = 'gap start',    from = 0,  to = 24,  step = 2, fine = 1 },
    { key = 'ge',  name = 'gap end',      from = 16, to = 60,  step = 4, fine = 2 },
    { key = 'thr', name = 'threshold %',  from = 30, to = 95,  step = 5, fine = 5 },
    { key = 'tol', name = 'tolerance',    from = 2,  to = 15,  step = 1, fine = 1 },
}

local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ac.cyan .. 'Usage' .. res)
    print(usage)
    print(ac.cyan .. 'Arguments' .. res)
    print(arguments)
    print(ac.cyan .. 'Example usage' .. res)
    print(example)
end

local function oops(err)
    print(red .. 'ERROR: ' .. res .. err)
    core.clearCommandBuffer()
    return nil, err
end

local function config(args)
    core.console('lf em 4x50 config ' .. args, true, true)
end

-- word read from <block> as "XX XX XX XX", nil on failure
local function read_word(block, pwd)
    local cmd = 'lf em 4x50 rdbl -b ' .. block
    if pwd ~= '' then cmd = cmd .. ' -p ' .. pwd end
    local out = core.console(cmd, true, true) or ''
    out = out:gsub('\27%[[%d;]*m', '')
    return out:match('%s' .. block .. ' | (%x%x %x%x %x%x %x%x) |')
end

-- successful reads out of <tries>, a read must match <ref> once it is known
local function score(block, pwd, tries, ref)
    local ok = 0
    for _ = 1, tries do
        local w = read_word(block, pwd)
        if w ~= nil and (ref.word == nil or ref.word == w) then
            ref.word = ref.word or w
            ok = ok + 1
        end
    end
    return ok
end

-- centre of the widest run of values at the best rate
local function pick(results)
    local best = 0
    for _, r in ipairs(results) do
        if r.ok > best then best = r.ok end
    end
    if best == 0 then return nil, 0 end

    local run_start, run_len, cur_start, cur_len = 1, 0, 1, 0
    for i, r in ipairs(results) do
        if r.ok == best then
            if cur_len == 0 then cur_start = i end
            cur_len = cur_len + 1
            if cur_len > run_len then run_start, run_len = cur_start, cur_len end
        else
            cur_len = 0
        end
    end
    return results[run_start + math.floor((run_len - 1) / 2)].value, best
end

local function main(args)
    local block, pwd, tries, only, apply, fine = '32', '', 10, nil, false, false

    for o, a in getopt.getopt(args, 'hb:p:n:s:fa') do
        if o == 'h' then return help() end
        if o == 'b' then
            local n = tonumber(a)
            if not n or n < 0 or n > 33 then return oops('block must be 0..33') end
            block = tostring(math.floor(n))
        end
        if o == 'p' then
            if #a ~= 8 or not a:match('^%x+$') then return oops('password must be 8 hex digits') end
            pwd = a
        end
        if o == 'n' then
            tries = tonumber(a)
            if not tries or tries < 1 then return oops('invalid number of tries') end
            tries = math.floor(tries)
        end
        if o == 's' then only = a end
        if o == 'f' then fine = true end
        if o == 'a' then apply = true end
    end

    local ref = { word = nil }
    config('-d')
    local base = score(block, pwd, tries, ref)
    print(('defaults: %d/%d reads, block %s = %s'):format(base, tries, block, ref.word or '??'))

    local chosen = {}
    for _, s in ipairs(sweeps) do
        if only == nil or only == s.key then
            print(ac.cyan .. ('--- %s (--%s) ---'):format(s.name, s.key) .. res)
            local results = {}
            for v = s.from, s.to, (fine and s.fine or s.step) do
                if core.kbd_enter_pressed() then
                    config('-d')
                    return oops('stopped by user')
                end
                config('-d --' .. s.key .. ' ' .. v)
                local ok = score(block, pwd, tries, ref)
                table.insert(results, { value = v, ok = ok })
                local col = (ok == tries) and green or ((ok == 0) and red or yellow)
                print(('%4d  %s%2d/%d %s%s'):format(v, col, ok, tries, string.rep('#', ok), res))
            end
            local v, rate = pick(results)
            if v ~= nil then
                chosen[s.key] = v
                print(('suggested --%s %d (%d/%d)'):format(s.key, v, rate, tries))
            else
                print(red .. 'no working value for --' .. s.key .. res)
            end
        end
    end

    local combo = ''
    for _, s in ipairs(sweeps) do
        if chosen[s.key] ~= nil then
            combo = combo .. (' --%s %d'):format(s.key, chosen[s.key])
        end
    end

    config('-d' .. combo)
    local final = score(block, pwd, tries * 2, ref)
    print(ac.cyan .. '--- result ---' .. res)
    print(('suggested settings:%s'):format(combo))
    print(('combined: %d/%d reads (defaults: %d/%d)'):format(final, tries * 2, base, tries))

    if apply then
        print(green .. 'kept, until the device restarts. Run `lf em 4x50 config` to see them.' .. res)
    else
        config('-d')
        print('defaults restored, use -a to keep the suggestion')
    end
end

main(args)
