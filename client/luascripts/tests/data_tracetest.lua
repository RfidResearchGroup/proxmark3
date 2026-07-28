local getopt = require('getopt')
local ansicolors = require('ansicolors')
local R = require('testresult')

copyright = ''
author = 'Iceman'
version = 'v1.1.1'
desc = [[
Replays every LF trace in traces/ through `lf search` and reports what each one
was identified as, against a recorded baseline.

The baseline lives in traces/lf_search_expected.txt, one line per trace.
`-u` - record or refresh the baseline

Runs entirely offline, no device and no tag needed.
]]
example = [[
    1. script run tests/data_tracetest
    2. script run tests/data_tracetest -u
    3. script run tests/data_tracetest -f em4
]]
usage = [[
script run tests/data_tracetest [-h] [-u] [-v] [-f <substring>]
]]
arguments = [[
    -h             : this help
    -u             : update the baseline from this run
    -v             : print the full `lf search` output for every trace
    -f <substring> : only traces whose name contains this
]]

local BASELINE = 'traces/lf_search_expected.txt'
local RULE = R.RULE

local ROW = '%-44s %-24s %-24s '


local function no_capture(out)

    if type(out) == 'string' then return false end

    print('[?] Maybe a session already running')
    return true
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

local function identified(out)

    local found = {}
    local seen = {}

    for name in out:gmatch('Valid (.-) ID found') do
        if seen[name] == nil then
            seen[name] = true
            table.insert(found, name)
        end
    end

    table.sort(found)
    if #found == 0 then return 'none' end
    return table.concat(found, ' + ')
end

local function load_baseline(path)
    local t, n = {}, 0
    local fh = io.open(path, 'r')
    if fh == nil then return nil, 0 end
    for line in fh:lines() do
        local name, want = line:match('^(%S+)%s+(.-)%s*$')
        if name ~= nil and name:sub(1, 1) ~= '#' then
            t[name] = want
            n = n + 1
        end
    end
    fh:close()
    return t, n
end

local function main(args)

    local update, verbose, filter = false, false, nil

    for o, a in getopt.getopt(args, 'huvf:') do
        if o == 'h' then return help() end
        if o == 'u' then update = true end
        if o == 'v' then verbose = true end
        if o == 'f' then filter = a end
    end

    local cwd = core.cwd()

    local files = {}
    local p = assert(io.popen("find '" .. cwd .. "/traces/' -iname 'lf_*.pm3' -type f | sort"))
    for file in p:lines() do
        if filter == nil or file:find(filter, 1, true) then
            table.insert(files, file)
        end
    end
    p:close()

    if #files == 0 then
        print('[!] no traces found under ' .. cwd .. '/traces/')
        return
    end

    local baseline, nbase = load_baseline(cwd .. '/' .. BASELINE)
    if baseline == nil and update == false then
        print('[!] no baseline at ' .. BASELINE)
        print('[?] recording what this run finds, then run with -u to freeze it')
        baseline = {}
    end

    print(RULE)
    print(('LF trace identification,  %d traces%s'):format(#files, (nbase > 0) and (', baseline of '.. nbase) or ''))
    print(RULE)
    print('    ' .. ROW:format('trace', 'identified as', 'baseline') .. 'verdict')
    print(RULE)

    local pass, fail, new, results = 0, 0, 0, {}

    for _, file in ipairs(files) do

        local name = file:match('([^/]+)$')

        core.console('data load -f ' .. file, false, true)
        local out = core.console('lf search -1u', true, not verbose)

        if no_capture(out) then return end

        local got = identified(out)
        table.insert(results, { name = name, got = got })

        if update then
            print('[=] ' .. ROW:format(name, got, '') .. R.SKIP)
        else
            local want = baseline[name]
            if want == nil then
                new = new + 1
                print('[?] ' .. ROW:format(name, got, '( no entry )') .. NEW)
            elseif want == got then
                pass = pass + 1
                print('[+] ' .. ROW:format(name, got, '') .. R.OK)
            else
                fail = fail + 1
                print('[!] ' .. ROW:format(name, got, want) .. R.FAIL)
            end
        end

        core.clearCommandBuffer()

        if core.kbd_enter_pressed() then
            print('aborted by user')
            break
        end
    end

    print(RULE)

    if update then
        local fh, err = io.open(cwd .. '/' .. BASELINE, 'w')
        if fh == nil then
            print('[!] could not write '.. BASELINE ..': '..tostring(err))
            return
        end

        fh:write('# `lf search -1u` identification per trace, recorded by `script run tests/data_tracetest -u`.\n')

        for _, r in ipairs(results) do
            fh:write(('%-46s %s\n'):format(r.name, r.got))
        end

        fh:close()

        print(('[+] wrote %d entries to %s'):format(#results, BASELINE))

    else
        local count = R.counter()
        count.pass, count.fail, count.other = pass, fail, new
        count:summary()
        if new > 0 then
            print(('[?] %d have no baseline entry, record one with -u'):format(new))
        end
    end

    print(RULE)
    return fail
end

main(args)
