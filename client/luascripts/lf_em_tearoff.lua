local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = 'Iceman'
author = 'Iceman'
version = 'v0.9.9'
desc = [[
This is scripts loops though a tear attack and reads expected value.
]]
example = [[
    1. script run tearoff -n 2 -s 200 -e 400 -a 5
]]
usage = [[
script run tearoff [-h] [-n <steps us>] [-a <addr>] [-p <pwd>] [-s <start us>] [-e <end us>] [-r <read>] [-w <write>]
]]
arguments = [[
    -h                 This help
    -n <steps us>      steps in milliseconds for each tearoff
    -a <addr>          address to target on card
    -p <pwd>           (optional) use a password
    -s <delay us>      initial start delay
    -e <delay us>      end delay, must be larger than start delay
    -r <read value>    4 hex bytes value to be read
    -w <write value>   4 hex bytes value to be written
    end
]]

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

local function main(args)

    --[[
    Basically do the following,

    1. hw tear
    2. lf em 4x05_write
    3. lf em 4x05_read

    The first two commands doesn't need a feedback from the system, so going with core.console commands.
    Since the read needs demodulation of signal I opted to add that function from cmdlfem4x.c to the core lua scripting
        core.em4x05_read(addr, password)

    --]]
    local n, addr, password, sd, ed, wr_value, rd_value

    for o, a in getopt.getopt(args, 'he:s:a:p:n:r:w:') do
        if o == 'h' then return help() end
        if o == 'n' then n = a end
        if o == 'a' then addr = a end
        if o == 'p' then password = a end
        if o == 'e' then ed = tonumber(a) end
        if o == 's' then sd = tonumber(a) end
        if o == 'w' then wr_value = a end
        if o == 'r' then rd_value = a end
    end

    rd_value = rd_value or 'FFFFFFFF'
    wr_value = wr_value or 'FFFFFFFF'
    addr = addr or 5
    password = password or ''
    n = n or 2
    sd = sd or 2000
    ed = ed or 2100

    if password ~= '' and #password ~= 8 then
        return oops('password must be 4 hex bytes')
    end

    if #wr_value ~= 8 then
        return oops('write value must be 4 hex bytes')
    end

    if #rd_value ~= 8 then
        return oops('read value must be 4 hex bytes')
    end

    if sd > ed then
        return oops('start delay can\'t be larger than end delay', sd, ed)
    end

    print('Starting EM4x05 tear off')
    print('target addr', addr)
    if password then
        print('target pwd', password)
    end
    print('target stepping', n)
    print('target delay', sd ,ed)
    print('read value', rd_value)
    print('write value', wr_value)

    local res_tear = 0
    local res_nowrite = 0

    local set_tearoff_delay = 'hw tearoff --delay %d'
    local enable_tearoff = 'hw tearoff --on'

    local wr_template = 'lf em 4x05 write --addr %s --data %s --pwd %s'

    -- init addr to value
    core.console(wr_template:format(addr, wr_value, password))

    if sd == ed then
       ed = n
       n = 0
    end

    for step = sd, ed, n do

        io.flush()
        if core.kbd_enter_pressed() then
            print("aborted by user")
            break
        end

        core.clearCommandBuffer()

        -- reset addr to known value, if not locked into.
        if n ~= 0 then
        c = wr_template:format(addr, wr_value, password)
        core.console(c)
        end

        local c = set_tearoff_delay:format(step)
        core.console(c);
        core.console(enable_tearoff)

        c = wr_template:format(addr, wr_value, password)
        core.console(c)

        local word, err =  core.em4x05_read(addr, password)
        if err then
            return oops(err)
        end

        local wordstr = ('%08X'):format(word)

        if wordstr ~= wr_value then
            if wordstr ~= rd_value then
                print((ansicolors.red..'TEAR OFF occurred:'..ansicolors.reset..' %08X'):format(word))
                res_tear = res_tear + 1
            else
                print((ansicolors.cyan..'TEAR OFF occurred:'..ansicolors.reset..' %08X'):format(word))
                res_nowrite = res_nowrite + 1
            end
        else
            print((ansicolors.green..'Good write occurred:'..ansicolors.reset..' %08X'):format(word))
        end
    end
end

--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
