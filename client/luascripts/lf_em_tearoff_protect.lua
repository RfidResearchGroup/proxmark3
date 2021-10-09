local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = 'Iceman'
author =  [[
'Author   Iceman
 CoAuthor Doegox
]]
version = 'v1.0.2'
desc = [[
This is scripts loops though a tear attack and reads expected value.
]]
example = [[
    Full automatic, with password:
    script run lf_em_tearoff_protect -p 50524F58

    Manual fix increment over specified range:
    script run lf_em_tearoff_protect -n 2 -s 200 -e 400

    Trying repeatedly for a fixed timing, forever or till success:
    script run lf_em_tearoff_protect -s 400 -e 400

    Tips:
        Use a low Q antenna
        Move card somehow away from the antenna to a position where it still works
]]
usage = [[
script run lf_em_tearoff_protect [-h] [-n <steps us>] [-p <pwd>] [-s <start us>] [-e <end us>]
]]
arguments = [[
    -h                 This help
    -n <steps us>      steps in milliseconds for each tear-off
    -p <pwd>           (optional) use a password
    -s <delay us>      initial start delay
    -e <delay us>      end delay, must be larger or equal to start delay
    end
]]

local set_tearoff_delay = 'hw tearoff --on --delay %d'
local wr_template = 'lf em 4x05 write --po -d %s -p %s'

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

local function exit_msg()
    print('')
    print('================= '..ansicolors.green..'verify with'..ansicolors.reset..' =================')
    print('    lf em 4x05_dump')
    print('===============================================')
    return nil
end

local function reset(wr_value, password)
    print('[=] '..ansicolors.red..'resetting the active lock block'..ansicolors.reset)
    core.console(wr_template:format(wr_value, password))
end

local function main(args)

    --[[
    Basically it does the following,

    1. hw tear
    2. lf em 4x05_write
    3. lf em 4x05_read

    The first two commands don't need a feedback from the system, so going with core.console commands.
    Since the read needs demodulation of signal I opted to add that function from cmdlfem4x.c to the core lua scripting
        core.em4x05_read(addr, password)

    --]]
    local n, password, sd, ed

    for o, a in getopt.getopt(args, 'he:s:p:n:') do
        if o == 'h' then return help() end
        if o == 'n' then n = tonumber(a) end
        if o == 'p' then password = a end
        if o == 'e' then ed = tonumber(a) end
        if o == 's' then sd = tonumber(a) end
    end

    password = password or ''
    if #password ~= 8 then
        password = ''
    end

    local word14, err14 =  core.em4x05_read(14, password)
    if err14 then
        return oops(err14)
    end
    local word15, err15 =  core.em4x05_read(15, password)
    if err15 then
        return oops(err15)
    end
    local bit15 = bit.band(0x00008000, word15)
    if bit15 == 0x00008000 then
        rd_value = ('%08X'):format(word15)
        reset(wr_value, password)
    else
        rd_value = ('%08X'):format(word14)
    end
    if rd_value == '00008000' then
        print('Tag already fully unlocked, nothing to do')
        return nil
    end
    local wr_value = '00000000'
    local auto = false
    if n == nil then
        auto = true
        sd = sd or 2000
        ed = ed or 6000
        n = (ed - sd) / 2
    else
        if sd == nil or ed == nil then
            return oops('start and stop delays need to be defined')
        end
        if sd > ed then
            return oops('start delay can\'t be larger than end delay', sd, ed)
        end
    end

    print('==========================================')
    print('Starting EM4x05 tear-off : target PROTECT')

    if password ~= '' then
        print('target pwd', password)
    end
    if auto then
        print('automatic mode', 'enabled')
    end
    print('target stepping', n)
    print('target delay', sd ,ed)
    print('read value', rd_value)
    print('write value', wr_value)
    print('==========================================')

    local res_tear = 0
    local res_nowrite = 0

    -- fix at one specific delay
    if sd == ed then
       n = 0
    end

    local tries = 0
    local soon = 0
    local late = 0
    while sd <= ed do

        if auto and n < 1 then -- n is a float
            print('[!] Reached n < 1                       => '..ansicolors.yellow..'disabling automatic mode'..ansicolors.reset)
            ed = sd
            auto = false
            n = 0
        end
        if not auto then
            sd = sd + n
        end
        if (tries >= 5) and (n == 0) and (soon ~= late) then
            if soon > late then
                print(('[!] Tried %d times, soon:%i late:%i        => '):format(tries, soon, late)..ansicolors.yellow..'adjusting delay by +1 us'..ansicolors.reset)
                sd = sd + 1
                ed = ed + 1
            else
                print(('[!] Tried %d times, soon:%i late:%i        => '):format(tries, soon, late)..ansicolors.yellow..'adjusting delay by -1 us'..ansicolors.reset)
                sd = sd - 1
                ed = ed - 1
            end
            tries = 0
            soon = 0
            late = 0
        end

        io.flush()
        if core.kbd_enter_pressed() then
            print("aborted by user")
            break
        end

        core.clearCommandBuffer()

        local c = set_tearoff_delay:format(sd)
        core.console(c);

        c = wr_template:format(wr_value, password)
        core.console(c)

        word14, err14 =  core.em4x05_read(14, password)
        if err14 then
            return oops(err14)
        end

        local wordstr14 = ('%08X'):format(word14)

        word15, err15 =  core.em4x05_read(15, password)
        if err15 then
            return oops(err15)
        end

        local wordstr15 = ('%08X'):format(word15)

        print(('[=] ref:'..rd_value..' 14:%08X 15:%08X '):format(word14, word15))


        if wordstr14 == rd_value and wordstr15 == '00000000' then
            print('[=] Status: Nothing happened            => '..ansicolors.green..'tearing too soon'..ansicolors.reset)
            if auto then
                sd = sd + n
                n = n / 2
                print(('[+] Adjusting params: n=%i sd=%i ed=%i'):format(n, sd, ed))
            else
                soon = soon + 1
            end
        else
            if wordstr15 == rd_value then
                if wordstr14 == '00000000' then
                    print('[=] Status: Protect succeeded           => '..ansicolors.green..'tearing too late'..ansicolors.reset)
                else
                    if wordstr14 == rd_value then
                        print('[=] Status: 15 ok, 14 not yet erased    => '..ansicolors.green..'tearing too late'..ansicolors.reset)
                    else
                        print('[=] Status: 15 ok, 14 partially erased  => '..ansicolors.green..'tearing too late'..ansicolors.reset)
                    end
                end
                reset(wr_value, password)
                -- it could still happen that a bitflip got committed, let's check...
                local word14b, err14b =  core.em4x05_read(14, password)
                if err14b then
                    return oops(err14b)
                end
                local wordstr14b = ('%08X'):format(word14b)
                if (wordstr14b == '00000000') then
                    reset(wr_value, password)
                    word14b, err14b =  core.em4x05_read(14, password)
                    if err14b then
                        return oops(err14b)
                    end
                end
                if (wordstr14b ~= rd_value) then
                    local word15b, err15b =  core.em4x05_read(15, password)
                    if err15b then
                        return oops(err15b)
                    end
                    print(('[=] Status: new definitive value!       => '..ansicolors.red..'SUCCESS:   '..ansicolors.reset..'14: '..ansicolors.cyan..'%08X'..ansicolors.reset..'  15: %08X'):format(word14b, word15b))
                    return exit_msg()
                end
                if auto then
                    ed = sd
                    sd = sd - n
                    n = n / 2
                    print(('[+] Adjusting params: n=%i sd=%i ed=%i'):format(n, sd, ed))
                else
                    late = late + 1
                end
            else
                bit15 = bit.band(0x00008000, word15)
                if bit15 == 0x00008000 then
                    print(('[=] Status: 15 bitflipped and active    => '..ansicolors.red..'SUCCESS?:  '..ansicolors.reset..'14: %08X  15: '..ansicolors.cyan..'%08X'..ansicolors.reset):format(word14, word15))
                    print('[+] Committing results...')
                    reset(wr_value, password)
                    local word14b, err14b =  core.em4x05_read(14, password)
                    if err14b then
                        return oops(err14b)
                    end
                    local wordstr14b = ('%08X'):format(word14b)
                    local word15b, err15b =  core.em4x05_read(15, password)
                    if err15b then
                        return oops(err15b)
                    end
                    local wordstr15b = ('%08X'):format(word15b)
                    print(('[=] ref:'..rd_value..' 14:%08X 15:%08X '):format(word14b, word15b))

                    bit15 = bit.band(0x00008000, word14b)
                    if bit15 == 0x00008000 then
                        if (wordstr14b == wordstr15) then
                            print(('[=] Status: confirmed                   => '..ansicolors.red..'SUCCESS:   '..ansicolors.reset..'14: '..ansicolors.cyan..'%08X'..ansicolors.reset..'  15: %08X'):format(word14b, word15b))
                            return exit_msg()
                        end
                        if (wordstr14b ~= rd_value) then
                            print(('[=] Status: new definitive value!       => '..ansicolors.red..'SUCCESS:   '..ansicolors.reset..'14: '..ansicolors.cyan..'%08X'..ansicolors.reset..'  15: %08X'):format(word14b, word15b))
                            return exit_msg()
                        end
                        print(('[=] Status: failed to commit bitflip        => '..ansicolors.red..'FAIL:      '..ansicolors.reset..'14: %08X  15: %08X'):format(word14b, word15b))
                    else
                        print(('[=] Status: failed to commit                => '..ansicolors.red..'FAIL:      '..ansicolors.reset..'14: %08X  15: %08X'):format(word14b, word15b))
                    end
                    if auto then
                        n = 0
                        ed = sd
                    else
                        tries = 0
                        soon = 0
                        late = 0
                    end
                else
                    print(('[=] Status: 15 bitflipped but inactive  => '..ansicolors.yellow..'PROMISING: '..ansicolors.reset..'14: %08X  15: '..ansicolors.cyan..'%08X'..ansicolors.reset):format(word14, word15))
                end
            end
        end
        if not auto then
            tries = tries + 1
        end
    end
end

--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
