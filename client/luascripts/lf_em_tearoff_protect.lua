local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = 'Iceman'
author =  [[
'Author   Iceman
 CoAuthor Doegox
]]
version = 'v1.0.1'
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

local set_tearoff_delay = 'hw tearoff -s --on --delay %d'
local wr_template = 'lf em 4x05_write %s %s %s'

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
    print('1.  lf em 4x05_write 99 00000000')
    print('2.  lf em 4x05_dump')
    print('===============================================')    
    return nil
end

local function reset(wr_value, password)
    print('[=] '..ansicolors.red..'reseting the active lock block'..ansicolors.reset)
    core.console(wr_template:format(99, wr_value, password))
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
    
    for o, a in getopt.getopt(args, 'he:s:p:n:') do
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
    local bit15 = bit.band(0x00008000, word15)
    if bit15 == 0x00008000 then
        rd_value = ('%08X'):format(word15)
    else
        rd_value = ('%08X'):format(word14)
    end
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
    
    -- fix at one specific delay
    if sd == ed then
       n = 0
    end

    local locked_on = false
    local tries = 0
    while sd <= ed do
    
        -- increase loop
        sd = sd + n
        
        if not locked_on then 
            if (tries == 10) and (n == 0) then
                print(ansicolors.cyan..('[!] Tried %d times, increased delay with 1us'):format(tries)..ansicolors.reset)
                tries = 0
                sd = sd + 1
                ed = ed + 1 
            end
        end
    
        io.flush()
        if core.kbd_enter_pressed() then
            print("aborted by user")
            break
        end

        core.clearCommandBuffer()

        local c = set_tearoff_delay:format(sd)
        core.console(c);

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
        
        if wordstr14 == rd_value and wordstr15 ~= wr_value then
            print(('[!] '..ansicolors.cyan..'TEAR OFF'..ansicolors.reset..' occurred: 14: %08X  15: '..ansicolors.cyan..'%08X'..ansicolors.reset):format(word14, word15))
        end
        
        if wordstr14 == rd_value then
            if wordstr15 ~= rd_value and  wordstr15 ~= wr_value then
                print(('[!] '..ansicolors.red..'TEAR OFF bitflip: '..ansicolors.reset..' 14: %08X  15: %08X'):format(word14, word15))
                
                
                bit15 = bit.band(0x00008000, word15)
                if bit15 == 0x00008000 then
                    return exit_msg()
                else
                    reset(wr_value, password)
                    print('[+] locked on to this delay')
                    locked_on = true
                end
            end
            
            if wordstr15 == rd_value then
                reset(wr_value, password)
                if not locked_on then  
                    tries = 0
                end
            end
        else        
            print('...write ok, erase not done', wordstr14, rd_value)
        end
        
        if not locked_on then 
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
