local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')
local os = require('os')
local dash = string.rep('--', 32)
local dir = os.getenv('HOME') .. '/.proxmark3/logs/'
local logfile = (io.popen('dir /a-d /o-d /tw /b/s "' .. dir .. '" 2>nul:'):read("*a"):match("%C+"))
local pm3 = require('pm3')
p = pm3.pm3()
local command = core.console
command('clear')

author = '  Author: jareckib - 15.02.2025'
version = '  version v1.02'
desc = [[
  This simple script first checks if a password has been set for the T5577.
  It uses the dictionary t55xx_default_pwds.dic for this purpose. If a password
  is found, it uses the wipe command to erase the T5577. Then the reanimation
  procedure is applied. If the password is not found or doesn't exist the script
  only performs the reanimation procedure. The script revives 99% of blocked tags.
 ]]
usage = [[
  script run lf_t55xx_fix
]]
arguments = [[
  script run lf_t55xx_fix -h    : this help
]]

local function help()
    print()
    print(author)
    print(version)
    print(desc)
    print(ac.cyan..'  Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'  Arguments'..ac.reset)
    print(arguments)
end

local function read_log_file(logfile)
    local file = io.open(logfile, "r")
    if not file then
        return nil
    end
    local content = file:read("*all")
    file:close()
    return content
end

local function sleep(n)
    os.execute("sleep " ..tonumber(n))
end

function wait(msec)
   local t = os.clock()
   repeat
   until os.clock() > t + msec * 1e-3
end

local function timer(n)
    while n > 0 do
        io.write("::::: "..ac.yellow.. tonumber(n) ..ac.yellow.." sec "..ac.reset..":::::\r")
        sleep(1)
        io.flush()
        n = n-1
    end
end

local function extract_password(log_content)
    for line in log_content:gmatch("[^\r\n]+") do
        local password = line:match('%[%+%] found valid password: %[ (%x%x%x%x%x%x%x%x) %]')
        if password then
            return password
        end
    end
    return nil
end

local function reset_log_file()
    local file = io.open(logfile, "w+")
    file:write("")
    file:close()
end

local function reanimate_t5577(password)
    if password then
        p:console('lf t55 wipe -p ' .. password)
        print("T5577 wiped using a password: " ..ac.green.. password ..ac.reset)
    else
        print(ac.yellow.."  No valid password found, proceeding with reanimation."..ac.reset)
    end

    p:console('lf t55 write -b 0 -d 000880E8 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r0 -t -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r1 -t -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r2 -t -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r3 -t -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --r0 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --r1 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --r2 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --r3 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r0 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r1 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r2 -p 00000000')
    p:console('lf t55 write -b 0 -d 000880E0 --pg1 --r3 -p 00000000')
    reset_log_file()
end

local function main(args)
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end
    p:console('clear')
    print(dash)
    print('I am initiating the repair process for '..ac.cyan..'T5577'..ac.reset)
    io.write("Place the" .. ac.cyan .. " T5577 " .. ac.reset .. "tag on the coil and press" .. ac.green .. " ENTER " .. ac.reset .. "to continue..")
    io.read()
    print(dash)
    print("::: "..ac.cyan.."Hold on, I'm searching for a password in the dictionary"..ac.reset.." :::")
    print(dash)
    p:console('lf t55 chk')
    local log_content = read_log_file(logfile)
    local password = log_content and extract_password(log_content) or nil
    reanimate_t5577(password)
    p:console('lf t55 detect')
    p:console('lf t55 read -b 0')
    timer(5)
    local success = false
    for line in p.grabbed_output:gmatch("[^\r\n]+") do
        if line:find("00 | 000880E0 |") then
            success = true
            break
        end
    end

    if success then
        print('Recovery of '..ac.cyan..'T5577'..ac.reset..' was successful !!!')
    else
        print('Recovery of '..ac.cyan..'T5577'..ac.reset..' was unsuccessful !!!')
    end
    print(dash)
end

main(args)
