local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')

copyright = ''
author = "Christian Herrmann"
version = 'v1.0.2'
desc = [[
Perform bulk EM410x enrollment of T5577 RFID tags.  It keeps track of last card id used.
If called with -s,  this value resets "session".

if press <enter>  it defaults to Y,  which writes a ID.
Any other input char will exit the script.

You can supply a password, which will set the config block / block 7 on the T5577.

The verify option will issue a 'lf em 410x reader' command,  so you can manually verify
that the write worked.

]]
example = [[
    -- resets and start enrolling EM410x id 11CC334455
    script run lf_em4100_bulk.lua -s 11CC334455

    -- continue enrolling from where last iteration
    script run lf_em4100_bulk.lua -c

    -- reset and start enrolling from 11223344,
    -- protecting the tag with password 010203
    -- and verify the em id write.
    script run lf_em4100_bulk.lua -s 1122334455 -p 01020304 -v
]]
usage = [[
script run lf_en4100_bulk.lua [-h] [-c] [-p password] [-s <start cn>] [-v]
]]
arguments = [[
    -h      : this help
    -c      : continue from last card number used
    -p      : Password protecting the T5577.
    -s      : starting card number
    -v      : verify write by executing a `lf em 410x reader`
    ]]

    -- Some globals
local DEBUG = false
local ENROLL_STATUS_FN = 'lf_em4100_status.txt'
---
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, errr
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ac.cyan..'Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'Arguments'..ac.reset)
    print(arguments)
    print(ac.cyan..'Example usage'..ac.reset)
    print(example)
end
---
-- Exit message
local function exitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end
---
--
local function readfile()
    local f = io.open(ENROLL_STATUS_FN, "r")
    if f == nil then
        return nil, string.format("Could not read file %s", ENROLL_STATUS_FN)
    end
    local t = f:read("*all")
    f:close()
    local cn_hi  = tonumber(t:sub(1, 2), 16)
    local cn_low = tonumber(t:sub(3, 10), 16)
    print(('Using EM4100 ID '..ac.green..'%02X%08X'..ac.reset..' from `'..ac.yellow..'%s'..ac.reset..'`'):format(cn_hi, cn_low, ENROLL_STATUS_FN))
    return cn_hi, cn_low
end
---
--
local function writefile(cn_hi, cn_low)
    local f = io.open(ENROLL_STATUS_FN, "w")
    if f == nil then
        return nil, string.format("Could not write to file %s", ENROLL_STATUS_FN)
    end
    f:write(("%02X%08X\n"):format(cn_hi, cn_low))
    f:close()
    print(('Wrote EM4100 ID '..ac.green..'%02X%08X'..ac.reset..' to `'..ac.yellow..'%s'..ac.reset..'`'):format(cn_hi, cn_low, ENROLL_STATUS_FN))
    return true, 'Ok'
end

---
-- main
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    local shall_verify = false
    local shall_continue = false
    local got_pwd = false
    local startid = ''
    local ipwd = ''


    for o, a in getopt.getopt(args, 'cp:s:hv') do
        if o == 'h' then return help() end
        if o == 'c' then shall_continue = true end
        if o == 's' then startid = a end
        if o == 'p' then
            ipwd = a
            got_pwd = true
        end
        if o == 'v' then shall_verify = true end
    end

    -- if reset/start over, check -s
    if not shall_continue then
        if startid == nil then return oops('empty card number string') end
        if #startid == 0 then return oops('empty card number string') end
        if #startid ~= 10 then return oops('card number wrong length. Must be 5 hex bytes') end
    end

    if got_pwd then
        if ipwd == nil then return oops('empty password') end
        if #ipwd == 0 then return oops('empty password') end
        if #ipwd ~= 8 then return oops('password wrong length. Must be 4 hex bytes') end
    end

    core.console('clear')
    print(ac.red..'disable hints for less output'..ac.reset)
    core.console('pref set hint --off')
    print('')

    local hi  = tonumber(startid:sub(1, 2), 16)
    local low = tonumber(startid:sub(3, 10), 16)
    local pwd = tonumber(ipwd, 16)

    if got_pwd then
        print(('Will protect T5577 with password '..ac.green..'%08X'..ac.reset):format(pwd))
    end

    if shall_verify then
        print('Will verify write afterwards')
    end

    if shall_continue then
        print('Continue enrolling from last save')
        hi, low = readfile()
    else
        print('reset & starting enrolling from refresh')
    end

    local template = 'EM4100 ID '..ac.green..'%02X%08X'..ac.reset
    for i = low, low + 10000, 1 do
        print('')
        print( string.rep('--',20) )
        local msg = (template):format(hi, i)
        local ans = utils.input(msg, 'y'):lower()
        if ans == 'y' then
            core.console( ('lf em 410x clone --id %02X%08X'):format(hi, i) )
            --        print ( ('lf em 410x clone --id %02X%08X'):format(hi, i) )

            if got_pwd then
                core.console('lf t55 detect')
                core.console(('lf t55 protect -n %08x'):format(pwd))
            end

            if shall_verify then
                core.console('lf em 410x reader')
            end
        else
            print(ac.red..'User aborted'..ac.reset)
            low = i
            break
        end
    end
    writefile(hi, low)

    print('enabling hints again')
    core.console('pref set hint --on')
end

main(args)
