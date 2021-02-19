local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')

copyright = ''
author = "Christian Herrmann"
version = 'v1.0.0'
desc = [[
Perform bulk EM410x enrollment of T5577 RFID tags.  It keeps track of last card id used.
If called with -s,  this value resets "session".

if press <enter>  it defaults to Y,  which writes a ID.
Any other input char will exit the script.

]]
example = [[
    -- resets and start enrolling EM410x id 11CC334455    
    script run lf_em4100_bulk.lua -s 11CC334455

    -- continue enrolling from where last iteration
    script run lf_em4100_bulk.lua -c
]]
usage = [[
script run lf_en4100_bulk.lua [-h] [-c] [-s <start cn>]
]]
arguments = [[
    -h      : this help
    -c      : continue from last card number used
    -s      : starting card number
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
    local cn = tonumber(t, 16)
    print(('Using EM4100 ID '..ac.green..'%010X'..ac.reset..' from `'..ac.yellow..'%s'..ac.reset..'`'):format(cn, ENROLL_STATUS_FN))
    return cn
end
---
--
local function writefile(cn)
    local f = io.open(ENROLL_STATUS_FN, "w")
    if f == nil then
        return nil, string.format("Could not write to file %s", ENROLL_STATUS_FN)
    end
    f:write(("%010X\n"):format(cn))
    f:close()
    print(('Wrote EM4100 ID '..ac.green..'%010X'..ac.reset..' to `'..ac.yellow..'%s'..ac.reset..'`'):format(cn, ENROLL_STATUS_FN))
    return true, 'Ok'
end

---
-- main
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    local shall_continue = false
    local startid = ''

    for o, a in getopt.getopt(args, 'cs:h') do
        if o == 'h' then return help() end
        if o == 'c' then
            shall_continue = true
        end
        if o == 's' then startid = a end
    end

    -- if reset/start over, check -s
    if not shall_continue then 
        if startid == nil then return oops('empty card number string') end
        if #startid == 0 then return oops('empty card number string') end
        if #startid ~= 10 then return oops('card number wrong length. Should be 5 hex bytes') end
    end

    core.console('clear')
    print(ac.red..'disable hints for less output'..ac.reset)
    core.console('pref set hint --off')
    print('')
    
    local sid = tonumber(startid, 16)    
    if shall_continue then
        print('Continue enrolling from last save')
        sid = readfile()
    else
        print('reset & starting enrolling from refresh')
    end
   
    local template = 'EM4100 ID '..ac.green..'%010X'..ac.reset
    local curr = sid
    for i = sid, sid + 10000, 1 do
        curr = i

        print('')
        print( string.rep('--',20) )
        local msg = (template):format(curr)
        local ans = utils.input(msg, 'y'):lower()
        if ans == 'y' then
            core.console( ('lf em 410x clone --id %010X'):format(curr) )
            --        print ( ('lf em 410x clone --id %010X'):format(curr) )
        else
            print(ac.red..'User aborted'..ac.reset)
            break
        end
    end
    writefile(curr)

    print('enabling hints again')
    core.console('pref set hint --on')
end

main(args)
