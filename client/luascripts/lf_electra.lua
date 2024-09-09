local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')
local os = require('os')
local count = 0
line = '-------------------------------------------------------------------------'
mod = "                   ELECTRA or EM410x fob cloning SCRIPT "
version = "                   v1.1.17  02/09/2023 made by jareckib "
desc = [[

   Cloning new ELECTRA tags or EM410x to T5577 tag. This script changes
   block 0. Additional data is written to block 3 and 4. The last
   ELECTRA ID can be accessed through the option ---> "-c". For copy
   directly from the original ELECTRA tag, ---> option "-e". For copy
   from input, EM410X ID ---> option "-s". Next option for cloning simple
   EM4102 ---> option "-m". If press  <Enter> it,  which writes an ID.
   If press <n> ---> exit the script.
]]
example = [[
-------------------------------------------------------------------------------

--------------- cloning ELECTRA tag from input ID to T5577 tag ----------------

  script run lf_electra -s 11AA22BB55

----------------- continue cloning from last cloned ELECTRA -------------------

  script run lf_electra -c

----------------------  ELECTRA cloning from the original TAG -----------------

  script run lf_electra -e

----------------------------- simple EM4102 cloning ---------------------------

  script run lf_electra -m

-------------------------------------------------------------------------------
]]
usage = [[
  script run lf_electra.lua [-e] [-h] [-c] [-m] [-s <ID HEX number>]
]]
arguments = [[
    -h      : this help
    -c      : continue cloning from last ID used
    -s      : ELECTRA - EM410x ID HEX number
    -e      : Read original ELECTRA from Proxmark3 device
    -m      : EM410x cloning
    ]]
--------------------------------------Path to logs files
local DEBUG = false
local dir = os.getenv('HOME')..'/.proxmark3/logs/'
local LAST_ID = os.getenv('HOME')..'/.proxmark3/logs/last_id.txt'
local ID_STATUS = (io.popen('dir /a-d /o-d /tw /b/s "'..dir..'" 2>nul:'):read("*a"):match"%C+")
if not ID_STATUS then
   error"No files in this directory"
end
-------------------------------------------A debug printout-function
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
------------------------------------------------- errors
local function oops(err)
    core.console('clear')
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    print(ac.red..'               ERROR:'..ac.reset.. err)
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    return nil, err
end
-----------------------------------------------sleep
local function sleep(n)
    os.execute("sleep " ..tonumber(n))
end
--------------------wait
function wait(msec)
   local t = os.clock()
   repeat
   until os.clock() > t + msec * 1e-3
end
----------------------------------------------time wait
local function timer(n)
    while n > 0 do
        io.write(ac.cyan.."   ::::: "..ac.yellow.. tonumber(n) ..ac.yellow.." sec "..ac.cyan..":::::\r"..ac.reset)
        sleep(1)
        io.flush()
        n = n-1
    end
end
----------------------------------------------------- help
local function help()
    core.console('clear')
    print(line)
    print(ac.cyan..mod..ac.reset)
    print(ac.cyan..version..ac.reset)
    print(ac.yellow..desc..ac.reset)
    print(line)
    print(ac.cyan..'  Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'  Arguments'..ac.reset)
    print(arguments)
    print(line)
    timer(30)
    core.console('clear')
    print(ac.cyan..'  Example usage'..ac.reset)
    print(example)
end
------------------------------------ Exit message
local function exitMsg(msg)
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    print(msg)
    print()
end
--------------------------------- idsearch EM ID
local function id()
    local f = assert(io.open(ID_STATUS, "r"))
    for line in f:lines() do
        id = line:match"^%[%+%] EM 410x ID (%x+)"
        if id then break end
    end
    f:close()
    local  f= io.open(ID_STATUS, "w+")
    f:write(id)
    f:close()
    local  f= io.open(ID_STATUS, "r")
    local t = f:read("*all")
    f:close()
    local hex_hi  = tonumber(t:sub(1, 2), 16)
    local hex_low = tonumber(t:sub(3, 10), 16)
    return hex_hi, hex_low
end
---------------------------------------read file
local function readfile()
    local f = io.open(ID_STATUS, "r")
    for line in f:lines() do
        id = line:match"^(%x+)"
        if id then break end
    end
    f:close()
    if not id then
        return oops ("        ....No ID found in file") end
    local  f= io.open(ID_STATUS, "r")
    local t = f:read("*all")
    f:close()
    local hex_hi  = tonumber(t:sub(1, 2), 16)
    local hex_low = tonumber(t:sub(3, 10), 16)
    return hex_hi, hex_low
end
----------------------------------------last ID
local function IDsaved()
    local f = io.open(LAST_ID, "r")
    for line in f:lines() do
        id = line:match"^(%x+)"
    if id then break end
    end
    f:close()
    if not id then
        return oops ("        ....No ID found in file") end
    local  f= io.open(LAST_ID, "r")
    local t = f:read("*all")
    f:close()
    local hex_hi  = tonumber(t:sub(1, 2), 16)
    local hex_low = tonumber(t:sub(3, 10), 16)
    return hex_hi, hex_low
end
----------------------------------------write file
local function writefile(hex_hi, hex_low)
    local f = io.open(ID_STATUS, "w+")
    local g = io.open(LAST_ID, 'w+')
    f:write(("%02X%08X\n"):format(hex_hi, hex_low))
    f:close()
    g:write(("%02X%08X\n"):format(hex_hi, hex_low))
    g:close()
    print(('  Saved EM410x ID '..ac.green..'%02X%08X'..ac.reset..' to TXT file:'):format(hex_hi, hex_low))
    print((ac.yellow..'  %s'..ac.reset):format(LAST_ID))
    return true, 'Ok'
end
---------------replace line
local last_str = ''
function txt_change(str)
   io.write(('\b \b'):rep(#last_str))  -- old line
   io.write(str)                       -- new line
   io.flush()
   last_str = str
end
---------------------------------------- main
local function main(args)
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    print()
    if #args == 0 then return help() end
    local saved_id = false
    local id_original = false
    local emarine = false
    local input_id = ''
    for o, a in getopt.getopt(args, 'hems:c') do
        if o == 'h' then return help() end
        if o == 'e' then id_original = true end
        if o == 'm' then emarine = true end
        if o == 's' then input_id = a end
        if o == 'c' then saved_id = true end
    end
    --------------------check -id
    if not saved_id and not id_original and not emarine then
        if input_id == nil then return oops('       empty EM410x ID string') end
        if #input_id == 0 then return oops('       empty EM410x ID string') end
        if #input_id < 10 then return oops(' EM410x ID too short. Must be 5 hex bytes') end
        if #input_id > 10 then return oops(' EM410x ID too long. Must be 5 hex bytes') end
    end
    core.console('clear')
    print( string.rep('--',39) )
    print(ac.green..'            ....... OFF THE HINTS WILL BE LESS ON THE SCREEN'..ac.reset)
    print( string.rep('--',39) )
    core.console('pref set hint --off')
    print( string.rep('--',39) )
    timer(4)
    core.console('clear')
    local hi  = tonumber(input_id:sub(1, 2), 16)
    local low = tonumber(input_id:sub(3, 10), 16)
    if saved_id then
        hi, low = IDsaved()
        print( string.rep('--',39) )
        print( string.rep('--',39) )
        print('')
        print(ac.green..'             ......Continue cloning from last saved ID'..ac.reset)
        print('')
        print( string.rep('--',39) )
    end
    if id_original then
        print( string.rep('--',39) )
        print( string.rep('--',39) )
        print('')
        print(ac.green..'                Put the ELECTRA tag on the coil PM3 to read '..ac.reset)
        print('')
        print( string.rep('--',39))
        print(string.rep('--',39))
    end
    if emarine then
        print( string.rep('--',39) )
        print( string.rep('--',39) )
        print('')
        print(ac.green..'                Put the EM4102 tag on the coil PM3 to read '..ac.reset)
        print('')
        print( string.rep('--',39) )
        print( string.rep('--',39) )
    end
    if emarine or id_original then
       io.write('   Press'..ac.yellow..' Enter'..ac.reset..' to continue ... ');io.read()
       txt_change('   Readed TAG : ')
       core.console(' lf em 410x read')
       print( string.rep('--',39) )
       hi, low = id()
       timer(7)
       core.console('clear')
       print( string.rep('--',39) )
       print( string.rep('--',39) )
       print('')
       print(ac.green..'                   Continuation of the cloning process....'..ac.reset)
       print('')
       print( string.rep('--',39) )
    end
    if not emarine and not id_original and not saved_id then
       print( string.rep('--',39) )
       print( string.rep('--',39) )
       print('')
       print(ac.green..'          ........ ELECTRA cloning from Entered EM-ELECTRA ID'..ac.reset)
       print('')
       print( string.rep('--',39) )
    end
    if emarine then
       d = ('EM4102 ID ')
    else
       d =('ELECTRA ID  ')
    end
    local template = ((d)..ac.green..'%02X%08X'..ac.reset)
    for i = low, low + 100, 1 do
        local msg = (template):format(hi, low)
        print( string.rep('--',39) )
        if count > 0 then
            print(('  TAGs created: '..ac.green..'%s'..ac.reset):format(count))
            print( string.rep('--',39) )
        end
        print(('  %s >>>>>> cloning to '..ac.cyan..'T5577 -'..ac.yellow..' Enter'..ac.reset..' for yes or '..ac.yellow..'n'..ac.reset..' for exit'):format(msg))
        print('  Before confirming the cloning operation, put a blank '..ac.cyan..'T5577'..ac.reset..' tag on coil'..ac.cyan..' PM3'..ac.reset..' !')
        print( string.rep('--',39) )
        io.write('  Continue with this operation'..ac.yellow..' (Enter/n)'..ac.reset..' ? > ')
        answer = io.read()
        if answer == 'n' then
            core.console('clear')
            print( string.rep('--',39) )
            print(ac.red..'                                  USER ABORTED'..ac.reset)
            print( string.rep('--',39) )
            break
        end
        core.console('clear')
        print( string.rep('--',39) )
        if emarine then
            core.console( ('lf em 410x clone --id %02X%08X'):format(hi, low) )
        else
            core.console( ('lf em 410x clone --id %02X%08X'):format(hi, low) )
            core.console('lf t55 write -b 0 -d 00148080')
            core.console('lf t55 write -b 3 -d 7E1EAAAA')
            core.console('lf t55 write -b 4 -d AAAAAAAA')
        end
        count = count+1
    end
    writefile(hi, low)
    core.console('pref set hint --on')
    print( string.rep('--',39) )
    if count > 0 then
        print(('  TAGs created: '..ac.green..'%s'..ac.reset):format(count))
        print( string.rep('--',39) )
    end
end
main(args)
