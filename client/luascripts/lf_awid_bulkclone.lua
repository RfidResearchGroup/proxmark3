local getopt = require('getopt')


copyright = ''
author = "TheChamp669"
version = 'v1.0.0'
desc = [[
Perform bulk enrollment of 26 bit AWID style RFID Tags
For more info, check the comments in the code
]]
example = [[
    --
    script run lf_awid_bulkclone.lua -f 1 -b 1000 
]]
usage = [[
script run lf_awid_bulkclone.lua -f facility -b base_id_num
]]
arguments = [[
    -h      : this help
    -f      : facility id
    -b      : starting card id
]]
local DEBUG = true
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
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

local function showHelp()
    print("Usage: script run <scriptname> [-h]")
    print("Options:")
    print("-h \t This help")
end

local function main(args)


    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    for o, a in getopt.getopt(args, 'f:b:c:h') do
        if o == 'h' then return help() end
        if o == 'f' then
            if isempty(a) then
                print('You did not supply a facility code, using 255')
                fc = 255
            else
                fc = a
            end
        end
        if o == 'b' then
            if isempty(a) then 
                print('You did not supply a starting card number, using 59615')
                cn = 59615
            else
                cn = a
            end
        end
    end

    -- Example starting values
    local sessionStart = os.date("%Y_%m_%d_%H_%M_%S")  -- Capture the session start time

    print("Session Start: " .. sessionStart)
    print("Facility Code,Card Number")
    
    while true do
        print(string.format("Preparing to Write: Facility Code %d, Card Number %d", fc, cn))
        
        local command = string.format("lf awid clone --fmt 26 --fc %d --cn %d", fc, cn)
        core.console(command)
        
        print(string.format("%d,%d", fc, cn))
        
        print("Press Enter to continue with the next card number or type 'q' and press Enter to quit.")
        local user_input = io.read()
        
        if user_input:lower() == 'q' then
            break
        else
            cn = cn + 1
        end
    end
end

main(args)