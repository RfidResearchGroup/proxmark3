local getopt = require('getopt')
local cmds = require('commands')


copyright = ''
author = "TheChamop669"
version = 'v1.0.0'
desc = [[
Perform bulk enrollment of 26 bit IO Prox / Kantech style RFID Tags
The vnc is set to 2.
For more info, check the comments in the code
]]
example = [[
    --
    script run lf_ioprox_bulkclone.lua -f 1 -b 1000
]]
usage = [[
script run lf_ioprox_bulkclone.lua -f facility -b base_id_num
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

local function main(args)
    
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    for o, a in getopt.getopt(args, 'f:b:h') do
        if o == 'h' then return help() end
        if o == 'f' then
            if isempty(a) then
                print('You did not supply a facility code, using 0')
                fc = 0
            else
                fc = a
            end
        end
        if o == 'b' then
            if isempty(a) then return oops('You must supply the flag -b (starting card number)') end
            cn = a
        end
    end

    local successful_writes = {}
    local timestamp = os.date('%Y-%m-%d %H:%M:%S', os.time())

    while true do
        print(string.format("Setting fob to Facility Code: %d, Card Number: %d", fc, cn))

        -- Writing to block 0 with the specific data for ioProx card format
        core.console("lf t55xx write -b 0 -d 00147040")

        -- Command to set facility code and card number on the fob
        local command = string.format("lf io clone --vn 2 --fc %d --cn %d", fc, cn)
        core.console(command)

        table.insert(successful_writes, string.format("%d,%d", fc, cn))
        print("Fob created successfully.")

        print("Press Enter to create the next fob, type 'r' and press Enter to retry, or type 'q' and press Enter to quit.")
        local user_input = io.read()

        if user_input:lower() == 'q' then
            print("Timestamp: ", timestamp)
            print("Successful Writes:")
            for _, v in ipairs(successful_writes) do print(v) end
            break
        elseif user_input:lower() ~= 'r' then
            cn = cn + 1
        end
    end
end

main(args)
