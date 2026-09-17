local getopt = require('getopt')
local ansicolors  = require('ansicolors')
local utils = require('utils')

copyright = ''
author = 'whiteneon'
version = 'v1.0.0'
desc = [[
This script attempts to reset the password
 - on a T55xx LF chip.
 ]]
example = [[
     script run lf_t55xx_reset
]]
usage = [[
script run lf_t55xx_reset -h
]]
arguments = [[
    -h             : this help
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
---
-- The main entry point
function main(args)
    local dash = string.rep('--', 20)

    print( dash )
    print( dash )
    print()

    -- Read the parameters
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    print('Attempting T55xx chip reset')
    print(dash)
--    core.console('lf t55 write -b 0 -d 000880E0 --r0 -t')
--    core.console('lf t55 write -b 0 -d 000880E0 --r1 -t')
--    core.console('lf t55 write -b 0 -d 000880E0 --r2 -t')
--    core.console('lf t55 write -b 0 -d 000880E0 --r3 -t')
    core.console('lf t55 write -b 0 -d 000880E0 --r0')
    core.console('lf t55 write -b 0 -d 000880E0 --r1')
    core.console('lf t55 write -b 0 -d 000880E0 --r2')
    core.console('lf t55 write -b 0 -d 000880E0 --r3')
    core.console('lf t55 wipe')
    core.console('lf t55 detect')
    print(dash)
    print('all done!')

end

main(args)
