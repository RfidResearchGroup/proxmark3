local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local dumplib = require('html_dumplib')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.3'
desc = [[
This script will load several traces files in current working directory/traces/ folder and do
"data load"
"lf search 1 u"

The following tracefiles will be loaded:
   em*.pm3
   modulation*.pm3
]]
example = [[
    1. script run tracetest
]]
usage = [[
script run tracetest [-h]
]]
arguments = [[
    -h             : this help
]]
local DEBUG = true -- the debug flag
---
-- A debug printout-function
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
--
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end


local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local cmdDataLoad = 'data load %s';
    local cwd = core.cwd();

    local tracesEM = "find '"..cwd.."/traces/ ' -iname 'em*.pm3' -type f"
    local tracesMOD = "find '"..cwd.."/traces/' -iname 'modulation*.pm3' -type f"

    local write2File = false
    local outputTemplate = os.date('testtest_%Y-%m-%d_%H%M%S')

    -- Arguments for the script
    for o, arg in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    core.clearCommandBuffer()

    local files = {}

    -- Find a set of traces staring with EM
    local p = assert( io.popen(tracesEM))
    for file in p:lines() do
        table.insert(files, file)
    end
    p.close();

    -- Find a set of traces staring with MODULATION
    p = assert( io.popen(tracesMOD) )
    for file in p:lines() do
        table.insert(files, file)
    end
    p.close();

    local cmdLFSEARCH = 'lf search 1 u'

    -- main loop
    io.write('Starting to test traces > ')
    for _,file in pairs(files) do

        local x = 'data load '..file
        dbg(x)
        core.console(x)

        dbg(cmdLFSEARCH)
        core.console(cmdLFSEARCH)

        core.clearCommandBuffer()

        if core.kbd_enter_pressed() then
            print('aborted by user')
            break
        end
    end
    io.write('\n')

    print( string.rep('--',20) )

end
main(args)
