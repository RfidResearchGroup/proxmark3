-- The getopt-functionality is loaded from pm3/getopt.lua
-- Have a look there for further details
getopt = require('getopt')
bin = require('bin')
dumplib = require('html_dumplib')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Martin Holst Swende'
version = 'v1.0.3'
desc =[[
This script takes a dumpfile and produces a html based dump, which is a
bit more easily analyzed.
]]
example = [[
    script run data_mf_bin2html -o mifarecard_foo.html
]]
usage = [[
script run data_mf_bin2html [-i <file>] [-o <file>]
]]
arguments = [[
    -h              This help
    -i <file>       Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used
    -o <filename>   Speciies the output file. If omitted, <curtime>.html is used.

]]
-------------------------------
-- Some utilities
-------------------------------

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
    print('[!!] ERROR:', err)
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

local function main(args)

    local input = 'dumpdata.bin'
    local output = os.date('%Y-%m-%d_%H%M%S.html');
    for o, a in getopt.getopt(args, 'i:o:h') do
        if o == 'h' then return help() end
        if o == 'i' then input = a end
        if o == 'o' then output = a end
    end
    local filename, err = dumplib.convert_bin_to_html(input,output, 16)
    if err then return oops(err) end

    print(('[+] Wrote a HTML dump to the file %s'):format(filename))
end

--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
