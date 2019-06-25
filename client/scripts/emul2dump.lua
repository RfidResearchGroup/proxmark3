local getopt = require('getopt')
local bin = require('bin')
local dumplib = require('html_dumplib')

copyright = ''
author = 'Iceman'
version = 'v1.0.1'
desc =[[
This script takes an dumpfile on EML (ASCII) format and converts it to the PM3 dumpbin file to be used with `hf mf restore`
]]
example =[[
    1. script run emul2dump
    2. script run emul2dump -i myfile.eml
    3. script run emul2dump -i myfile.eml -o myfile.bin
]]
usage = [[
script run emul2dump [-i <file>] [-o <file>]

Arguments:
    -h              This help
    -i <filename>   Specifies the dump-file (input). If omitted, 'dumpdata.eml' is used
    -o <filename>   Specifies the output file. If omitted, <currdate>.bin is used.

]]
---
-- This is only meant to be used when errors occur
local function oops(err)
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
--
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

local function main(args)

    local input = 'dumpdata.eml'
    local output  = os.date('%Y-%m-%d_%H%M%S.bin');

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hi:o:') do
        if o == 'h' then return help() end
        if o == 'i' then input = a end
        if o == 'o' then output = a end
    end

    local filename, err = dumplib.convert_eml_to_bin(input,output)
    if err then return oops(err) end

    ExitMsg(('Wrote a BIN dump to the file %s'):format(filename))
end

main(args)
