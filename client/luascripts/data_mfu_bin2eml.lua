-- The getopt-functionality is loaded from pm3/getopt.lua
-- Have a look there for further details
getopt = require('getopt')
bin = require('bin')
local ansicolors  = require('ansicolors')

copyright = ''
author = "Martin Holst Swende \n @Marshmellow \n @iceman"
version = 'v1.0.4'
desc =[[
This script takes a dumpfile from 'hf mfu dump' and converts it to a format that can be used
by the emulator
]]
example = [[
    script run data_mfu_bin2eml -i dumpdata-foobar.bin
]]
usage = [[
script run data_mfu_bin2eml [-i <file>] [-o <file>]
]]
arguments = [[
    -h              This help
    -i <file>       Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used
    -o <filename>   Specifies the output file. If omitted, <uid>.eml is used.

]]

local DEBUG = false

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

local function convert_to_ascii(hexdata)
    if string.len(hexdata) % 8 ~= 0 then
        return oops(("Bad data, length should be a multiple of 8 (was %d)"):format(string.len(hexdata)))
    end

    local js,i = "[";
    for i = 1, string.len(hexdata),8 do
        js = js .."'" ..string.sub(hexdata,i,i+7).."',\n"
    end
    js = js .. "]"
    return js
end

local function readdump(infile)
     t = infile:read('*all')
     len = string.len(t)
     local len,hex = bin.unpack(('H%d'):format(len),t)
     return hex
end

local function convert_to_emulform(hexdata)
    if string.len(hexdata) % 8 ~= 0 then
        return oops(('Bad data, length should be a multiple of 8 (was %d)'):format(string.len(hexdata)))
    end
    local ascii,i = '';
    for i = 1, string.len(hexdata), 8 do
        ascii = ascii..string.sub(hexdata, i, i+7)..'\n'
    end
    return string.sub(ascii, 1, -2)
end

local function main(args)

    local input = 'dumpdata.bin'
    local output

    for o, a in getopt.getopt(args, 'i:o:h') do
        if o == 'h' then return help() end
        if o == 'i' then input = a end
        if o == 'o' then output = a end
    end
    -- Validate the parameters

    local infile = io.open(input, 'rb')
    if infile == nil then
        return oops('Could not read file ', input)
    end
    local dumpdata = readdump(infile)
    -- The hex-data is now in ascii-format,

    -- But first, check the uid
    -- lua uses start index and endindex,  not count.
    -- UID is  3three skip bcc0 then 4bytes.
    -- 1 lua is one-index.
    -- 1 + 112 (56*2)  new dump format has version/signature/counter data here
    -- 113,114,115,116,117,118   UID first three bytes
    -- 119,120 bcc0
    -- 121---  UID last four bytes
    local uid = string.sub(dumpdata, 113, 113+5)..string.sub(dumpdata, 113+8, 113+8+7)
    output = output or (uid .. '.eml')

    -- Format some linebreaks
    dumpdata = convert_to_emulform(dumpdata)

    local outfile = io.open(output, 'w')
    if outfile == nil then
        return oops('Could not write to file ', output)
    end

    outfile:write(dumpdata:lower())
    io.close(outfile)
    print(('[+] Wrote an emulator-dump to the file %s'):format(output))
end

--[[
In the future, we may implement so that scripts are invoked directly
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.
--]]
main(args)
