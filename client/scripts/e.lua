local getopt = require('getopt')
local utils = require('utils')

copyright = ''
author = 'Iceman'
version = 'v1.0.1'
desc = [[
This script calculates many checksums (CRC) over the provided hex input.
]]
example = [[
    script run e -b 010203040506070809
    script run e -b 010203040506070809 -w 16
]]
usage = [[
Arguments:
     -b       data in hex
     -w       bitwidth of the CRC family of algorithm. <optional> defaults to all known CRC presets.
]]
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
    print('Example usage')
    print(example)
    print(usage)
end
---
-- The main entry point
function main(args)

    local data
    local width = 0

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hb:w:') do
        if o == 'h' then return help() end
        if o == 'b' then data = a end
        if o == 'w' then width = a end
    end

    data = data or '01020304'
    width = width or 0

    print( string.rep('-',60) )
    print('Bit width of CRC | '..width)
    print('Bytes            | '..data)
    print('')
    print( ('%-20s| %-16s| %s'):format('Model','CRC', 'CRC reverse','bigEnd', 'bigEnd','little','little'))
    print( string.rep('-',60) )
    local lists, err = core.reveng_models(width)
    if lists == nil then return oops(err) end

    for _,i in pairs(lists) do
        if string.len(i) > 1 then
            local a1 = core.reveng_runmodel(i, data, false, '0')
            local a2 = core.reveng_runmodel(i, data, true, '0')
            local a3 = core.reveng_runmodel(i, data, false, 'b')
            local a4 = core.reveng_runmodel(i, data, false, 'B')
            local a5 = core.reveng_runmodel(i, data, false, 'l')
            local a6 = core.reveng_runmodel(i, data, false, 'L')
            print( ('%-20s| %-16s| %-16s| %-16s| %-16s| %-16s| %-16s'):format(i, a1:upper(), a2:upper(),a3:upper(),a4:upper(),a5:upper(),a6:upper() ) )
        end
    end
end

main(args)
