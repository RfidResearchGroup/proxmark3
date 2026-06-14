local getopt = require('getopt')
local utils = require('utils')
local ansicolors  = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.3'
desc = [[
This script calculates many checksums (CRC) over the provided hex input.
]]
example = [[
    script run data_hex_crc -d 010203040506070809
    script run data_hex_crc -d 010203040506070809 -w 16
    script run data_hex_crc -d 010203040506070809 -w 16 -s 47ED
]]
usage = [[
script run data_hex_crc [-d <hex bytes] [-w <width>]
]]
arguments = [[
     -d       data in hex
     -s       search for a value in the calculated crc and mark it green
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

    local search
    local data
    local width = 0

    -- Read the parameters
    for o, a in getopt.getopt(args, 'hd:w:s:') do
        if o == 'h' then return help() end
        if o == 'd' then data = a end
        if o == 's' then search = a end
        if o == 'w' then width = a end
    end

    -- sanitize lua args parsing
    data = data or '01020304'
    width = width or 0
    search = search or 0

    local seplen = math.min(math.max(#('CRC width... '..width), #('Bytes....... '..data)), 80)
    local sep = string.rep('-', seplen)

    -- header
    print('')
    print(ansicolors.cyan.. 'CRC calculations' .. ansicolors.reset)
    print(sep)
    print('CRC width... '..width)
    print('Bytes....... ' .. ansicolors.green .. data .. ansicolors.reset)
    print(sep)
    print('')

    local lists, err = core.reveng_models(width)

    if lists == nil then return oops(err) end

    -- first pass: compute all values and find max CRC length
    local results = {}
    local maxlen = 0
    for _,i in pairs(lists) do
        if string.len(i) > 1 then

            --  model name,  hex,  reverse,  endian
            local a1 = core.reveng_runmodel(i, data, false, '0'):upper()
            local a2 = core.reveng_runmodel(i, data, true,  '0'):upper()
            local a3 = core.reveng_runmodel(i, data, false, 'b'):upper()
            local a4 = core.reveng_runmodel(i, data, false, 'B'):upper()
            local a5 = core.reveng_runmodel(i, data, false, 'l'):upper()
            local a6 = core.reveng_runmodel(i, data, false, 'L'):upper()

            results[#results+1] = {i, a1, a2, a3, a4, a5, a6}

            for _, v in ipairs({a1, a2, a3, a4, a5, a6}) do
                if #v > maxlen then
                    maxlen = #v
        end
            end
        end
    end

    table.sort(results, function(a, b)
        local na = tonumber(a[1]:match('^%a+%-(%d+)')) or 0
        local nb = tonumber(b[1]:match('^%a+%-(%d+)')) or 0
        if na ~= nb then return na < nb end
        return a[1]:lower() < b[1]:lower()
    end)

    -- column width = crc length + one space each side
    local cw = maxlen + 2

    local hcols = {
        {'',    'CRC'},
        {'CRC', 'rev'},
        {'',     'be'},
        {'',     'BE'},
        {'',     'le'},
        {'',     'LE'},
    }

    local function hrow(line)
        local cells = {}
        for _, h in ipairs(hcols) do
            cells[#cells+1] = ('%-'..(cw - 1)..'s'):format(h[line])
        end
        return cells
    end

    print(('%-24s| '):format('')       .. table.concat(hrow(1), '| '))
    print(('%-24s| '):format('Model') .. table.concat(hrow(2), '| '))
    print( string.rep('-', 26 + (cw + 1) * 6) )

    local row = 0
    for _, entry in ipairs(results) do
        local name = entry[1]
        row = row + 1
        local base = (row % 2 == 1) and ansicolors.yellow or ''

        local function fmt(v)
            local cell = ('%-'.. (cw-1) ..'s'):format(v)  -- one space left pad, right-pad to cw
            if search ~= 0 and v == search:upper() then
                return ansicolors.green .. cell .. ansicolors.reset .. base
            end
            return cell
        end

        local values = fmt(entry[2]) ..'| '.. fmt(entry[3]) ..'| '.. fmt(entry[4]) ..'| '.. fmt(entry[5]) ..'| '.. fmt(entry[6]) ..'| '.. fmt(entry[7])
        print(base .. ('%-24s| '):format(name) .. values .. ansicolors.reset)
    end
end

main(args)
