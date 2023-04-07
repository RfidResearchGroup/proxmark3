--
-- hf_mf_sim_hid.lua - A tool to clone a large number of tags at once.
-- Adapted from lf_hid_bulkclone.lua
-- Created 16.08.2022
local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = "Michael Micsen"
version = 'v0.0.1'
desc = [[
Perform simulation of Mifare credentials with HID encoding
This script only supports: H10301
]]
example = [[
    --
    script run hf_mf_sim_hid.lua -f 1 -c 10000
]]
usage = [[
script run hf_mf_sim_hid.lua -f facility -c card_number
]]
arguments = [[
    -h      : this help
    -f      : facility id
    -c      : starting card id
]]
local DEBUG = true
--local bxor = bit32.bxor
local bor = bit32.bor
local lshift = bit32.lshift
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
--[[Implement a function to simply visualize the bitstream in a text format
--This is especially helpful for troubleshooting bitwise math issues]]--
local function toBits(num,bits)
    -- returns a table of bits, most significant first.
    bits = bits or math.max(1, select(2, math.frexp(num)))
    local t = {} -- will contain the bits
    for b = bits, 1, -1 do
        t[b] = math.fmod(num, 2)
        num = math.floor((num - t[b]) / 2)
    end
    return table.concat(t)
end

--[[
  Likely, I'm an idiot, but I couldn't find any parity functions in Lua
  This can also be done with a combination of bitwise operations (in fact,
  is the canonically "correct" way to do it, but my brain doesn't just
  default to this and so counting some ones is good enough for me
]]--
local function evenparity(s)
    local _, count = string.gsub(s, '1', '')
    local p = count % 2
    if (p == 0) then
        return false
    else
        return true
    end
end

local function isempty(s)
    return s == nil or s == ''
end

--[[
  The Proxmark3 "clone" functions expect the data to be in hex format so
  take the card id number and facility ID as arguments and construct the
  hex.  This should be easy enough to extend to non 26bit formats
]]--
local function cardHex(i, f)

    fac = lshift(f, 16)
    id = bor(i, fac)
    stream = toBits(id, 24)

    --As the function defaults to even parity and returns a boolean,
    --perform a 'not' function to get odd parity
    high = evenparity(string.sub(stream,1,12)) and 1 or 0
    low =  not evenparity(string.sub(stream,13)) and 1 or 0
    bits = bor( lshift(id, 1), low)
    bits = bor( bits, lshift(high, 25))

    --Add sentinel bit
    sentinel = lshift(1, 26)
    bits = bor(bits, sentinel)


    return ('%08x'):format(bits)
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
            if isempty(a) then
                print('You did not supply a facility code, using 0')
                facility = 0
            else
                facility = a
            end
        end
        if o == 'c' then
            print(a)
            if isempty(a) then return oops('You must supply the flag -c (card number)1') end
            cardnum = a
        end
    end

    --Due to my earlier complaints about how this specific getopt library
    --works, specifying ':' does not enforce supplying a value, thus we
    --need to do these checks all over again.
    if isempty(cardnum) then return oops('You must supply the flag -c (card number)2') end
    --If the facility ID is non specified, ensure we code it as zero
    if isempty(facility) then
        print('Using 0 for the facility code as -f was not supplied')
        facility = 0
    end

    -- Write the MAD to read for a Mifare HID credential
    core.console('hf mf esetblk -b 1 -d 1B014D48000000000000000000000000')
    core.console('hf mf esetblk -b 3 -d A0A1A2A3A4A5787788C189ECA97F8C2A')
    --Write the sector trailer for the credential sector
    core.console('hf mf esetblk -b 7 -d 484944204953787788AA204752454154')
    local cardh = cardHex(cardnum, facility)
    print('Hex')
    print(cardh)
    core.console( ('hf mf esetblk -b 5 -d 020000000000000000000000%s'):format(cardh) )

    core.console('hf mf sim --1k -i')
end

main(args)
