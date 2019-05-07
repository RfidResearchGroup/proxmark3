--
-- lf_bulk.lua - A tool to clone a large number of tags at once.
-- Updated 2017-04-18
-- Updated 2018-02-20 iceman
local getopt = require('getopt')

copyright = ''
author = "Brian Redbeard"
version = 'v1.0.1'
desc = [[
Perform bulk enrollment of 26 bit H10301 style RFID Tags
For more info, check the comments in the code
]]
example = [[
    --
    script run lf_bulk.lua -f 1 -b 1000 -c 10
]]
usage = [[
script run lf_bulk.lua -f facility -b base_id_num -c count

Arguments:
    -h      : this help
    -f      : facility id
    -b      : starting card id
    -c      : count,  number of cards to make
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
    print('Example usage')
    print(example)
    print(usage)
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

    --Since the lua library bit32 is (obviously) 32 bits and we need to
    --encode 36 bits to properly do a 26 bit tag with the preamble we need
    --to create a higher order and lower order component which we will
    --then assemble in the return.  The math above defines the proper
    --encoding as per HID/Weigand/etc.  These bit flips are due to the
    --format length check on bit 38 (cmdlfhid.c:64) and
    --bit 31 (cmdlfhid.c:66).
    preamble = bor(0, lshift(1, 5))
    bits = bor(bits, lshift(1, 26))

    return ('%04x%08x'):format(preamble, bits)
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
    for o, a in getopt.getopt(args, 'f:b:c:h') do
        if o == 'h' then return help() end
        if o == 'f' then
            if isempty(a) then
                print('You did not supply a facility code, using 0')
                facility = 0
            else
                facility = a
            end
        end
        if o == 'b' then
            if isempty(a) then return oops('You must supply the flag -b (base id)') end
            baseid = a
        end
        if o == 'c' then
            if isempty(a) then return oops('You must supply the flag -c (count)') end
            count = a
        end
    end

    --Due to my earlier complaints about how this specific getopt library
    --works, specifying ':' does not enforce supplying a value, thus we
    --need to do these checks all over again.
    if isempty(baseid) then return oops('You must supply the flag -b (base id)') end
    if isempty(count) then return oops('You must supply the flag -c (count)') end

    --If the facility ID is non specified, ensure we code it as zero
    if isempty(facility) then
        print('Using 0 for the facility code as -f was not supplied')
        facility = 0
    end

    --The next baseid + count function presents a logic/UX conflict
    --where users specifying -c 1 (count = 1) would try to program two
    --tags.  This makes it so that -c 0 & -c 1 both code one tag, and all
    --other values encode the expected amount.
    if tonumber(count) > 0 then count = count - 1 end

    endid = baseid + count

    for cardnum = baseid, endid do
        local card = cardHex(cardnum, facility)
        print('Press enter to program card '..cardnum..':'..facility..' (hex: '..card..')')
        --This would be better with 'press any key', but we'll take what we can get.
        io.read()
        core.console( ('lf hid clone %s'):format(card) )
    end
end

main(args)
