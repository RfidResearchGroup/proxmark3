local getopt = require('getopt')
local ansicolors = require('ansicolors')

--Copyright
copyright = ''
author = 'nisgola'
version = 'v1'

-- Script description
desc = [[
This is a script that write Sector Trailers to the emulator memory.

By default, both keys A and B are set to 0xFFFFFFFFFFFF.
The Access Bytes are set to 0xFF0780 and User Bytes to 0x00.
]]
example = [[
    -- Use default formatting
    1. script run hf_mf_em_util

    -- Change keys A and B
    2. script run hf_mf_em_util -a 112233445566 -b AABBCCDDEEFF

    -- Define access bits and User byte
    3. script run hf_mf_em_util -x 00f0ff -u 12
]]
-- Usage info
usage = [[
script run hf_mf_em_util [-h] [-4] [-a <hex>] [-b <hex>] [-x <hex>] [-u <hex>]
]]
-- Arguments
arguments = [[
    -h          this help
    -4          format as 4K card
    -a <hex>    define key A
    -b <hex>    define key B
    -x <hex>    define Access Bytes
    -u <hex>    define User Byte
]]
-- Help function
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
-- Print error
local function oops(err)
    print('ERROR:', err)
    return nil,err
end

-- Memory formatting
local function card_format(key_a,key_b,ab,user,s70)
    local blocks = {3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63,67,71,75,79,83,87,91,95,99,103,107,111,115,119,123,127,143,159,175,191,207,223,239,255}
    for k,v in ipairs(blocks) do
        local cmd = string.format("hf mf esetblk --blk %s -d %s%s%s%s",v,key_a,ab,user,key_b)
        core.console(cmd)
        print(cmd)
        core.clearCommandBuffer()
    if s70 == false and k > 15 then
        return
        end
    end
end

local function main(args)
    -- Receive parameters
    for o, a in getopt.getopt(args, 'ha:b:x:u:4') do
        if o == 'h' then return help() end
        if o == 'a' then KeyA = a end
        if o == 'b' then KeyB = a end
        if o == 'x' then Accessbit = a end
        if o == 'u' then User = a end
        if o == '4' then kkkk = true end
    end

    local KeyA = KeyA or 'FFFFFFFFFFFF'
    if #(KeyA) ~= 12 then
            return oops( string.format('Wrong length of the Key A, receveid %d, expected 12', #KeyA))
    end

    local KeyB = KeyB or 'FFFFFFFFFFFF'
    if #(KeyB) ~= 12 then
            return oops( string.format('Wrong length of the Key B, received %d, expected 12', #KeyB))
    end

    local Accessbit = Accessbit or 'FF0780'
    if #(Accessbit) ~= 6 then
            return oops( string.format('Wrong length of the Access bit, received %d, expected 6', #Accessbit))
    end

    local User = User or '00'
    if #(User) ~= 2 then
            return oops( string.format('Wrong lenght for the user defined byte, received %d, expected 2', #User))
    end

    local kkkk = kkkk or false

    -- Call card_format function
    card_format(KeyA,KeyB,Accessbit,User,kkkk)
end
main (args)
