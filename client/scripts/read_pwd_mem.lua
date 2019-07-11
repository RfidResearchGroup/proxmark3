local getopt = require('getopt')
local bin = require('bin')

copyright = 'Copyright (c) 2018 Bogito. All rights reserved.'
author = 'Bogito'
version = 'v1.0.2'
desc =
[[
This script will read the flash memory of RDV4 and print the stored passwords.
It was meant to be used as a help tool after using the BogRun standalone mode.

(Iceman) script adapted to read and print keys in the default dictionary flashmemory sections.
]]
example =
[[
    -- This will scan the first 256 bytes of flash memory for stored passwords
    script run read_pwd_mem

    -- This will scan 256 bytes of flash memory at offset 64 for stored passwords
    script run read_pwd_mem -o 64

    -- This will scan 32 bytes of flash memory at offset 64 for stored passwords
    script run read_pwd_mem -o 64 -l 32

    -- This will print found
    script run read_pwd_mem -o 241664 -k 6
]]
usage =
[[
Usage:
    script run read_pwd_mem -h -o <offset> -l <length> -k <keylength>

Arguments:
    -h              :  this help
    -o <offset>     :  memory offset, default is 0
    -l <length>     :  length in bytes, default is 256
    -k <keylen>     :  key length in bytes <4|6|8> ,  default is 4
    -m              :  print Mifare dictionary keys
    -t              :  print t55xx dictionary passwords
    -i              :  print iClass dictionary keys
]]
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
local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print()

    local data, err, quadlet
    local cnt = 0
    local offset = 0
    local length = 256
    local keylength = 4
    local usedkey = false

    for o, a in getopt.getopt(args, 'ho:l:k:mti') do

        -- help
        if o == 'h' then return help() end

        -- offset
        if o == 'o' then offset = tonumber(a) end

        -- num of bytes to read
        if o == 'l' then length = tonumber(a) end

        -- keylength
        if o == 'k' then keylength = tonumber(a); usedkey = true end

        if o == 'm' then keylength =6; usedkey = true; offset = 0x3F000-0x6000; end
        if o == 't' then keylength =4; usedkey = true; offset = 0x3F000-0x3000; end
        if o == 'i' then keylength =8; usedkey = true; offset = 0x3F000-0x4000; end
    end

    if length < 0 or length > 256 then
        return oops('Error: Length is not valid. Must be less than 256')
    end

    if (offset < 0) or (offset % 4 ~= 0) then
        return oops('Error: Offset is not valid. Mod-4 values are only allowed.')
    end

    print('Memory offset', offset)
    print('Length       ', length)
    print('Key length   ', keylength)
    print( string.rep('--',20) )

    if usedkey then length = 4096 end

    data, err = core.GetFromFlashMem(offset, length)
    if err then return oops(err) end

    if usedkey then

        _, keys, s = bin.unpack('SH'..length-2, data)
        if keys == 0xFFFF then return "No keys found in section" end

        local kl = keylength * 2
        for i = 1, keys do

            key  = string.sub(s, (i - 1) * kl + 1, i * kl )
            print(string.format('[%02d] %s',i, key))
        end
        print( string.rep('--',20) )
        print( ('[+] found %d passwords'):format(keys))
    else

        _, s = bin.unpack('H'..length, data)

        local cnt = 0, i
        for i = 1, (length/keylength) do

            key  = string.sub(s, (i-1)*8+1, i*8)
            if key == 'FFFFFFFF' then break end
            print(string.format('[%02d] %s',i, key))
            cnt = cnt + 1
        end
        print( string.rep('--',20) )
        print( ('[+] found %d passwords'):format(cnt))
    end
    print( string.rep('--',20) )
end

main(args)
