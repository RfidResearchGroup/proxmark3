---
-- This Lua script is designed to run with Iceman/RRG Proxmark3 fork
-- Just copy hf_mf_dump-luxeo.lua to client/luascripts/
-- and run "script run hf_mf_dump_luxeo"

-- requirements
local cmds = require('commands')
local getopt = require('getopt')
local utils = require('utils')
local lib14a = require('read14a')
local ansicolors  = require('ansicolors')

copyright = ''
author = '0xdrrb'
version = 'v0.1.3'
desc = [[
This is a script that tries to dump and decrypt the data of a specific type of Mifare laundromat token.
OBS! Tag must be on the antenna.
]]
example = [[
    script run hf_mf_dump_luxeo
]]
usage = [[
script run hf_mf_dump_luxeo
]]
arguments = [[
    -h              This help
]]
local PM3_SUCCESS = 0

-- Some shortcuts
local band = bit32.band
local bor = bit32.bor
local bnot = bit32.bnot
local bxor = bit32.bxor
local lsh = bit32.lshift
local rsh = bit32.rshift

local acgreen   = ansicolors.bright..ansicolors.green
local accyan    = ansicolors.bright..ansicolors.cyan
local acred     = ansicolors.red
local acyellow  = ansicolors.bright..ansicolors.yellow
local acblue    = ansicolors.bright..ansicolors.blue
local acmagenta = ansicolors.bright..ansicolors.magenta
local acoff     = ansicolors.reset


-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR: ', err)
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
--
local function setdevicedebug( status )
    local c = 'hw dbg '
    if status then
        c = c..'-1'
    else
        c = c..'-0'
    end
    core.console(c)
end

local function xteaCrypt(num_rounds, v, key)
    local v0 = v[0]
    local v1 = v[1]
    local delta = 0x9E3779B9
    local sum = 0

    for i = 0, num_rounds-1 do
        -- v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        v0 = band(bxor(bxor(lsh(v1,4), rsh(v1,5)) + v1, sum + key[band(sum,3)]) + v0, 0xFFFFFFFF)
        sum = band(sum + delta, 0xFFFFFFFF)
        -- v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        v1 = band(bxor(bxor(lsh(v0,4), rsh(v0,5)) + v0, sum + key[band(rsh(sum,11),3)]) + v1, 0xFFFFFFFF)
    end
    v[0] = v0
    v[1] = v1
end

local function xteaDecrypt(num_rounds, v, key)
    local v0 = v[0]
    local v1 = v[1]
    local delta = 0x9E3779B9
    local sum = band(delta * num_rounds, 0xFFFFFFFF)

    for i = 0, num_rounds-1 do
        -- v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        v1 = band(v1 - bxor(bxor(lsh(v0,4), rsh(v0,5)) + v0, sum + key[band(rsh(sum,11),3)]), 0xFFFFFFFF)
        sum = band(sum - delta, 0xFFFFFFFF)
        -- v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        v0 = band(v0 - bxor(bxor(lsh(v1,4), rsh(v1,5)) + v1, sum + key[band(sum,3)]), 0xFFFFFFFF)
    end
    v[0] = v0
    v[1] = v1
end

local function createxteakey(mfuid)
    local xteakey = {}
    local buid = {}
    local tmpkey = {}
    local uid = {}

    -- Warning ! "it is customary in Lua to START ARRAYS WITH ONE"
    buid = utils.ConvertHexToBytes(mfuid)
    uid[0] = bor(buid[1], lsh(buid[2], 8))
    uid[1] = bor(buid[3], lsh(buid[4], 8))

    tmpkey[0] = 0x198B
    tmpkey[1] = uid[0]
    tmpkey[2] = 0x46D8
    tmpkey[3] = uid[1]
    tmpkey[4] = 0x5310
    tmpkey[5] = bxor(uid[0], 0xA312)
    tmpkey[6] = 0xFFCB
    tmpkey[7] = bxor(uid[1], 0x55AA)

    xteakey[0] = bor(lsh(tmpkey[1], 16), tmpkey[0])
    xteakey[1] = bor(lsh(tmpkey[3], 16), tmpkey[2])
    xteakey[2] = bor(lsh(tmpkey[5], 16), tmpkey[4])
    xteakey[3] = bor(lsh(tmpkey[7], 16), tmpkey[6])

    return xteakey
end

local function getblockdata(response)
    if not response then
        return nil, 'No response from device'
    end
    if response.Status == PM3_SUCCESS then
        return response.Data
    else
        return nil, "Couldn't read block.. ["..response.Status.."]"
    end
end

local function readblock(blockno, key)
    -- Read block N
    local keytype = '01'  -- key B
    local data = ('%02x%s%s'):format(blockno, keytype, key)
    local c = Command:newNG{cmd = cmds.CMD_HF_MIFARE_READBL, data = data}
    local b, err = getblockdata(c:sendNG(false))
    if not b then return oops(err) end
    return b
end

local function readtag(mfkey,xteakey)
    local tagdata = {}
    local cleardata = {}
    local v = {}
    local vv = {}

    -- Read 4 sectors and build table
    for sect = 8, 11 do
        for blockn = sect * 4, (sect * 4) + 2 do
            local blockdata = readblock(blockn, mfkey)
            if not blockdata then return oops('[!] failed reading block') end
            table.insert(tagdata, blockdata)
        end
    end

    -- Decrypt data and build clear table
    for key,value in ipairs(tagdata) do
        local clearblockdata
        v[0] = utils.SwapEndianness(value:sub(1, 8), 32)
        v[1] = utils.SwapEndianness(value:sub(9, 16), 32)
        xteaDecrypt(16, v, xteakey)
        vv[0] = utils.SwapEndianness(value:sub(17, 24), 32)
        vv[1] = utils.SwapEndianness(value:sub(25, 32), 32)
        xteaDecrypt(16, vv, xteakey)
        clearblockdata=string.format("%08X%08X%08X%08X",
            utils.SwapEndianness(string.format("%08X", v[0]), 32),
            utils.SwapEndianness(string.format("%08X", v[1]), 32),
            utils.SwapEndianness(string.format("%08X", vv[0]), 32),
            utils.SwapEndianness(string.format("%08X", vv[1]), 32))
        table.insert(cleardata, clearblockdata)
    end

    return tagdata,cleardata

end


local function main(args)

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    local xteakey = {}
    -- local v = {}
    local edata = {}
    local cdata = {}

    -- Turn off Debug
    setdevicedebug(false)

    -- GET TAG UID
    tag, err = lib14a.read(false, true)
    if err then
        lib14a.disconnect()
        return oops(err)
    end
    core.clearCommandBuffer()

    -- simple tag check
    if 0x08 ~= tag.sak then
        if 0x0400 ~= tag.atqa then
            return oops(('[fail] found tag %s :: looking for Mifare S50 1k'):format(tag.name))
        end
    end

    xteakey = createxteakey(tag.uid)
    print(acblue.."UID: "..tag.uid..acoff)
    print(acblue..string.format("XTEA key: %08X %08X %08X %08X", xteakey[0], xteakey[1], xteakey[2], xteakey[3])..acoff)

    local keys = {
        "415A54454B4D",
        "4B6A43059B64",
        "C8BE6250C9C5",
    }

    for i, key in ipairs(keys) do
        edata, cdata = readtag(key, xteakey)
        if edata and cdata then
            goto continue
        end
    end

    if edata == nil or cdata == nil then
        print("ERROR Reading tag!")
        return nil
    end

    ::continue::

    print("Ciphered data:")
    for key,value in ipairs(edata) do
        print(value)
        if key % 3 == 0 then print("") end
    end

    -- compute CRC for each segment
    crcH = utils.SwapEndianness(core.reveng_runmodel("CRC-16/ARC", cdata[1]..cdata[2]..cdata[3]:sub(1,28), false, '0'),16)
    crcA = utils.SwapEndianness(core.reveng_runmodel("CRC-16/ARC", cdata[4]..cdata[5]..cdata[6]..cdata[7]:sub(1,28), false, '0'),16)
    crcB = utils.SwapEndianness(core.reveng_runmodel("CRC-16/ARC", cdata[8]..cdata[9]..cdata[10]..cdata[11]:sub(1,28), false, '0'),16)

    print("\nHeader:")
    for key,value in ipairs(cdata) do
        if key == 3 then
            print(value:sub(1,28)..acmagenta..value:sub(29,32)..acoff)
            if utils.SwapEndianness(value:sub(29,32),16) == crcH then strcrc = " OK" else strcrc = acred.." CRCERROR !!" end
            print(acmagenta.."CRC16/ARC = "..string.format("0x%04X", crcH)..strcrc..acoff)
            print("\nDataA:")
        elseif key == 4 then
            print(acgreen..value:sub(1,4)..acoff..value:sub(5,16)..accyan..value:sub(17,24)..acoff..value:sub(25,26)..accyan..value:sub(27,28)..acoff..value:sub(29,32))
            versionA = utils.SwapEndianness(value:sub(1,4),16)
            dateA = string.format("%d/%02d/%02d %02d:%02d", tonumber(value:sub(17,18),10)+2000, tonumber(value:sub(19,20),10),
                                             tonumber(string.format("%02X", band(tonumber(value:sub(21,22),16),0x3f)),10),
                                             tonumber(value:sub(23,24),10), tonumber(value:sub(27,28),10))
        elseif key == 8 then
            print(acgreen..value:sub(1,4)..acoff..value:sub(5,16)..accyan..value:sub(17,24)..acoff..value:sub(25,26)..accyan..value:sub(27,28)..acoff..value:sub(29,32))
            versionB = utils.SwapEndianness(value:sub(1,4),16)
            dateB = string.format("%d/%02d/%02d %02d:%02d", tonumber(value:sub(17,18),10)+2000, tonumber(value:sub(19,20),10),
                                             tonumber(string.format("%02X", band(tonumber(value:sub(21,22),16),0x3f)),10),
                                             tonumber(value:sub(23,24),10), tonumber(value:sub(27,28),10))
        elseif key == 5 then
            print(acyellow..value:sub(1,4)..acoff..value:sub(5,32))
            creditA = utils.SwapEndianness(value:sub(1,4),16)/100
        elseif key == 9 then
            print(acyellow..value:sub(1,4)..acoff..value:sub(5,32))
            creditB = utils.SwapEndianness(value:sub(1,4),16)/100
        elseif key == 7 then
            print(value:sub(1,28)..acmagenta..value:sub(29,32)..acoff)
            print(acgreen.."Version "..string.format("0x%04X", versionA)..acoff)
            print(acyellow.."Credit : "..creditA..acoff)
            if utils.SwapEndianness(value:sub(29,32),16) == crcA then strcrc = " OK" else strcrc = acred.." CRCERROR !!" end
            print(acmagenta.."CRC16/ARC = "..string.format("0x%04X", crcA)..strcrc..acoff)
            print(accyan.."Date: "..dateA..acoff)
            print("\nDataB:")
        elseif key == 11 then
            print(value:sub(1,28)..acmagenta..value:sub(29,32)..acoff)
            print(acgreen.."Version "..string.format("0x%04X", versionB)..acoff)
            print(acyellow.."Credit : "..creditB..acoff)
            if utils.SwapEndianness(value:sub(29,32),16) == crcB then strcrc = " OK" else strcrc = acred.." CRCERROR !!" end
            print(acmagenta.."CRC16/ARC = "..string.format("0x%04X", crcB)..strcrc..acoff)
            print(accyan.."Date: "..dateB..acoff)
            print("\nFooter:")
        else
            print(value)
        end
    end

    return
end

main(args)
