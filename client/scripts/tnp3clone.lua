local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils = require('utils')
local pre = require('precalc')
local toys = require('default_toys')

local lsh = bit32.lshift
local rsh = bit32.rshift
local bor = bit32.bor
local band = bit32.band

copyright = ''
author = "Iceman"
version = 'v1.0.1'
desc =[[
This script will try making a barebone clone of a tnp3 tag on to a magic generation1 card.
]]
example =[[
    script run tnp3clone
    script run tnp3clone -h
    script run tnp3clone -l
    script run tnp3clone -t aa00 -s 0030

]]
usage = [[
script run tnp3clone -t <toytype> -s <subtype>

Arguments:
    -h             : this help
    -l             : list all known toy tokens
    -t <data>      : toytype id, 4hex symbols
    -s <data>      : subtype id, 4hex symbols

    For fun,  try the following subtype id:
    0612 - Lightcore
    0118 - Series 1
    0138 - Series 2
    0234 - Special
    023c - Special
    0020 - Swapforce
]]

local PM3_SUCCESS = 0

---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end
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
-- decode response and get the blockdata from a normal mifare read command
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

local function readblock( blocknum, keyA )
    -- Read block N
    local keytype = '00'
    local data = ('%02x%s%s'):format(blocknum, keytype, keyA)
    local c = Command:newNG{cmd = cmds.CMD_MIFARE_READBL, data = data}
    local b, err = getblockdata(c:sendNG(false))
    if not b then return oops(err) end
    return b
end
---
-- decode response and get the blockdata from backdoor magic command
local function readmagicblock( blocknum )
    -- Read block N
    local CSETBLOCK_SINGLE_OPERATION = 0x1F
    local c = Command:newMIX{
                    cmd = cmds.CMD_MIFARE_CGETBLOCK
                    , arg1 = CSETBLOCK_SINGLE_OPERATION
                    , arg3 = blocknum
                    }
    local b, err = getblockdata(c:sendMIX())
    if not b then return oops(err) end
    return b
end

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local numBlocks = 64
    local cset = 'hf mf csetbl '
    local csetuid = 'hf mf csetuid '
    local cget = 'hf mf cgetbl '
    local empty = '00000000000000000000000000000000'
    local AccAndKeyB = '7F0F0869000000000000'
    local atqa = '0F01'
    local sak = '81'
    -- Defaults to Gusto
    local toytype = 'C201'
    local subtype = '0030'
    local DEBUG = true

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'ht:s:l') do
        if o == 'h' then return help() end
        if o == 't' then toytype = a end
        if o == 's' then subtype = a end
        if o == 'l' then return toys.List() end
    end

    if #toytype ~= 4 then return oops('[!] Wrong size - toytype. (4hex symbols)') end
    if #subtype ~= 4 then return oops('[!] Wrong size - subtype. (4hex symbols)') end

    -- look up type, find & validate types
    local item = toys.Find( toytype, subtype)
    if item then
        print( ('[+] Looking up input: Found %s - %s (%s)'):format(item[6], item[5], item[4]) )
    else
        print('[-] Didn\'t find item type. If you are sure about it, post on forum')
    end
    --15,16
    --13-14

    -- find tag
    local card, err = lib14a.read(false, true)
    if not card then return oops(err) end

    -- load keys
    local akeys  = pre.GetAll(card.uid)
    local keyA = akeys:sub(1, 12 )

    local b0 = readblock(0, keyA)
    if not b0 then
        print('[-] failed reading block with factorydefault key. Trying chinese magic read.')
        b0, err = readmagicblock(0)
        if not b0 then
            oops('[!] '..err)
            return oops('[!] failed reading block with chinese magic command. Quitting...')
        end
    end
    core.clearCommandBuffer()

    -- wipe card.
    local cmd  = (csetuid..'%s %s %s w'):format(card.uid, atqa, sak)
    core.console(cmd)
    core.clearCommandBuffer()

    local b1 = toytype..string.rep('00',10)..subtype

    local calc = utils.Crc16(b0..b1)
    local calcEndian = bor(rsh(calc,8), lsh(band(calc, 0xff), 8))

    local cmd  = (cset..'1 %s%04x'):format( b1, calcEndian)
    core.console(cmd)
    core.clearCommandBuffer()

    local pos, key
    for blockNo = 2, numBlocks-1, 1 do
        pos = (math.floor( blockNo / 4 ) * 12)+1
        key = akeys:sub(pos, pos + 11 )
        if  blockNo%4 == 3 then
            cmd =  ('%s %d %s%s'):format(cset,blockNo,key,AccAndKeyB)
            core.console(cmd)
        end
    end
    core.clearCommandBuffer()

    -- Set sector trailer S0, since it has different access rights
    cmd = ('%s 3 %s0f0f0f69000000000000'):format(cset, keyA)
    core.console(cmd)
    core.clearCommandBuffer()
end
main(args)
