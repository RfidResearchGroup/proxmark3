local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')
local dumplib = require('html_dumplib')
local toys = require('default_toys')

copyright = ''
author = 'Iceman'
version = 'v1.0.1'
desc =[[
This script will try to dump the contents of a Mifare TNP3xxx card.
It will need a valid KeyA in order to find the other keys and decode the card.
]]
example = [[
    script run tnp3dump
    script run tnp3dump -n
    script run tnp3dump -p
    script run tnp3dump -k aabbccddeeff
    script run tnp3dump -k aabbccddeeff -n
    script run tnp3dump -o myfile
    script run tnp3dump -n -o myfile
    script run tnp3dump -p -o myfile
    script run tnp3dump -k aabbccddeeff -n -o myfile
]]
usage = [[
script run tnp3dump -k <key> -n -p -o <filename>

Arguments:
    -h             : this help
    -k <key>       : Sector 0 Key A.
    -n             : Use the nested cmd to find all keys
    -p             : Use the precalc to find all keys
    -o             : filename for the saved dumps
]]

local PM3_SUCCESS = 0
local RANDOM = '20436F707972696768742028432920323031302041637469766973696F6E2E20416C6C205269676874732052657365727665642E20'
local DEBUG = false -- the debug flag
local numBlocks = 64
local numSectors = 16
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
--
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

local function readdumpkeys(infile)
     t = infile:read("*all")
     len = string.len(t)
     local len,hex = bin.unpack(("H%d"):format(len),t)
     return hex
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

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local keyA, cmd, err
    local useNested = false
    local usePreCalc = false
    local cmdReadBlockString = 'hf mf rdbl %d A %s'
    local input = "dumpkeys.bin"
    local outputTemplate = os.date("toydump_%Y-%m-%d_%H%M%S");

    -- Arguments for the script
    for o, a in getopt.getopt(args, 'hk:npo:') do
        if o == "h" then return help() end
        if o == "k" then keyA = a end
        if o == "n" then useNested = true end
        if o == "p" then usePreCalc = true end
        if o == "o" then outputTemplate = a end
    end

    -- validate input args.
    keyA =  keyA or '4b0b20107ccb'
    if #(keyA) ~= 12 then
        return oops( string.format('Wrong length of write key (was %d) expected 12', #keyA))
    end

    -- Turn off Debug
    local cmdSetDbgOff = "hw dbg 0"
    core.console( cmdSetDbgOff)
    utils.Sleep(0.5)

    result, err = lib14a.read(false, true)
    if not result then return oops(err) end

    core.clearCommandBuffer()

    -- Show tag info
    print((' Found tag %s'):format(result.name))

    dbg(('Using keyA : %s'):format(keyA))

    --Trying to find the other keys
    if useNested then
      core.console( ('hf mf nested 1 0 A %s d'):format(keyA) )
    end

    core.clearCommandBuffer()

    local akeys = ''
    if usePreCalc then
        local pre = require('precalc')
        akeys = pre.GetAll(result.uid)
        dbg(akeys)
    else
        print('Loading dumpkeys.bin')
        local hex, err = utils.ReadDumpFile(input)
        if not hex then
            return oops(err)
        end
        akeys = hex:sub(0,12*16)
    end

    local block0, block1
    -- Read block 0
    dbg('Reading block 0')
    local blockno = '00'
    local keytype = '00'
    local data = ('%s%s%s'):format(blockno, keytype, keyA)
    cmd = Command:newNG{cmd = cmds.CMD_MIFARE_READBL, data = data}
    block0, err = getblockdata(cmd:sendNG(false))
    if not block0 then return oops(err) end

    core.clearCommandBuffer()

    -- Read block 1
    dbg('Reading block 1')
    local blockno = '01'
    data = ('%s%s%s'):format(blockno, keytype, keyA)
    cmd = Command:newNG{cmd = cmds.CMD_MIFARE_READBL, data = data}
    block1, err = getblockdata(cmd:sendNG(false))
    if not block1 then return oops(err) end

    core.clearCommandBuffer()

    local tmpHash = block0..block1..'%02x'..RANDOM

    local key
    local pos = 0
    local blockNo
    local blocks = {}

    -- main loop
    io.write('Reading blocks > ')
    for blockNo = 0, numBlocks-1, 1 do

        io.flush()

        if core.ukbhit() then
            print("aborted by user")
            break
        end

        core.clearCommandBuffer()

        pos = (math.floor( blockNo / 4 ) * 12)+1
        key = akeys:sub(pos, pos + 11 )
        data = ('%02x%s%s'):format(blockNo, keytype, key)
        cmd = Command:newNG{cmd = cmds.CMD_MIFARE_READBL, data = data}
        local blockdata, err = getblockdata(cmd:sendNG(false))
        if not blockdata then return oops(err) end

        if  blockNo%4 ~= 3 then

            if blockNo < 8 then
                -- Block 0-7 not encrypted
                blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,blockdata)
            else
                -- blocks with zero not encrypted.
                if string.find(blockdata, '^0+$') then
                    blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,blockdata)
                else
                    local baseStr = utils.ConvertHexToAscii(tmpHash:format(blockNo))
                    local key = md5.sumhexa(baseStr)
                    local aestest = core.aes128_decrypt(key, blockdata)
                    local hex = utils.ConvertAsciiToHex(aestest)

                    blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,hex)
                    io.write(blockNo..',')
                end
            end
        else
            -- Sectorblocks, not encrypted
            blocks[blockNo+1] = ('%02d  :: %s%s'):format(blockNo,key,blockdata:sub(13,32))
        end
    end
    io.write('\n')

    core.clearCommandBuffer()

    -- Print results
    local bindata = {}
    local emldata = ''

    for _,s in pairs(blocks) do
        local slice = s:sub(8,#s)
        local str = utils.ConvertHexToAscii(slice)
        emldata = emldata..slice..'\n'
        for c in (str):gmatch('.') do
            bindata[#bindata+1] = c
        end
    end

    print( string.rep('--',20) )

    local uid = block0:sub(1,8)
    local toytype = block1:sub(1,4)
    local cardidLsw = block1:sub(9,16)
    local cardidMsw = block1:sub(16,24)
    local cardid = block1:sub(9,24)
    local subtype = block1:sub(25,28)

    -- Write dump to files
    if not DEBUG then
        local foo = dumplib.SaveAsBinary(bindata, outputTemplate..'-'..uid..'.bin')
        print(("Wrote a BIN dump to:  %s"):format(foo))
        local bar = dumplib.SaveAsText(emldata, outputTemplate..'-'..uid..'.eml')
        print(("Wrote a EML dump to:  %s"):format(bar))
    end

    print( string.rep('--',20) )
    -- Show info

    local item = toys.Find(toytype, subtype)
    if item then
        print(('            ITEM TYPE : %s - %s (%s)'):format(item[6],item[5], item[4]) )
    else
        print(('            ITEM TYPE : 0x%s 0x%s'):format(toytype, subtype))
    end

    print( ('                  UID : 0x%s'):format(uid) )
    print( ('               CARDID : 0x%s'):format(cardid ) )
    print( string.rep('--',20) )

    core.clearCommandBuffer()
end
main(args)
