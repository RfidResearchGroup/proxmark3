local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')
local toys = require('default_toys')
local pre = require('precalc')
local ansicolors = require('ansicolors')

copyright = ''
author = 'Iceman'
version = 'v1.0.3'
desc = [[
This script will try to load a binary datadump of a Mifare TNP3xxx card.
It will try to validate all checksums and view some information stored in the dump
For an experimental mode, it tries to manipulate some data.
At last it sends all data to the PM3 device memory where it can be used in the command  "hf mf sim"
]]
example = [[
    1. script run hf_mf_tnp3_sim
    2. script run hf_mf_tnp3_sim -m
    3. script run hf_mf_tnp3_sim -m -i myfile
]]
usage = [[
script run hf_mf_tnp3_sim [-h] [-m] [-i <filename>]
]]
arguments = [[
    -h             : this help
    -m             : Maxed out items (experimental)
    -i             : filename for the datadump to read (bin)
]]

local DEBUG = true -- the debug flag
local RANDOM = '20436F707972696768742028432920323031302041637469766973696F6E2E20416C6C205269676874732052657365727665642E20'

local band = bit32.band
local bor = bit32.bor
local lshift = bit32.lshift
local rshift = bit32.rshift
local byte = string.byte
local char = string.char
local sub = string.sub
local format = string.format

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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
--
-- Exit message
local function ExitMsg(msg)
    print( string.rep('--',20) )
    print( string.rep('--',20) )
    print(msg)
    print()
end

local function writedumpfile(infile)
     t = infile:read('*all')
     len = string.len(t)
     local len,hex = bin.unpack(('H%d'):format(len),t)
     return hex
end
-- blocks with data
-- there are two dataareas, in block 8 or block 36,   ( 1==8 ,
-- checksum type =  0, 1, 2, 3
local function GetCheckSum(blocks, dataarea, chksumtype)

    local crc
    local area = 36
    if  dataarea == 1 then
        area = 8
    end

    if chksumtype == 0 then
        crc = blocks[1]:sub(29,32)
    elseif chksumtype == 1 then
        crc = blocks[area]:sub(29,32)
    elseif chksumtype == 2 then
        crc = blocks[area]:sub(25,28)
    elseif chksumtype == 3 then
        crc = blocks[area]:sub(21,24)
    end
    return utils.SwapEndianness(crc,16)
end

local function SetAllCheckSum(blocks)
    print('Updating all checksums')
    SetCheckSum(blocks, 3)
    SetCheckSum(blocks, 2)
    SetCheckSum(blocks, 1)
    SetCheckSum(blocks, 0)
end

local function SetCheckSum(blocks, chksumtype)

    if blocks == nil then return nil, 'Argument \"blocks\" nil' end
    local newcrc
    local area1 = 8
    local area2 = 36

    if chksumtype == 0 then
        newcrc = ('%04X'):format(CalcCheckSum(blocks,1,0))
        blocks[1] = blocks[1]:sub(1,28)..newcrc:sub(3,4)..newcrc:sub(1,2)
    elseif chksumtype == 1 then
        newcrc = ('%04X'):format(CalcCheckSum(blocks,1,1))
        blocks[area1] = blocks[area1]:sub(1,28)..newcrc:sub(3,4)..newcrc:sub(1,2)
        newcrc = ('%04X'):format(CalcCheckSum(blocks,2,1))
        blocks[area2] = blocks[area2]:sub(1,28)..newcrc:sub(3,4)..newcrc:sub(1,2)
    elseif chksumtype == 2 then
        newcrc = ('%04X'):format(CalcCheckSum(blocks,1,2))
        blocks[area1] = blocks[area1]:sub(1,24)..newcrc:sub(3,4)..newcrc:sub(1,2)..blocks[area1]:sub(29,32)
        newcrc = ('%04X'):format(CalcCheckSum(blocks,2,2))
        blocks[area2] = blocks[area2]:sub(1,24)..newcrc:sub(3,4)..newcrc:sub(1,2)..blocks[area2]:sub(29,32)
    elseif chksumtype == 3 then
        newcrc = ('%04X'):format(CalcCheckSum(blocks,1,3))
        blocks[area1] = blocks[area1]:sub(1,20)..newcrc:sub(3,4)..newcrc:sub(1,2)..blocks[area1]:sub(25,32)
        newcrc = ('%04X'):format(CalcCheckSum(blocks,2,3))
        blocks[area2] = blocks[area2]:sub(1,20)..newcrc:sub(3,4)..newcrc:sub(1,2)..blocks[area2]:sub(25,32)
    end
end

function CalcCheckSum(blocks, dataarea, chksumtype)
    local area = 36
    if dataarea == 1 then
        area = 8
    end

    if chksumtype == 0 then
        data = blocks[0]..blocks[1]:sub(1,28)
    elseif chksumtype == 1 then
        data = blocks[area]:sub(1,28)..'0500'
    elseif chksumtype == 2 then
        data = blocks[area+1]..blocks[area+2]..blocks[area+4]
    elseif chksumtype == 3 then
        data = blocks[area+5]..blocks[area+6]..blocks[area+8]..string.rep('00',0xe0)
    end
    return utils.Crc16(data)
end

local function ValidateCheckSums(blocks)
    print(' Validating checksums')

    local isOk, crc, calc
    -- Checksum Type 0
    crc = GetCheckSum(blocks,1,0)
    calc = CalcCheckSum(blocks, 1, 0)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 0       : %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 1 (DATAAREAHEADER 1)
    crc = GetCheckSum(blocks,1,1)
    calc = CalcCheckSum(blocks,1,1)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 1 area 1: %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 1 (DATAAREAHEADER 2)
    crc = GetCheckSum(blocks,2,1)
    calc = CalcCheckSum(blocks,2,1)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 1 area 2: %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 2 (DATAAREA 1)
    crc = GetCheckSum(blocks,1,2)
    calc = CalcCheckSum(blocks,1,2)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 2 area 1: %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 2 (DATAAREA 2)
    crc = GetCheckSum(blocks,2,2)
    calc = CalcCheckSum(blocks,2,2)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 2 area 2: %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 3 (DATAAREA 1)
    crc = GetCheckSum(blocks,1,3)
    calc = CalcCheckSum(blocks,1,3)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 3 area 1: %04x = %04x -- %s\n'):format(crc,calc,isOk))

    -- Checksum Type 3 (DATAAREA 2)
    crc = GetCheckSum(blocks,2,3)
    calc = CalcCheckSum(blocks,2,3)
    if crc == calc then isOk='Ok' else isOk = 'Error' end
    io.write( ('TYPE 3 area 2: %04x = %04x -- %s\n'):format(crc,calc,isOk))

end

local function AddKey(keys, blockNo, data)
    local pos = (math.floor( blockNo / 4 ) * 12)+1
    local key = keys:sub(pos, pos + 11 )
    return key..data:sub(13)
end

local function LoadEmulator(uid, blocks)
    print('Sending dumpdata to emulator memory')
    local keys = pre.GetAll(uid)
    local cmd, blockdata
    for _,b in pairs(blocks) do

        blockdata = b

        if  _%4 ~= 3 then
            if (_ >= 8 and _<=21)  or  (_ >= 36 and _<=49) then
                local base = ('%s%s%02x%s'):format(blocks[0], blocks[1], _ , RANDOM)
                local baseStr = utils.ConvertHexToAscii(base)
                local key = md5.sumhexa(baseStr)
                local enc = core.aes128_encrypt(key, blockdata)
                blockdata = utils.ConvertAsciiToHex(enc)
            end
        else
            -- add keys if not existing..
            if ( blockdata:sub(1,12) == '000000000000' ) then
                blockdata = AddKey(keys, _, blockdata)
            end
        end

        io.write( _..',')
        io.flush()
        core.clearCommandBuffer()
        cmd = Command:newMIX{cmd = cmds.CMD_HF_MIFARE_EML_MEMSET, arg1 = _ ,arg2 = 1,arg3 = 16, data = blockdata}
        local err, msg = cmd:sendMIX(true)
        if err == nil then return err, msg end
    end
    io.write('\n')
end

local function Num2Card(m, l)

    local k = {
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,0x42, 0x43, 0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x50, 0x51, 0x52, 0x53, 0x54,0x56, 0x57, 0x58, 0x59, 0x5A, 0x00
    }
    local msw = tonumber(utils.SwapEndiannessStr(m,32),16)
    local lsw = tonumber(utils.SwapEndiannessStr(l,32),16)

    if msw > 0x17ea1 then
        return "too big"
    end

    if msw == 0x17ea1 and lsw > 0x8931fee8 then
        return "out of range"
    end

    local s = ""
    local index
    for i = 1,10 do
        index, msw, lsw = DivideByK( msw, lsw)
        if ( index <= 1 ) then
            s = char(k[index]) .. s
        else
            s = char(k[index-1]) .. s
        end
        print (index-1, msw, lsw)
    end
    return s
end
--33LRT-LM9Q9
--7, 122, 3474858630
--20, 4, 1008436634
--7, 0, 627182959
--17, 0, 21626998
--16, 0, 745758
--23, 0, 25715
--21, 0, 886
--16, 0, 30
--1, 0, 1
--1, 0, 0

function DivideByK(msw, lsw)

    local lowLSW
    local highLSW
    local remainder = 0
    local RADIX = 29

    --local num = 0 | band( rshift(msw,16), 0xffff)
    local num = band( rshift(msw, 16), 0xffff)

    --highLSW = 0 | lshift( (num / RADIX) , 16)
    highLSW = lshift( (num / RADIX) , 16)
    remainder = num % RADIX

    num =  bor( lshift(remainder,16), band(msw, 0xffff))

    --highLSW |= num / RADIX
    highLSW = highLSW or (num / RADIX)
    remainder = num % RADIX

    num =  bor( lshift(remainder,16), ( band(rshift(lsw,16), 0xffff)))

    --lowLSW = 0 | (num / RADIX) << 16
    lowLSW = 0 or (lshift( (num / RADIX), 16))
    remainder = num % RADIX

    num =  bor( lshift(remainder,16) , band(lsw, 0xffff) )

    lowLSW = bor(lowLSW, (num / RADIX))
    remainder = num % RADIX
    return remainder, highLSW, lowLSW

                -- uint num = 0 | (msw >> 16) & 0xffff;

            -- highLSW = 0 | (num / RADIX) << 16;
            -- remainder = num % RADIX;

            -- num = (remainder << 16) | (msw & 0xffff);

            -- highLSW |= num / RADIX;
            -- remainder = num % RADIX;

            -- num = (remainder << 16) | ((lsw >> 16) & 0xffff);

            -- lowLSW = 0 | (num / RADIX) << 16;
            -- remainder = num % RADIX;

            -- num = (remainder << 16) | (lsw & 0xffff);

            -- lowLSW |= num / RADIX;
            -- remainder = num % RADIX;

end

local function main(args)

    print( string.rep('--',20) )
    print( string.rep('--',20) )

    local result, err, hex
    local maxed = false
    local inputTemplate = 'dumpdata.bin'
    local outputTemplate = os.date('toydump_%Y-%m-%d_%H%M');

        -- Arguments for the script
    for o, a in getopt.getopt(args, 'hmi:o:') do
        if o == 'h' then return help() end
        if o == 'm' then maxed = true end
        if o == 'o' then outputTemplate = a end
        if o == 'i' then inputTemplate = a end
    end

    -- Turn off Debug
    local cmdSetDbgOff = 'hw dbg -0'
    core.console( cmdSetDbgOff)
    utils.Sleep(0.5)

    -- Load dump.bin file
    print( ('Load data from %s'):format(inputTemplate))
    hex, err = utils.ReadDumpFile(inputTemplate)
    if not hex then return oops(err) end

    local blocks = {}
    local blockindex = 0
    for i = 1, #hex, 32 do
        blocks[blockindex] = hex:sub(i, i+31)
        blockindex = blockindex + 1
    end

    if DEBUG then ValidateCheckSums(blocks) end

    --
    print( string.rep('--',20) )
    print(' Gathering info')
    local uid = blocks[0]:sub(1,8)
    local toytype = blocks[1]:sub(1,4)
    local cardidLsw = blocks[1]:sub(9,16)
    local cardidMsw = blocks[1]:sub(17,24)
    local subtype  = blocks[1]:sub(25,28)

    -- Show info
    print( string.rep('--',20) )

    local item = toys.Find( toytype, subtype)
    if item then
        local itemStr = ('%s - %s (%s)'):format(item[6],item[5], item[4])
        print(' ITEM TYPE : '..itemStr )
    else
        print( (' ITEM TYPE : 0x%s 0x%s'):format(toytype, subtype) )
    end

    print( ('       UID : %s'):format(uid) )
    print( ('    CARDID : %s %s [%s]'):format(
                                cardidMsw,cardidLsw,
                                --Num2Card(cardidMsw, cardidLsw))
                                '')
                                )
    print( string.rep('--',20) )


    -- Experience should be:
    local experience = blocks[8]:sub(1,6)
    print(('Experience  : %d'):format(utils.SwapEndianness(experience,16)))

    local money = blocks[8]:sub(7,10)
    print(('Money       : %d'):format(utils.SwapEndianness(money,16)))

    --

    -- Sequence number
    local seqnum = blocks[8]:sub(18,19)
    print(('Sequence number : %d'):format( tonumber(seqnum,16)))

    local fairy = blocks[9]:sub(1,8)
    --FD0F = Left, FF0F = Right
    local path = 'not chosen'
    if fairy:sub(2,2) == 'D' then
        path = 'Left'
    elseif fairy:sub(2,2) == 'F' then
        path = 'Right'
    end
    print(('Fairy       : %d [Path: %s] '):format(utils.SwapEndianness(fairy,24),path))

    local hat = blocks[9]:sub(8,11)
    print(('Hat         : %d'):format(utils.SwapEndianness(hat,16)))

    local level = blocks[13]:sub(27,28)
    print(('LEVEL : %d'):format( tonumber(level,16)))

    --local health = blocks[]:sub();
    --print(('Health : %d'):format( tonumber(health,16))

    --0x0D    0x29    0x0A    0x02    16-bit hero points value. Maximum 100.
    local heropoints = blocks[13]:sub(20,23)
    print(('Hero points : %d'):format(utils.SwapEndianness(heropoints,16)))

    --0x10    0x2C    0x0C    0x04    32 bit flag value indicating heroic challenges completed.
    local challenges = blocks[16]:sub(25,32)
    print(('Finished hero challenges : %d'):format(utils.SwapEndianness(challenges,32)))

    -- Character Name
    local name1 = blocks[10]:sub(1,32)
    local name2 = blocks[12]:sub(1,32)
    print('Custom name : '..utils.ConvertHexToAscii(name1..name2))

    if maxed then
        print('Lets try to max out some values')
        -- max out money, experience
        --print (blocks[8])
        blocks[8] = 'FFFFFF'..'FFFF'..blocks[8]:sub(11,32)
        blocks[36] = 'FFFFFF'..'FFFF'..blocks[36]:sub(11,32)
        --print (blocks[8])

        -- max out hero challenges
        --print (blocks[16])
        blocks[16] = blocks[16]:sub(1,24)..'FFFFFFFF'
        blocks[44] = blocks[44]:sub(1,24)..'FFFFFFFF'
        --print (blocks[16])

        -- max out heropoints
        --print (blocks[13])
        blocks[13] = blocks[13]:sub(1,19)..'0064'..blocks[13]:sub(24,32)
        blocks[41] = blocks[41]:sub(1,19)..'0064'..blocks[41]:sub(24,32)
        --print (blocks[13])

        -- Update Checksums
        SetAllCheckSum(blocks)

        -- Validate Checksums
        ValidateCheckSums(blocks)
    end

    --Load dumpdata to emulator memory
    if DEBUG then
        err = LoadEmulator(uid, blocks)
        if err then return oops(err) end
        core.clearCommandBuffer()
        print('The simulation is now prepared.\n --> run \"hf mf sim -u '..uid..'\" <--')
    end
end
main(args)
