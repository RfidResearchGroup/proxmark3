local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')
local toyNames = require('default_toys')

example =[[
	1. script run tnp3sim
	2. script run tnp3sim -m
	3. script run tnp3sim -m -i myfile
]]
author = "Iceman"
usage = "script run tnp3sim -h -m -i <filename>"
desc =[[
This script will try to load a binary datadump of a Mifare TNP3xxx card.
It vill try to validate all checksums and view some information stored in the dump
For an experimental mode, it tries to manipulate some data.
At last it sends all data to the PM3 device memory where it can be used in the command  "hf mf sim"

Arguments:
	-h             : this help
	-m             : Maxed out items (experimental)
	-i             : filename for the datadump to read (bin)
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag
--- 
-- A debug printout-function
function dbg(args)
	if not DEBUG then
		return
	end
	
    if type(args) == "table" then
		local i = 1
		while result[i] do
			dbg(result[i])
			i = i+1
		end
	else
		print("###", args)
	end	
end	
--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
end
--- 
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end
--
-- Exit message
function ExitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end


local function writedumpfile(infile)
	 t = infile:read("*all")
	 len = string.len(t)
	 local len,hex = bin.unpack(("H%d"):format(len),t)
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
		data =	blocks[area+1]..blocks[area+2]..blocks[area+4]
	elseif chksumtype == 3 then
		data =  blocks[area+5]..blocks[area+6]..blocks[area+8]..string.rep('00',0xe0)	
	end
	return utils.Crc16(data)
end

local function ValidateCheckSums(blocks)

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


local function LoadEmulator(blocks)
	local HASHCONSTANT = '20436F707972696768742028432920323031302041637469766973696F6E2E20416C6C205269676874732052657365727665642E20'
	local cmd
	local blockdata
	for _,b in pairs(blocks) do 
		
		blockdata = b
		
		if  _%4 ~= 3 then
			if (_ >= 8 and _<=21)  or  (_ >= 36 and _<=49) then
				local base = ('%s%s%02x%s'):format(blocks[0], blocks[1], _ , HASHCONSTANT)	
				local baseStr = utils.ConvertHexToAscii(base)
				local key = md5.sumhexa(baseStr)
				local enc = core.aes(key, blockdata)
				local hex = utils.ConvertAsciiToBytes(enc)
				hex = utils.ConvertBytesToHex(hex)
			
				blockdata = hex
				io.write( _..',')
			end
		end

		cmd = Command:new{cmd = cmds.CMD_MIFARE_EML_MEMSET, arg1 = _ ,arg2 = 1,arg3 = 0, data = blockdata}
		local err = core.SendCommand(cmd:getBytes())
		if err then 
			return err
		end
	end
	io.write('\n')
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	
	local result, err, hex
	local maxed = false
	local inputTemplate = "dumpdata.bin"
	local outputTemplate = os.date("toydump_%Y-%m-%d_%H%M");
	
		-- Arguments for the script
	for o, a in getopt.getopt(args, 'hmi:o:') do
		if o == "h" then return help() end		
		if o == "m" then maxed = true end
		if o == "o" then outputTemplate = a end		
		if o == "i" then inputTemplate = a end
	end
	
	-- Turn off Debug
	local cmdSetDbgOff = "hf mf dbg 0"
	core.console( cmdSetDbgOff) 
	
	-- if not loadFromDump then
		-- -- Look for tag present on reader,
		-- result, err = lib14a.read1443a(false)
		-- if not result then return oops(err)	end

		-- core.clearCommandBuffer()
	
		-- if 0x01 ~= result.sak then -- NXP MIFARE TNP3xxx
			-- return oops('This is not a TNP3xxx tag. aborting.')
		-- end	

		-- -- Show tag info
		-- print((' Found tag : %s'):format(result.name))
	-- end
	
	-- Load dump.bin file
	print( (' Load data from %s'):format(inputTemplate))
	hex, err = utils.ReadDumpFile(inputTemplate)
	if not hex then return oops(err) end
	
	local blocks = {}
	local blockindex = 0
	for i = 1, #hex, 32 do
		blocks[blockindex] = hex:sub(i,i+31)
		blockindex = blockindex + 1
	end

	if DEBUG then
		print('Validating checksums in the loaded datadump')
		ValidateCheckSums(blocks)
	end
	
	--
	print( string.rep('--',20) )	
	print(' Gathering info')
	local uid = blocks[0]:sub(1,8)
	local itemtype = blocks[1]:sub(1,4)
	local cardid = blocks[1]:sub(9,24)

	-- Show info 
	print( string.rep('--',20) )
	print( (' ITEM TYPE : 0x%s - %s'):format(itemtype, toyNames[itemtype]) )
	print( ('       UID : 0x%s'):format(uid) )
	print( ('    CARDID : 0x%s'):format(cardid ) )	
	print( string.rep('--',20) )

	-- lets do something.
	-- 
	local experience = blocks[8]:sub(1,6)
	print(('Experience  : %d'):format(utils.SwapEndianness(experience,24)))
	local money = blocks[8]:sub(7,10)
	print(('Money       : %d'):format(utils.SwapEndianness(money,16)))
	local fairy = blocks[9]:sub(1,8)
	--FD0F = Left, FF0F = Right
	local path = 'not choosen'
	if fairy:sub(2,2) == 'D' then
		path = 'Left'
	elseif fairy:sub(2,2) == 'F' then
		path = 'Right'
	end
	print(('Fairy       : %d [Path: %s] '):format(utils.SwapEndianness(fairy,24),path))
	
	local hat = blocks[9]:sub(8,11)
	print(('Hat         : %d'):format(utils.SwapEndianness(hat,16)))
	
	--0x0D    0x29    0x0A    0x02    16-bit hero points value. Maximum 100.
	local heropoints = blocks[13]:sub(20,23)
	print(('Hero points : %d'):format(utils.SwapEndianness(heropoints,16)))

	--0x10    0x2C    0x0C    0x04    32 bit flag value indicating heroic challenges completed.
	local challenges = blocks[16]:sub(25,32)
	print(('Finished hero challenges : %d'):format(utils.SwapEndianness(challenges,32)))
	
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
		print('Updating all checksums')
		SetCheckSum(blocks, 3)
		SetCheckSum(blocks, 2)
		SetCheckSum(blocks, 1)
		SetCheckSum(blocks, 0)
	
		print('Validating all checksums')	
		ValidateCheckSums(blocks)
	end
	
	--Load dumpdata to emulator memory
	if DEBUG then
		print('Sending dumpdata to emulator memory')
		err = LoadEmulator(blocks)
		if err then return oops(err) end	
		core.clearCommandBuffer()
		print('The simulation is now prepared.\n --> run \"hf mf sim u '..uid..' x\" <--')
	end
end
main(args)