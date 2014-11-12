local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')
local dumplib = require('html_dumplib')
local toyNames = require('default_toys')

example =[[
	1. script run tnp3
	2. script run tnp3 -n
	3. script run tnp3 -k aabbccddeeff
	4. script run tnp3 -k aabbccddeeff -n
	5. script run tnp3 -o myfile 
	6. script run tnp3 -n -o myfile 
	7. script run tnp3 -k aabbccddeeff -n -o myfile 
]]
author = "Iceman"
usage = "script run tnp3 -k <key> -n -o <filename>"
desc =[[
This script will try to dump the contents of a Mifare TNP3xxx card.
It will need a valid KeyA in order to find the other keys and decode the card.
Arguments:
	-h             : this help
	-k <key>       : Sector 0 Key A.
	-n             : Use the nested cmd to find all keys
	-o             : filename for the saved dumps
]]

local hashconstant = '20436F707972696768742028432920323031302041637469766973696F6E2E20416C6C205269676874732052657365727665642E20'

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag
local numBlocks = 64
local numSectors = 16
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

local function readdumpkeys(infile)
	 t = infile:read("*all")
	 len = string.len(t)
	 local len,hex = bin.unpack(("H%d"):format(len),t)
	 return hex
end

local function waitCmd()
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
	if response then
		local count,cmd,arg0 = bin.unpack('LL',response)
		if(arg0==1) then
			local count,arg1,arg2,data = bin.unpack('LLH511',response,count)
			return data:sub(1,32)
		else
			return nil, "Couldn't read block.." 
		end
	end
	return nil, "No response from device"
end

local function computeCrc16(s)
	local hash = core.crc16(utils.ConvertHexToAscii(s))	
	return hash
end

local function reverseCrcBytes(crc)
	crc2 = crc:sub(3,4)..crc:sub(1,2)
	return tonumber(crc2,16)
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	
	local keyA
	local cmd
	local err
	local useNested = false
	local cmdReadBlockString = 'hf mf rdbl %d A %s'
	local input = "dumpkeys.bin"
	local outputTemplate = os.date("toydump_%Y-%m-%d_%H%M%S");

	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hk:no:') do
		if o == "h" then return help() end		
		if o == "k" then keyA = a end
		if o == "n" then useNested = true end
		if o == "o" then outputTemplate = a end		
	end

	-- validate input args.
	keyA =  keyA or '4b0b20107ccb'
	if #(keyA) ~= 12 then
		return oops( string.format('Wrong length of write key (was %d) expected 12', #keyA))
	end

	-- Turn off Debug
	local cmdSetDbgOff = "hf mf dbg 0"
	core.console( cmdSetDbgOff) 
	
	result, err = lib14a.read1443a(false)
	if not result then
		return oops(err)
	end

	core.clearCommandBuffer()
	
	if 0x01 ~= result.sak then -- NXP MIFARE TNP3xxx
		return oops('This is not a TNP3xxx tag. aborting.')
	end	

	-- Show tag info
	print((' Found tag : %s'):format(result.name))
	print(('Using keyA : %s'):format(keyA))

	--Trying to find the other keys
	if useNested then
	  core.console( ('hf mf nested 1 0 A %s d'):format(keyA) )
	end
	
	-- Loading keyfile
	print('Loading dumpkeys.bin')
	local infile = io.open(input, "rb")
	if infile == nil then 
		return oops('Could not read file ', input)
	end
	local akeys = readdumpkeys(infile):sub(0,12*16)
	
	-- Read block 0
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 0,arg2 = 0,arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block0, err = waitCmd()
	if err then return oops(err) end
	
	-- Read block 1
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 1,arg2 = 0,arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block1, err = waitCmd()
	if err then return oops(err) end

	local key
	local pos = 0
	local blockNo
	local blocks = {}

	print('Reading card data')
	core.clearCommandBuffer()
		
	-- main loop
	io.write('Decrypting blocks > ')
	for blockNo = 0, numBlocks-1, 1 do

		if core.ukbhit() then
			print("aborted by user")
			break
		end
	
		pos = (math.floor( blockNo / 4 ) * 12)+1
		key = akeys:sub(pos, pos + 11 )
		cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = blockNo ,arg2 = 0,arg3 = 0, data = key}
		local err = core.SendCommand(cmd:getBytes())
		if err then return oops(err) end
		local blockdata, err = waitCmd()
		if err then return oops(err) end		

		if  blockNo%4 ~= 3 then
			if blockNo < 8 then
				-- Block 0-7 not encrypted
				blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,blockdata) 
			else
				local base = ('%s%s%02x%s'):format(block0, block1, blockNo, hashconstant)	
				local baseStr = utils.ConvertHexToAscii(base)
				local md5hash = md5.sumhexa(baseStr)
				local aestest = core.aes(md5hash, blockdata)

				local hex = utils.ConvertAsciiStringToBytes(aestest)
				hex = utils.ConvertBytes2HexString(hex)
				--local _,hex = bin.unpack(("H%d"):format(16),aestest)

				-- blocks with zero not encrypted.
				if string.find(blockdata, '^0+$') then
					blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,blockdata) 
				else
					blocks[blockNo+1] = ('%02d  :: %s'):format(blockNo,hex)
					io.write( blockNo..',')
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
		local str = utils.ConvertBytesToAsciiString(
				 utils.ConvertHexStringToBytes(slice)
				)
		emldata = emldata..slice..'\n'
		for c in (str):gmatch('.') do
			bindata[#bindata+1] = c
		end
	end 
	
	-- Write dump to files
	if not DEBUG then
		local foo = dumplib.SaveAsBinary(bindata, outputTemplate..'.bin')
		print(("Wrote a BIN dump to the file %s"):format(foo))
		local bar = dumplib.SaveAsText(emldata, outputTemplate..'.eml')
		print(("Wrote a EML dump to the file %s"):format(bar))
	end

	local uid = block0:sub(1,8)
	local itemtype = block1:sub(1,4)
	local cardid = block1:sub(9,24)

	-- Show info 
	print( string.rep('--',20) )
	print( (' ITEM TYPE : 0x%s - %s'):format(itemtype, toyNames[itemtype]) )
	print( ('       UID : 0x%s'):format(uid) )
	print( ('    CARDID : 0x%s'):format(cardid ) )	
	print( string.rep('--',20) )

	print('Validating checksums')
	-- Checksum Typ 0
	local test1 = ('%s%s'):format(block0, block1:sub(1,28))
	local crc = block1:sub(29,32)
	local revcrc = reverseCrcBytes(crc)

	io.write( ('BLOCK 0-1 : %04x = %04x \n'):format(revcrc,computeCrc16(test1)))
	
	-- Checksum Typ 1  BLOCK 9
	local block9 = blocks[9]:sub(8,35)
	test1 = ('%s0500'):format(block9)
	crc = blocks[9]:sub(36,39)
	revcrc = reverseCrcBytes(crc)
	io.write( ('BLOCK 8 : %04x = %04x \n'):format(revcrc,computeCrc16(test1)))

	-- Checksum Typ 1  BLOCK 37
	local block37 = blocks[37]:sub(8,35)
	test1 = ('%s0500'):format(block37)
	crc = blocks[37]:sub(36,39)
	revcrc = reverseCrcBytes(crc)
	io.write( ('BLOCK 36 : %04x = %04x \n'):format(revcrc,computeCrc16(test1)))
	
	-- Checksum Typ 2
	-- 10,11,13
	test1 =	blocks[10]:sub(8,39)..
			blocks[11]:sub(8,39)..
			blocks[13]:sub(8,39)

	crc = blocks[9]:sub(32,35)
	revcrc = reverseCrcBytes(crc)
	io.write( ('BLOCK 10-11-13 :%04x = %04x \n'):format(revcrc,computeCrc16(test1)))
	-- Checksum Typ 3
	-- 15,17,18,19
	crc = blocks[9]:sub(28,31)
	revcrc = reverseCrcBytes(crc)
	test1 = blocks[14]:sub(8,39)..
			blocks[15]:sub(8,39)..
			blocks[17]:sub(8,39)

	local tohash = test1..string.rep('00',0xe0)	
	local hashed = computeCrc16(tohash)
	io.write( ('BLOCK 14-15-17 %04x = %04x \n'):format(revcrc,hashed))	
end
main(args)