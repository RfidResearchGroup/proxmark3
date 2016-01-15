local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')
local dumplib = require('html_dumplib')
local toys = require('default_toys')

example =[[
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
author = "Iceman"
usage = "script run tnp3dump -k <key> -n -p -o <filename>"
desc =[[
This script will try to dump the contents of a Mifare TNP3xxx card.
It will need a valid KeyA in order to find the other keys and decode the card.
Arguments:
	-h             : this help
	-k <key>       : Sector 0 Key A.
	-n             : Use the nested cmd to find all keys
	-p             : Use the precalc to find all keys
	-o             : filename for the saved dumps
]]
local RANDOM = '20436F707972696768742028432920323031302041637469766973696F6E2E20416C6C205269676874732052657365727665642E20'
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = false -- the debug flag
local numBlocks = 64
local numSectors = 16
--- 
-- A debug printout-function
function dbg(args)
	if not DEBUG then return end
	
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
	return nil,err
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

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	
	local keyA
	local cmd
	local err
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
	local cmdSetDbgOff = "hf mf dbg 0"
	core.console( cmdSetDbgOff) 
	
	result, err = lib14a.read1443a(false)
	if not result then
		return oops(err)
	end

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
	else
		print('Loading dumpkeys.bin')
		local hex, err = utils.ReadDumpFile(input)
		if not hex then
			return oops(err)
		end
		akeys = hex:sub(0,12*16)
	end
	
	-- Read block 0
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 0,arg2 = 0,arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block0, err = waitCmd()
	if err then return oops(err) end
	
	core.clearCommandBuffer()
	
	-- Read block 1
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 1,arg2 = 0,arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block1, err = waitCmd()
	if err then return oops(err) end

	core.clearCommandBuffer()
	
	local tmpHash = block0..block1..'%02x'..RANDOM

	local key
	local pos = 0
	local blockNo
	local blocks = {}
	
	-- main loop
	io.write('Reading blocks > ')
	for blockNo = 0, numBlocks-1, 1 do

		if core.ukbhit() then
			print("aborted by user")
			break
		end
	
		core.clearCommandBuffer()
		
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