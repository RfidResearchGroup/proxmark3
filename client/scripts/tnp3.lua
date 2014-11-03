local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')

example =[[
	1. script run tnp3
	2. script run tnp3 -n
	3. script run tnp3 -k aabbccddeeff
	4. script run tnp3 -k aabbccddeeff -n
]]
author = "Iceman"
usage = "script run tnp3 -k <key> -n"
desc =[[
This script will try to dump the contents of a Mifare TNP3xxx card.
It will need a valid KeyA in order to find the other keys and decode the card.
Arguments:
	-h             : this help
	-k <key>       : Sector 0 Key A.
	-n             : Use the nested cmd to find all keys
]]

-- AES konstant?  LEN 0x24 36,
-- I dekompilen är det för internal static array = 0x36 54
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

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print()
	
	local keyA
	local cmd
	local err
	local useNested = false
	local cmdReadBlockString = 'hf mf rdbl %d A %s'
	local input = "dumpkeys.bin"
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hk:n') do
		if o == "h" then return help() end		
		if o == "k" then keyA = a end
		if o == "n" then useNested = true end
	end

	-- validate input args.
	keyA =  keyA or '4b0b20107ccb'
	if #(keyA) ~= 12 then
		return oops( string.format('Wrong length of write key (was %d) expected 12', #keyA))
	end
	
	result, err = lib14a.read1443a(false)
	if not result then
		return oops(err)
	end

	print((' Found tag : %s'):format(result.name))

	core.clearCommandBuffer()
	
	if 0x01 ~= result.sak then -- NXP MIFARE TNP3xxx
		return oops('This is not a TNP3xxx tag. aborting.')
	end	
	
	-- Show info
	print(('Using keyA : %s'):format(keyA))
	print( string.rep('--',20) )

	print('Trying to find other keys.')
	if useNested then
	  core.console( ('hf mf nested 1 0 A %s d'):format(keyA) )
	end
	
	-- Loading keyfile
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

	-- main loop
	for blockNo = 8, numBlocks-1, 1 do
		local b = blockNo%4
		if b ~= 3 then
			pos = (math.floor( blockNo / 4 ) * 12)+1
			key = akeys:sub(pos, pos + 12 )
			cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = blockNo ,arg2 = 0,arg3 = 0, data = key}
			local err = core.SendCommand(cmd:getBytes())
			if err then return oops(err) end
			local blockdata, err = waitCmd()
			if err then return oops(err) end
	
			local base = ('%s%s%d%s'):format(block0, block1, blockNo, hashconstant)
			local md5hash = md5.sumhexa(base)
			local aestest = core.aes(md5hash, blockdata)
		
			local _,hex = bin.unpack(("H%d"):format(16),aestest)
		
			-- local hexascii = string.gsub(hex, '(%x%x)', 
							-- function(value) 
								-- return string.char(tonumber(value, 16)) 
							-- end
						-- )

	        if string.find(blockdata, '^0+$') then
				blocks[blockNo] = ('%02d  :: %s :: %s'):format(blockNo,blockdata,blockdata) 
			else
				--blocks[blockNo] = ('%02d :: %s :: %s :: %s '):format(blockNo,key,md5hash,hex)
				blocks[blockNo] = ('%02d  :: %s :: %s'):format(blockNo,blockdata,blockdata) 
			end		
		
			if core.ukbhit() then
				print("aborted by user")
				break
			end
		end
	end
	
	-- Print results
	print('BLK :: DATA                                DECRYPTED' )
	print( string.rep('--',36) )
	for _,s in pairs(blocks) do
		print( s )
	end 
end

main(args)