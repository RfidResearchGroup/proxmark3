local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')
local md5 = require('md5')

example =[[
	1. script run tnp3
	2. script run tnp3 -k aabbccddeeff
]]
author = "Iceman"
usage = "script run tnp3 -k <key>"
desc =[[
This script will try to dump the contents of a Mifare TNP3xxx card.
It will need a valid KeyA in order to find the other keys and decode the card.
Arguments:
	-h             - this help
	-k <key>       - Sector 0 Key A.
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

local function show(data)
	if DEBUG then
	    local formatString = ("H%d"):format(string.len(data))
	    local _,hexdata = bin.unpack(formatString, data)
	    dbg("Hexdata" , hexdata)
	end
end

function waitCmd()
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
	local cmdReadBlockString = 'hf mf rdbl %d A %s'
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hk:') do
		if o == "h" then return help() end		
		if o == "k" then keyA = a end
	end

	-- validate input args.
	keyA =  keyA or '4b0b20107ccb'
	if #(keyA) ~= 12 then
		return oops( string.format('Wrong length of write key (was %d) expected 12', #keyA))
	end
	
	result, err = lib14a.read1443a(false)
	if not result then
		print(err)
		return
	end
	print((" Found tag : %s"):format(result.name))

	core.clearCommandBuffer()
	
	if 0x01 ~= result.sak then -- NXP MIFARE TNP3xxx
		print("This is not a TNP3xxx tag. aborting.")
		return
	end	
	
	-- Show info
	print(('Using keyA : %s'):format(keyA))
	print( string.rep('--',20) )

	local cmdNestedString = 'hf mf nested 1 0 A %s d'
	local cmdDumpString = 'hf mf dump'
	--core.console(cmdNestedString.format(keyA) )
	--core.console(cmdDumpString)

	print('Reading data need to dump data')
	
	-- Read block 0
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 0,arg2 = 0,arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block0, err = waitCmd()
	if err then return oops(err) end
	
	-- Read block 1
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 1,arg2 = 0,arg3 = 0, data = keyA}
	local err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block1, err = waitCmd()
	if err then return oops(err) end


	-- Read block 9
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = 9,arg2 = 0,arg3 = 0, data = '56f6313550f9'}
	local err = core.SendCommand(cmd:getBytes())
	if err then return oops(err) end
	local block9, err = waitCmd()
	if err then return oops(err) end
	
	-- main loop
	print('BLOCK MD5                                 DECRYPTED                           ASCII' ) 
		
	for block=0,numBlocks-1,1 do
	
		if math.fmod(block,4) then
			
		end
		
		local base = ('%s%s%02d%s'):format(block0, block1, block, hashconstant)
		local md5hash = md5.sumhexa(base)
		local aestest = core.aes(md5hash, block9 )
		
		local _,hex = bin.unpack(("H%d"):format(16),aestest)
		
		
		local hexascii = string.gsub(hex, '(%x%x)', 
							function(value) 
								return string.char(tonumber(value, 16)) 
							end
						)

		print( block .. ' ::  ' .. md5hash .. ' :: ' .. hex .. ' :: ' .. hexascii  )	
		
		-- if core.ukbhit() then
			-- print("aborted by user")
			-- break
		-- end
	end
end

main(args)