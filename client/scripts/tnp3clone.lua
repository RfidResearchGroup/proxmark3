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

example =[[
	script run tnp3clone
	script run tnp3clone -h
	script run tnp3clone -l
	script run tnp3clone -t aa00 -s 0030

]]
author = "Iceman"
usage = "script run tnp3clone -t <toytype> -s <subtype>"
desc =[[
This script will try making a barebone clone of a tnp3 tag on to a magic generation1 card.

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


-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
end
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end

local function waitCmd()
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK,2000)
	if response then
		local count,cmd,arg0 = bin.unpack('LL',response)
		if(arg0==1) then
			local count,arg1,arg2,data = bin.unpack('LLH511',response,count)
			return data:sub(1,32)
		else
			return nil, "Couldn't read block." 
		end
	end
	return nil, "No response from device"
end

local function readblock( blocknum, keyA )
	-- Read block 0
	cmd = Command:new{cmd = cmds.CMD_MIFARE_READBL, arg1 = blocknum, arg2 = 0, arg3 = 0, data = keyA}
	err = core.SendCommand(cmd:getBytes())
	if err then return nil, err end
	local block0, err = waitCmd()
	if err then return nil, err end
	return block0
end
local function readmagicblock( blocknum )
	-- Read block 0
	local CSETBLOCK_SINGLE_OPERATION = 0x1F
	cmd = Command:new{cmd = cmds.CMD_MIFARE_CGETBLOCK, arg1 = CSETBLOCK_SINGLE_OPERATION, arg2 = 0, arg3 = blocknum}
 	err = core.SendCommand(cmd:getBytes())
	if err then return nil, err end
	local block0, err = waitCmd()
	if err then return nil, err end
	return block0
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	
	local numBlocks = 64
    local cset = 'hf mf csetbl '
	local csetuid = 'hf mf csetuid '
	local cget = 'hf mf cgetbl '
	local empty = '00000000000000000000000000000000'
	local AccAndKeyB = '7F078869000000000000'
	-- Defaults to Gusto
	local toytype = 'C201'
	local subtype = '0030'
	local DEBUG = true
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'ht:s:l') do
		if o == "h" then return help() end		
		if o == "t" then toytype = a end
		if o == "s" then subtype = a end
		if o == "l" then return toys.List() end
	end

	if #toytype ~= 4 then return oops('Wrong size - toytype. (4hex symbols)') end	
	if #subtype ~= 4 then return oops('Wrong size - subtype. (4hex symbols)') end	

	-- look up type, find & validate types
	local item = toys.Find( toytype, subtype)
	if item then
		print( (' Looking up input: Found %s - %s (%s)'):format(item[6],item[5], item[4]) )
	else
		print('Didn\'t find item type. If you are sure about it, report it in')
	end
	--15,16
	--13-14 

	
	-- find tag
	result, err = lib14a.read1443a(false, true)
	if not result then return oops(err)	end

	-- load keys
	local akeys  = pre.GetAll(result.uid)
	local  keyA = akeys:sub(1, 12 ) 

	local b0 = readblock(0,keyA)
	if not b0 then
		print('failed reading block with factorydefault key.  Trying chinese magic read.')
	    b0, err = readmagicblock(0)
		if not b0 then 
			oops(err) 
			return oops('failed reading block with chinese magic command.  quitting...')
		end
	end
	
	-- wipe card.
	local cmd  = (csetuid..'%s 0004 08 w'):format(result.uid)	
	core.console(cmd) 

	local b1 = toytype..string.rep('00',10)..subtype
	
	local calc = utils.Crc16(b0..b1)
	local calcEndian = bor(rsh(calc,8), lsh(band(calc, 0xff), 8))
	
	local cmd  = (cset..'1 %s%04x'):format( b1, calcEndian)	
	core.console(cmd) 
	
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
end
main(args)