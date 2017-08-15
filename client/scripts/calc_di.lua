local bin = require('bin')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')

copyright = 'Copyright (c) 2017 IceSQL AB. All rights reserved.'
author = "Iceman"
version = 'v1.0.0'
desc = [[ This script calculates mifare keys based on uid diversification for DI. 
Algo not found by me.
]]
example =
[[
	-- if called without, it reads tag uid
	 script run calc_di
	 
	 -- 
	 script run calc_di -u 11223344556677
]]
usage =
[[
script run calc_di -h -u <uid>

Arguments:
	-h             : this help
	-u <UID>       : UID
]]

local DEBUG = true
local BAR = '286329204469736E65792032303133'
local MIS = '0A14FD0507FF4BCD026BA83F0A3B89A9'
local bxor=bit32.bxor
--- 
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == "table" then
		local i = 1
		while args[i] do
			dbg(args[i])
			i = i+1
		end
	else
		print("###", args)
	end	
end	
--- 
-- This is only meant to be used when errors occur
local function oops(err)
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
function exitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end

-- create key
local function keygen(uid)
	local data = MIS..uid..BAR
	local hash = utils.ConvertAsciiToBytes(utils.Sha1Hex(data))
	return string.format("%02X%02X%02X%02X%02X%02X",
		hash[3+1],
		hash[2+1],
		hash[1+1],
		hash[0+1],
		hash[7+1],
		hash[6+1]
		)
end
---
-- print one row with keys
local function printRow(sector, keyA, keyB)
	print('|'..sector..'|  '..keyA..'  |  '..keyB..'  |' )
end
---
-- print keys
local function printKeys(key)
	print('|---|----------------|----------------|')
	print('|sec|key A           |key B           |')
	print('|---|----------------|----------------|')
    for i=0,4 do
		local s = ("02X"):format(i) 
		printRow( s, key, key)
	end
	print('|---|----------------|----------------|')
end
---
-- main
local function main(args)

	print( string.rep('==', 30) )
	print()
			
	local i, uid, key
	local useUID = false
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hu:') do
		if o == "h" then return help() end		
		if o == "u" then uid = a; useUID = true end		
	end

	if useUID then
		-- uid string checks if supplied
		if uid == nil then return oops('empty uid string') end
		if #uid == 0 then return oops('empty uid string') end
		if #uid ~= 14 then return oops('uid wrong length. Should be 7 hex bytes') end
		key = keygen(uid)
	else
		-- GET TAG UID	
		tag, err = lib14a.read1443a(false)
		if not tag then return oops(err) end
		core.clearCommandBuffer()

		-- simple tag check
		if 0x09 ~= tag.sak then
			if 0x4400 ~= tag.atqa then 
				return oops(('[fail] found tag %s :: looking for Mifare Mini 0.3k'):format(tag.name)) 
			end
		end		
		uid = tag.uid
	end

	print('|UID|', uid)
	printKeys(key)
end

main(args)