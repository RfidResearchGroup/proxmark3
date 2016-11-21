local cmds = require('commands')
local getopt = require('getopt')
local utils = require('utils')
local lib14a = require('read14a')

example = "script iterates over all possible sectors for a tag and runs hardnested attack against them to collect the keys."
author = "Iceman"
desc =
[[
This script iterates over all possible sectors for a tag and runs hardnested attack against them to collect the keys.

Arguments:
	-k 				Known key, 6 bytes (12 hex digits)
Examples : 
	script hard -b 112233445566
]]

local numBlocks = 64
local numSectors = 16
local DEBUG = TRUE
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
---
-- a simple selftest function,
local function selftest()
	return nil
end

--- 
-- The main entry point
function main(args)

	local blockno = '00'
	local keytype = 0 --A  01==B
	local key = 'fc00018778f7'
	local trgkey = ''
	
	local data
	-- Read the parameters
	for o, a in getopt.getopt(args, 'hk:t') do
		if o == "h" then return help() end
		if o == "k" then key = a end
		if o == "t" then return selftest() end
	end

	-- Turn off Debug
	local cmdSetDbgOff = "hf mf dbg 0"
	core.console( cmdSetDbgOff) 
	-- identify tag
	result, err = lib14a.read1443a(false)
	if not result then
		return oops(err)
	end
	core.clearCommandBuffer()
	
	-- Show tag info
	print((' Found tag %s'):format(result.name))
	
	local keys = {}
	-- loop
	for i=4, 12	, 4 do
		for trgkeytype=0,1 do
			local trgblockno = ("%02d"):format(i)
			local err, found_key = core.hardnested(blockno, keytype, key, trgblockno, trgkeytype, trgkey, 0,0,0,0)			
			
			table.insert( keys ,  { ["success"] = err, ["sector"] = i, ["type"] = trgkeytype, ["key"] =  utils.ConvertAsciiToHex(found_key) } )
		end
	end
	--print
	for k,v in pairs(keys) do 
		for a,b in pairs(v) do print(a,b) end
	end
end

main(args)