local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local lib14a = require('read14a')
local utils = require('utils')

example =[[
	1. script run formatMifare
	2. script run formatMifare -k aabbccddeeff -n 112233445566 -a FF0780
]]
author = "Iceman"
usage = "script run formatMifare -k <key>"
desc =[[
This script will generate 'hf mf wrbl' commands for each block to format a Mifare card.

Alla datablocks gets 0x00
As default the script sets the keys A/B to 0xFFFFFFFFFFFF
and the access bytes will become 0x78,0x77,0x88
The GDB will become 0x00

The script will skip the manufactoring block 0.

Arguments:
	-h             - this help
	-k <key>       - the current six byte key with write access
	-n <key>       - the new key that will be written to the card
	-a <access>    - the new access bytes that will be written to the card
]]
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag
local CmdString = 'hf mf wrbl %d B %s %s'
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
--
-- Read information from a card
function GetCardInfo()
	result, err = lib14a.read1443a(false)
	if not result then
		print(err)
		return
	end
	print(("Found:  %s"):format(result.name))

	core.clearCommandBuffer()
	
	if 0x18 == result.sak then -- NXP MIFARE Classic 4k | Plus 4k
		-- IFARE Classic 4K offers 4096 bytes split into forty sectors, 
		-- of which 32 are same size as in the 1K with eight more that are quadruple size sectors. 
		numSectors = 40
	elseif 0x08 == result.sak then  -- NXP MIFARE CLASSIC 1k | Plus 2k
		-- 1K offers 1024 bytes of data storage, split into 16 sector
		numSectors = 16
	elseif 0x09 == result.sak then  -- NXP MIFARE Mini 0.3k
		-- MIFARE Classic mini offers 320 bytes split into five sectors.
		numSectors = 5
	elseif  0x10 == result.sak then -- NXP MIFARE Plus 2k
		numSectors = 32
	elseif  0x01 == sak then        -- NXP MIFARE TNP3xxx 1K
		numSectors = 16
	else
		print("I don't know how many sectors there are on this type of card, defaulting to 16")
	end	
	--[[
	 The mifare Classic 1k card has 16 sectors of 4 data blocks each. 
	 The first 32 sectors of a mifare Classic 4k card consists of 4 data blocks and the remaining
	 8 sectors consist of 16 data blocks. 
	--]]
	
	-- Defaults to 16 * 4 = 64  - 1 = 63
    numBlocks = numSectors * 4 - 1  
		
	if numSectors > 32 then
		numBlocks = 32*4+ (numSectors-32)*16 -1
	end
	
end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print()
	
	local OldKey 
	local NewKey
	local Accessbytes
	
	-- Arguments for the script
	for o, a in getopt.getopt(args, 'hk:n:a:') do
		if o == "h" then return help() end		
		if o == "k" then OldKey = a end
		if o == "n" then NewKey = a	end
		if o == "a" then Accessbytes = a end
	end

	-- validate input args.
	OldKey =  OldKey or 'FFFFFFFFFFFF'
	if #(OldKey) ~= 12 then
		return oops( string.format('Wrong length of write key (was %d) expected 12', #OldKey))
	end
	
	NewKey =  NewKey or 'FFFFFFFFFFFF'
	if #(NewKey) ~= 12 then
		return oops( string.format('Wrong length of new key (was %d) expected 12', #NewKey))
	end

	--Accessbytes =  Accessbytes or '787788'
	Accessbytes =  Accessbytes or 'FF0780'
	if #(Accessbytes) ~= 6 then
		return oops( string.format('Wrong length of accessbytes (was %d) expected 12', #Accessbytes))
	end

	GetCardInfo()
	
	-- Show info
	print( string.format('Estimating number of blocks: %d', numBlocks))
	print( string.format('Old key:    %s', OldKey))
	print( string.format('New key:    %s', NewKey))
	print( string.format('New Access: %s', Accessbytes))
	print( string.rep('--',20) )

		-- Set new block data
	local EMPTY_BL = string.rep('00',16)
	local EMPTY_SECTORTRAIL = string.format('%s%s%s%s',NewKey,Accessbytes,'00',NewKey)
	
	dbg( string.format('New sector-trailer : %s',EMPTY_SECTORTRAIL))
	dbg( string.format('New emptyblock: %s',EMPTY_BL))
	dbg('')
	
	-- Ask
	local dialogResult = utils.confirm("Do you want to erase this card")
	if dialogResult == false then 
		return ExitMsg('Quiting it is then. Your wish is my command...')
	end	

	print( string.rep('--',20) )
	
	-- main loop
	for block=0,numBlocks,1 do

		local reminder = (block+1) % 4
		local cmd
		if reminder == 0 then
			cmd = CmdString:format(block, OldKey , EMPTY_SECTORTRAIL)
		else
			cmd = CmdString:format(block, OldKey , EMPTY_BL)		
		end	
	
		if block ~= 0 then
			print(cmd)
			--core.console(cmd)
		end
		
		if core.ukbhit() then
			print("aborted by user")
			break
		end
	end
end

main(args)