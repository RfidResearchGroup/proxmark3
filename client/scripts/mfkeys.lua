--[[
	This is an example of Lua-scripting within proxmark3. This is a lua-side
	implementation of hf mf chk  

	This code is licensed to you under the terms of the GNU GPL, version 2 or,
	at your option, any later version. See the LICENSE.txt file for the text of
	the license.
	
	Copyright (C) 2013 m h swende <martin at swende.se>
--]]
-- Loads the commands-library
local cmds = require('commands')
-- Load the default keys
local keys = require('mf_default_keys')
-- Ability to read what card is there
local reader = require('read14a')


local desc = 
("This script implements check keys. It utilises a large list of default keys (currently %d keys).\
If you want to add more, just put them inside mf_default_keys.lua. "):format(#keys)

local TIMEOUT = 10000 -- 10 seconds
	
--[[This may be moved to a separate library at some point]]
local utils = 
{
	--- 
	-- Asks the user for Yes or No
	confirm = function(message, ...)
		local answer
		message = message .. " [y]/[n] ?"
		repeat
			io.write(message)
			io.flush()
			answer=io.read()
			if answer == 'Y' or answer == "y" then
				return true
			elseif answer == 'N' or answer == 'n' then 
				return false
			end
		until false
	end,
	---
	-- Asks the user for input
	input = function (message , default)
		local answer
		if default ~= nil then
			message = message .. " (default: ".. default.. " )"
		end
		message = message .." \n > "
		io.write(message)
		io.flush()
		answer=io.read()
		if answer == '' then answer = default end

		return answer
	end,
}


local function checkCommand(command)

	--print("Sending this command : " .. tostring(command))
	local usbcommand = command:getBytes()
	core.SendCommand(usbcommand)
	local result = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
	if result then
		local count,cmd,arg0 = bin.unpack('LL',result)
		if(arg0==1) then
			local count,arg1,arg2,data = bin.unpack('LLH511',result,count)
			key = data:sub(1,12)
			return key
		else
			--print("Key not found...")
			return nil
		end
	else
		print("Timeout while waiting for response. Increase TIMEOUT in keycheck.lua to wait longer")
		return nil, "Timeout while waiting for device to respond"
	end
end


function checkBlock(blockNo, keys, keyType)
	-- The command data is only 512 bytes, each key is 6 bytes, meaning that we can send max 85 keys in one go. 
	-- If there's more, we need to split it up
	local start, remaining= 1, #keys
	local packets = {}
	while remaining > 0 do
		local n,data = remaining, nil
		if remaining > 85 then n = 85 end
		local data = table.concat(keys,"",start,n)
		--print("data",data)
		--print("data len", #data)
		print(("Testing block %d, keytype %d, with %d keys"):format(blockNo, keyType, n))
		local command = Command:new{cmd = cmds.CMD_MIFARE_CHKKEYS, 
								arg1 = blockNo, 
								arg2 = keyType, 
								arg3 = n, 
								data = data}
		local status = checkCommand(command)
		if status then return status, blockNo end
		start = start+n+1
		remaining = remaining - n
	end
	return nil
end

-- A function to display the results
local function displayresults(results)
	local sector, blockNo, keyA, keyB,_

	print("________________________________________")
	print("|Sector|Block|     A      |      B     |")
	print("|--------------------------------------|")

	for sector,_ in pairs(results) do
		blockNo, keyA, keyB = unpack(_)

		print(("| %3d  | %3d |%s|%s|"):format(sector, blockNo, keyA, keyB ))
	end
	print("|--------------------------------------|")

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
local function dumptofile(results)
	local sector, blockNo, keyA, keyB,_

	if utils.confirm("Do you wish to save the keys to dumpfile?") then 
		local destination = utils.input("Select a filename to store to", "dumpkeys.bin")
		local file = io.open(destination, "w")
		if file == nil then 
			print("Could not write to file ", destination)
			return
		end

		local key_a = ""
		local key_b = ""
		
		for sector,_ in pairs(results) do
			blockNo, keyA, keyB = unpack(_)
			key_a = key_a .. bin.pack("H",keyA);
			key_b = key_b .. bin.pack("H",keyB);
		end
		file:write(key_a)
		file:write(key_b)
		file:close()
	end
end


local function main( args)

	print(desc);

	result, err = reader.read1443a()
	if not result then
		print(err)
		return
	end
	print(("Found a %s tag"):format(result.name))


	core.clearCommandBuffer()
	local blockNo
	local keyType = 0 -- A=0, B=1
	local numSectors = 16 

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
	for sector=1,numSectors,1 do

		--[[
		The mifare Classic 1k card has 16 sectors of 4 data blocks each. 
		The first 32 sectors of a mifare Classic 4k card consists of 4 data blocks and the remaining
		8 sectors consist of 16 data blocks. 
		--]]
		local blockNo = sector * 4 -1 
		
		if sector > 32 then
			blockNo = 32*4+ (sector-32)*16 -1
		end

		local keyA = checkBlock(blockNo, keys, 0)
		if keyA then keys  = placeFirst(keyA, keys) end
		keyA = keyA or ""

		local keyB = checkBlock(blockNo, keys, 1)
		if keyB then keys  = placeFirst(keyB, keys) end
		keyB = keyB or ""

		result[sector] = {blockNo, keyA, keyB }

		-- Check if user aborted
		if core.ukbhit() then
			print("Aborted by user")
			break
		end
	end
	displayresults(result)
	dumptofile(result)
end

main( args)

