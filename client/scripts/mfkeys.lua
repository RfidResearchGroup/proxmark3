--[[
	This is an example of Lua-scripting within proxmark3. This is a lua-side
	implementation of hf mf chk  

	This code is licensed to you under the terms of the GNU GPL, version 2 or,
	at your option, any later version. See the LICENSE.txt file for the text of
	the license.
	
	Copyright (C) 2013 m h swende <martin at swende.se>
]]
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

local function main()

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
	local result = {}
	for sector=1,40,1 do

		--[[
		The mifare Classic 1k card has 16 sectors of 4 data blocks each. The
		first 32 sectors of a mifare Classic 4k card consists of 4 data blocks and the remaining
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
end

main()

