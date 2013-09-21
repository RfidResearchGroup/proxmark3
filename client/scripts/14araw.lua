local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')

example = "script run 14araw -x 6000F57b"
author = "Martin Holst Swende"


desc =
[[
This is a script to allow raw 1444a commands to be sent and received. 

Arguments:
	-o 				do not connect - use this only if you previously used -p to stay connected 
	-r 				do not read response
	-c 				calculate and append CRC
	-p 				stay connected - dont inactivate the field
	-x <payload> 	Data to send (NO SPACES!)
	-d 				Debug flag

Examples : 

# 1. Connect and don't disconnect
script run 14araw -p 
# 2. Send mf auth, read response (nonce)
script run 14araw -o -x 6000F57b -p
# 3. disconnect
script run 14araw -o

# All three steps in one go:
script run 14araw -x 6000F57b
]]

--[[

This script communicates with 
/armsrc/iso14443a.c, specifically ReaderIso14443a() at around line 1779 and onwards. 

Check there for details about data format and how commands are interpreted on the 
device-side.  
]]

-- Some globals
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = false -- the debug flag

-------------------------------
-- Some utilities 
-------------------------------

--- 
-- A debug printout-function
function dbg(args)
	if DEBUG then
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

--- 
-- The main entry point
function main(args)

	if args == nil or #args == 0 then
		return help()
	end

	local ignore_response = false
	local appendcrc = false
	local stayconnected = false
	local payload = nil
	local doconnect = true

	-- Read the parameters
	for o, a in getopt.getopt(args, 'corcpx:') do
		if o == "o" then doconnect = false end		
		if o == "r" then ignore_response = true end
		if o == "c" then appendcrc = true end
		if o == "p" then stayconnected = true end
		if o == "x" then payload = a end
		if o == "d" then DEBUG = true end
	end

	-- First of all, connect
	if doconnect then
		dbg("doconnect")
		-- We reuse the connect functionality from a 
		-- common library
		info, err = lib14a.read1443a(true)

		if err then return oops(err) end
		print(("Connected to card, uid = %s"):format(info.uid))
	end

	-- The actual raw payload, if any
	if payload then
		res,err = sendRaw(payload,{ignore_response = ignore_response})
		if err then return oops(err) end
	
		if not ignoreresponse then 
			-- Display the returned data	
			showdata(res)
		end
	end
	-- And, perhaps disconnect?
	if not stayconnected then 
		disconnect()
	end
end

--- Picks out and displays the data read from a tag
-- Specifically, takes a usb packet, converts to a Command
-- (as in commands.lua), takes the data-array and 
-- reads the number of bytes specified in arg1 (arg0 in c-struct)
-- and displays the data
-- @param usbpacket the data received from the device
function showdata(usbpacket)
	local cmd_response = Command.parse(usbpacket)
	local len = tonumber(cmd_response.arg1) *2
	--print("data length:",len)
	local data = string.sub(tostring(cmd_response.data), 0, len);
	print("<< ",data)
	--print("----------------")
end



function sendRaw(rawdata, options)
	print(">> ", rawdata)
	
	local flags = lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT + lib14a.ISO14A_COMMAND.ISO14A_RAW

	local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = flags, -- Send raw 
									-- arg2 contains the length, which is half the length 
									-- of the ASCII-string rawdata
									arg2 = string.len(rawdata)/2, 
									data = rawdata}
	return lib14a.sendToDevice(command, options.ignore_response) 
end

-- Sends an instruction to do nothing, only disconnect
function disconnect()

	local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = 0, -- Nothing 
									}
	-- We can ignore the response here, no ACK is returned for this command
	-- Check /armsrc/iso14443a.c, ReaderIso14443a() for details
	return lib14a.sendToDevice(command,true) 
end								


-------------------------
-- 	Testing
-------------------------
function selftest()
	DEBUG = true
	dbg("Performing test")
	main()
	main("-p")
	main(" -o -x 6000F57b -p")
	main("-o")
	main("-x 6000F57b")
	dbg("Tests done")
end
-- Flip the switch here to perform a sanity check. 
-- It read a nonce in two different ways, as specified in the usage-section
if "--test"==args then 
	selftest()
else 
	-- Call the main 
	main(args)
end
