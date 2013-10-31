--[[
THIS IS WORK IN PROGREESS, very much not finished. 

This library utilises other libraries under the hood, but can be used as a generic reader for 13.56MHz tags. 
]]

local reader14443A = require('read14a')
local cmds = require('commands')
local TIMEOUT = 1000

local function sendToDevice(command, ignoreresponse)
	core.clearCommandBuffer()
	local err = core.SendCommand(command:getBytes())
	if err then
		print(err)
		return nil, err
	end
	if ignoreresponse then return nil,nil end
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
	return response,nil
end

-------------------------------------------------------
-- This will be moved to a separate 14443B library
-------------------------------------------------------

local function read14443B()
	return nil, "Not implemented"
end
local reader14443B = {
	read = read14443B
}	


-------------------------------------------------------
-- This will be moved to a separate 1593 library
-------------------------------------------------------

local function errorString15693(number)
	local errors = {}
	errors[0x01] =  "The command is not supported"
	errors[0x02] =  "The command is not recognised"
	errors[0x03] =  "The option is not supported."
	errors[0x0f] =  "Unknown error."
	errors[0x10] =  "The specified block is not available (doesn’t exist)."
	errors[0x11] =  "The specified block is already -locked and thus cannot be locked again"
	errors[0x12] =  "The specified block is locked and its content cannot be changed."
	errors[0x13] =  "The specified block was not successfully programmed."
	errors[0x14] =  "The specified block was not successfully locked."
	
	return errors[number] or "Reserved for Future Use or Custom command error." 
end
-------------------------------------------------------
-- This will be moved to a separate 1593 library
-------------------------------------------------------

local function parse15693(data)
	-- From common/iso15693tools.h : 
	--[[ 
	#define ISO15_CRC_CHECK	 ((uint16_t)(~0xF0B8 & 0xFFFF)) 	// use this for checking of a correct crc
	--]]
	-- But that is very strange. Basically what is says is:
	-- define ISO15_CRC_CHECK 0F47
	-- So we can just use that directly... 
	-- The following code is based on cmdhf15.c around line 666 (NoTB!) and onwards
	if core.iso15693_crc(data, string.len(data)) ~= 0xF47 then
		return nil, "CRC failed"
	elseif data[1] % 2 == 1 then
		-- Above is a poor-mans bit check:
		-- recv[0] & ISO15_RES_ERROR //(0x01)
		local err = "Tag returned error %i: %s"
		err = string.format(err, data[1],errorString15693(data[1]))
		return nil, err
	end
	-- Finally, let the parsing begin... 
	-- the UID is just the data in reverse... almost:
	-- 	0FC481FF70000104E001001B0301
	--	   8877665544332211
	--  UID = E004010070FF81C4
	--        1122334455667788
	-- So, cut out the relevant part and reverse it
	local uid = data:sub(2,9):reverse()
	local uidStr = bin.unpack("H8", uid)

	local _,manufacturer_code = bin.unpack("s",uid:sub(2,2))
	local _,tag_size = bin.unpack(">I",data:sub(12,13))
	local _,micref_modelcode = bin.unpack("s",data:sub(14,14))

	return {
		uid = uidStr,
		manufacturer_code = manufacturer_code,
		tag_size = tag_size,
		micref_modelcode = micref_modelcode,
	}
end
-------------------------------------------------------
-- This will be moved to a separate 1593 library
-------------------------------------------------------

local function read15693()
	--[[

	We start by trying this command:
	 
		proxmark3> hf 15 cmd sysinfo -2 u
		0F C4 81 FF 70 00 01 04 E0 01 00 1B 03 01
		UID = E004010070FF81C4
		Philips; IC SL2 ICS20
		DSFID supported, set to 01
		AFI supported, set to 000
		Tag provides info on memory layout (vendor dependent)
		 4 (or 3) bytes/page x 28 pages
		IC reference given: 01
	 
	This command is not always present in ISO15693 tags (it is an optional standard command) but if it is present usually the tags contain all the "colored" info above.
	 
	If the above command doesn't give an answer (see example below):
	 
		proxmark3> hf 15 cmd sysinfo -2 u
		timeout: no
		 
	we must send the MANDATORY (present in ALL iso15693 tags) command (the example below is sent to a tag different from the above one):
	 
		proxmark3> hf 15 cmd inquiry
		UID=E007C1A257394244         
		Tag Info: Texas Instrument; Tag-it HF-I Standard; 8x32bit         
		proxmark3>
	 
	From which we obtain less information than the above one.
	--]]

	local command, result, info, err, data
	local data = "02"
	local datalen = string.len(data) / 2
	local speed = 1
	local recv = 1
	command = Command:new{cmd = cmds.CMD_ISO_15693_COMMAND, 
								arg1 = datalen,arg2 = speed,arg3 =recv, data=data}
	-- These are defined in common/iso15693tools.h

	-- #define ISO15_REQ_SUBCARRIER_SINGLE	0x00	// Tag should respond using one subcarrier (ASK)
	-- #define ISO15_REQ_DATARATE_HIGH		0x02	// Tag should respond using high data rate
	-- #define ISO15_REQ_NONINVENTORY		0x00

	local result,err = sendToDevice(command)

	if not result then
		print(err)
		return nil, "15693 sysinfo: no answer"
	end

	local count,cmd,recvLen,arg1,arg2 = bin.unpack('LLLL',result)
	data = string.sub(result,recvlen)
	info, err = parse15693(data)
	
	if err then 
		return nil, err
	end

	return info
end

local reader15693 = {
	read = read15693
}


---
-- This method library can be set waits or a 13.56 MHz tag, and when one is found, returns info about
-- what tag it is. 
-- 
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitForTag()
	print("Waiting for card... press any key to quit")
	local readers = {reader14443A, reader14443B, reader15693}
	local i = 0;
	while not core.ukbhit() do
		i = (i % 3) +1
		r = readers[i]
		print("Reading with ",i)
		res, err = r.read()
		if res then return res end
		print(err)
			-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end

return {
	waitForTag = waitForTag,
}