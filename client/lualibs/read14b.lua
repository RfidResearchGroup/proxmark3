--[[
	This is a library to read 14443b tags. It can be used something like this

	local reader = require('read14b')
	result, err = reader.select1443b()
	if not result then
		print(err)
		return
	end
	print(result.name)

--]]
-- Loads the commands-library
local cmds = require('commands')
local utils = require('utils')
local TIMEOUT = 2500
local ISO14B_COMMAND = {
	ISO14B_CONNECT = 1,
	ISO14B_DISCONNECT = 2,
	ISO14B_APDU = 4,
	ISO14B_RAW = 8,
	ISO14B_REQUEST_TRIGGER = 0x10,
	ISO14B_APPEND_CRC = 0x20,
	ISO14B_SELECT_STD = 0x40,
	ISO14B_SELECT_SR = 0x80,
}

local function parse1443b(data)
	--[[
	
	Based on this struct : 
	
	typedef struct {
		byte_t uid[10];
		byte_t uidlen;
		byte_t atqb[7];
		byte_t chipid;
		byte_t cid;
	} __attribute__((__packed__)) iso14b_card_select_t;

	--]]
	
	local count, uid, uidlen, atqb, chipid, cid = bin.unpack('H10CH7CC',data)
	uid = uid:sub(1,2*uidlen)
	return { uid = uid, uidlen = uidlen, atqb = atqb, chipid = chipid, cid = cid }
end

--- Sends a USBpacket to the device
-- @param command - the usb packet to send
-- @param ignoreresponse - if set to true, we don't read the device answer packet 
-- 		which is usually recipe for fail. If not sent, the host will wait 2s for a 
-- 		response of type CMD_ACK
-- @return 	packet,nil if successfull
--			nil, errormessage if unsuccessfull
local function sendToDevice(cmd, ignoreresponse)
	--core.clearCommandBuffer()
	local bytes = cmd:getBytes()
	local count,c,arg0,arg1,arg2 = bin.unpack('LLLL',bytes)
	local err = core.SendCommand(cmd:getBytes())
	if err then
		print('ERROR',err)
		return nil, err
	end
	if ignoreresponse then return nil,nil end
	
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK, TIMEOUT)
	return response,nil
end
--- Picks out and displays the data read from a tag
-- Specifically, takes a usb packet, converts to a Command
-- (as in commands.lua), takes the data-array and 
-- reads the number of bytes specified in arg1 (arg0 in c-struct)
-- and displays the data
-- @param usbpacket the data received from the device
local function showData(usbpacket)
	local response = Command.parse(usbpacket)
	local len = response.arg2 * 2
	local data = string.sub(response.data, 0, len);
	print("<< ",data)
end


-- This function does a connect and retrieves some info
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function read14443b(disconnect)

	local command, result, info, err, data

	local flags = ISO14B_COMMAND.ISO14B_CONNECT + 
				  ISO14B_COMMAND.ISO14B_SELECT_STD
	
	if disconnect then
		print('DISCONNECT')
		flags = flags + ISO14B_COMMAND.ISO14B_DISCONNECT
	end

	command = Command:new{cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = flags}
	local result,err = sendToDevice(command, false) 
	if result then
		local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',result)
		if arg0 == 0 then 
			data = string.sub(result, count)
			info, err = parse1443b(data)
		else
			err = "iso14443b card select failed"
		end
	else
		err = "No response from card"
	end

	if err then 
		print(err) 
		return nil, err
	end
	return info
end
--PING / PONG - Custom Anticollison for Navigo.
-- AA / BB ?!?
-- local ping = ('BA00')
-- result, err = sendRaw(ping, 1, 1)
-- if result then
	-- resp = Command.parse( result )
	-- if arg1 == 0 then 
		-- return nil, "iso14443b card - PING/PONG failed"
	-- end		
	-- showData(result)
-- else
	-- err = "No response from card"
	-- print(err) 
	-- return nil, err
-- end


---
-- Waits for a mifare card to be placed within the vicinity of the reader. 
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitFor14443b()
	print("Waiting for card... press any key to quit")
	while not core.ukbhit() do
		res, err = read14443b(false)
		if res then return res end
		-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end

local library = {
	parse1443b  = parse1443b,
	read1443b 	= read14443b,
	waitFor14443b = waitFor14443b,
	sendToDevice = sendToDevice,
	showData = showData,
	ISO14B_COMMAND = ISO14B_COMMAND,
}

return library