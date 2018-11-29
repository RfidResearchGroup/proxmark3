--[[
	This is a library to read 15693 tags. It can be used something like this

	local reader = require('read15')
	result, err = reader.read15693()
	if not result then
		print(err)
		return
	end
	print(result.name)

--]]
-- Loads the commands-library
local cmds = require('commands')
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds


--- Sends a USBpacket to the device
-- @param command - the usb packet to send
-- @param ignoreresponse - if set to true, we don't read the device answer packet
-- 		which is usually recipe for fail. If not sent, the host will wait 2s for a
-- 		response of type CMD_ACK
-- @return 	packet,nil if successfull
--			nil, errormessage if unsuccessfull
local function sendToDevice(command, ignoreresponse)
	local err = core.SendCommand(command:getBytes())
	if err then
		print(err)
		return nil, err
	end
	if ignoreresponse then return nil,nil end

	local response = core.WaitForResponseTimeout(cmds.CMD_ACK, TIMEOUT)
	return response,nil
end

-- This function does a connect and retrieves som einfo
-- @param dont_disconnect - if true, does not disable the field
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function read15693(slow, dont_readresponse)
	local command, result, info, err, data

	command = Command:new{cmd = cmds.CMD_ISO_15693_COMMAND, arg1 = 0, arg2 = 1, arg3 = 1 }

	if slow then
		command.arg2 = 0
	end
	if dont_readresponse then
		command.arg3 = 0 
	end
	
	local result, err = sendToDevice(command, dont_readresponse)
	if result then
		local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',result)
		if arg0 == 0 then
			return nil, "iso15693 no bytes returned"
		end	
		data = string.sub(result, count)
		info, err = bin.unpack('H', data)
		print("LEN", arg0, data )
	else
		err = "No response from card"
	end

	if err then
		print(err)
		return nil, err
	end
	return info
end

---
-- Waits for a mifare card to be placed within the vicinity of the reader.
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitFor15693()
	print("Waiting for card... press any key to quit")
	while not core.ukbhit() do
		res, err = read15693()
		if res then return res end
		-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end
local library = {
	read = read15693,
	waitFor15693 = waitFor15693,
--	parse15693 = parse15693,
	sendToDevice = sendToDevice,
}

return library
