--[[
	This is a library to read 14443a tags. It can be used something like this

	local reader = require('read14a')
	result, err = reader.read1443a()
	if not result then
		print(err)
		return
	end
	print(result.name)

--]]
-- Loads the commands-library
local cmds = require('commands')
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local ISO14A_COMMAND = {
	ISO14A_CONNECT = 1,
	ISO14A_NO_DISCONNECT = 2,
	ISO14A_APDU = 4,
	ISO14A_RAW = 8,
	ISO14A_REQUEST_TRIGGER = 0x10,
	ISO14A_APPEND_CRC = 0x20,
	ISO14A_SET_TIMEOUT = 0x40,
	ISO14A_NO_SELECT = 0x80,
	ISO14A_TOPAZMODE = 0x100
}

local ISO14443a_TYPES = {}		
ISO14443a_TYPES[0x00] = "NXP MIFARE Ultralight | Ultralight C"
ISO14443a_TYPES[0x01] = "NXP MIFARE TNP3xxx Activision Game Appliance"
ISO14443a_TYPES[0x04] = "NXP MIFARE (various !DESFire !DESFire EV1)"
ISO14443a_TYPES[0x08] = "NXP MIFARE CLASSIC 1k | Plus 2k"
ISO14443a_TYPES[0x09] = "NXP MIFARE Mini 0.3k"
ISO14443a_TYPES[0x10] = "NXP MIFARE Plus 2k"
ISO14443a_TYPES[0x11] = "NXP MIFARE Plus 4k"
ISO14443a_TYPES[0x18] = "NXP MIFARE Classic 4k | Plus 4k"
ISO14443a_TYPES[0x20] = "NXP MIFARE DESFire 4k | DESFire EV1 2k/4k/8k | Plus 2k/4k | JCOP 31/41"
ISO14443a_TYPES[0x24] = "NXP MIFARE DESFire | DESFire EV1"
ISO14443a_TYPES[0x28] = "JCOP31 or JCOP41 v2.3.1"
ISO14443a_TYPES[0x38] = "Nokia 6212 or 6131 MIFARE CLASSIC 4K"
ISO14443a_TYPES[0x88] = "Infineon MIFARE CLASSIC 1K"
ISO14443a_TYPES[0x98] = "Gemplus MPCOS"


local function tostring_1443a(sak)
	return ISO14443a_TYPES[sak] or ("Unknown (SAK=%x)"):format(sak)
end

local function parse1443a(data)
	--[[

	Based on this struct : 

	typedef struct {
		byte_t uid[10];
		byte_t uidlen;
		byte_t atqa[2];
		byte_t sak;
		byte_t ats_len;
		byte_t ats[256];
	} __attribute__((__packed__)) iso14a_card_select_t;

	--]]

	local count,uid,uidlen, atqa, sak, ats_len, ats= bin.unpack('H10CH2CC',data)
	uid = uid:sub(1,2*uidlen)
	--print("uid, atqa, sak: ",uid, atqa, sak)
	--print("TYPE: ", tostring_1443a(sak))
	return { uid = uid, atqa  = atqa, sak = sak, name = tostring_1443a(sak)}
end

--- Sends a USBpacket to the device
-- @param command - the usb packet to send
-- @param ignoreresponse - if set to true, we don't read the device answer packet 
-- 		which is usually recipe for fail. If not sent, the host will wait 2s for a 
-- 		response of type CMD_ACK
-- @return 	packet,nil if successfull
--			nil, errormessage if unsuccessfull

local function sendToDevice(command, ignoreresponse)
	--core.clearCommandBuffer(
	local err = core.SendCommand(command:getBytes())
	if err then
		print(err)
		return nil, err
	end
	if ignoreresponse then return nil,nil end

	local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
	return response,nil
end

-- This function does a connect and retrieves som einfo
-- @param dont_disconnect - if true, does not disable the field
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function read14443a(dont_disconnect)
	local command, result, info, err, data

	command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
								arg1 = ISO14A_COMMAND.ISO14A_CONNECT}
	if dont_disconnect then
		command.arg1 = command.arg1 + ISO14A_COMMAND.ISO14A_NO_DISCONNECT
	end
	local result,err = sendToDevice(command)
	if result then
		local count,cmd,arg0,arg1,arg2 = bin.unpack('LLLL',result)
		if arg0 == 0 then 
			return nil, "iso14443a card select failed"
		end
		data = string.sub(result,count)
		info, err = parse1443a(data)
	else
		err ="No response from card"
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
local function waitFor14443a()
	print("Waiting for card... press any key to quit")
	while not core.ukbhit() do
		res, err = read14443a()
		if res then return res end
		-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end
local library = {
	
	read1443a = read14443a,
	read 	= read14443a,
	waitFor14443a = waitFor14443a,
	parse1443a = parse1443a,
	sendToDevice = sendToDevice,
	ISO14A_COMMAND = ISO14A_COMMAND,
}

return library