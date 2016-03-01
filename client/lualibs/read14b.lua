
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
local TIMEOUT = 10000 -- Shouldn't take longer than 2 seconds

local function parse1443b_reqb(data)
	--[[
	--]]
	local pcb = data:sub(1,2)
	local uid = data:sub(3,10)
	local pps = data:sub(11,18)
	local ats = data:sub(19,24)
	local crc = data:sub(25,29)
	return { pcb = pcb, uid = uid, pps = pps, ats = ats, crc = crc, cid = '' }
end

local function parse1443b_attrib(data)
	--[[
	--]]
	local attrib = data:sub(1,2)
	local crc = data:sub(3,7)
	return { attrib = attrib, crc = crc }
end


--- Sends a USBpacket to the device
-- @param command - the usb packet to send
-- @param readresponse - if set to true, we read the device answer packet 
-- 		which is usually recipe for fail. If not sent, the host will wait 2s for a 
-- 		response of type CMD_ACK
-- @return 	packet,nil if successfull
--			nil, errormessage if unsuccessfull
local function sendToDevice(cmd, readresponse)
	core.clearCommandBuffer()
	local err = core.SendCommand(cmd:getBytes())
	if err then
		print(err)
		return nil, err
	end
	if readresponse == 0 then return '',nil end
	local response = core.WaitForResponseTimeout(cmds.CMD_ACK, TIMEOUT)
	if response == nil then return nil, nil	end
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
	local len = tonumber(response.arg1) * 2
	local data = string.sub(response.data, 0, len);
	print("<< ",data)
end

---
-- Sends a usbpackage ,  "hf 14b raw" and the 14bCrc is added to the rawdata before sending
local function sendRaw(rawdata, readresponse, addcrc)
	-- add crc first
	local rawdata_crc = rawdata
	if ( addcrc == 1) then 
		rawdata_crc = utils.Crc14b(rawdata)	
	end
	print(">> ", rawdata_crc)
	
	local command = Command:new{cmd = cmds.CMD_ISO_14443B_COMMAND, 
								arg1 = #rawdata_crc/2, 	-- LEN of data, which is half the length of the ASCII-string rawdata
								arg2 = readresponse, 	-- read response
								arg3 = 1,  				-- leave power on
								data = rawdata_crc}		-- raw data bytes 
	return sendToDevice(command, readresponse) 
end

-- This function does a connect and retrieves some info
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error

-- void SendRawCommand14443B(uint32_t datalen, uint32_t recv, uint8_t powerfield, uint8_t data[])
local function select1443b()

	local result, infoReqb, infoAttrib, infoPong, err, resp, len, data
	local goodReqbResponse = false
	--REQB
	local p = 5
	while p > 0 do
		-- 05 00 08
		-- 05
		--   command (REQB/WUPB)
		-- 00
		--   AFI application family identifier  ( 00 == all sorts)
		-- 08  (ie WUPB)
		--   bit 0-1-2   | N slots  ( 0 = 1, 1 = 2, 2 = 4, 3 = 8, 4 == 16)
		--   bit 3 		 | (1== WUPB, 0 == REQB)  
		--   bit 4-5-6-7 | AFI application family identifier
		local result, err = sendRaw('050008', 1, 1)
		if result then
			resp = Command.parse( result )
			len = tonumber(resp.arg1) * 2
			local data = string.sub(resp.data, 0, len)
			if ( resp.arg1 == 14 ) then
				--print ('DATA ::', data)
				infoReqb, err = parse1443b_reqb(data)
				--print(infoReqb.pcb, infoReqb.uid, infoReqb.pps, infoReqb.ats, infoReqb.crc)
				goodReqbResponse = true
				break -- break while loop. REQB got a good response
			end
		end
		
		-- send some strange 0A/0C
		if ( p < 3) then
			sendRaw('0A', 0, 0)
			sendRaw('0C', 0, 0)
		end
		
		p = p - 1
		print('retrying')
	end

	if goodReqbResponse == false then 
		err = "No response from card"
		print(err) 
		return nil, err	
	end
	--SLOT MARKER
	-- result, err = sendRaw('05', 1, 1)
	-- if result then
		-- showData(result)
		-- resp = Command.parse( result )
		-- if arg1 == 0 then 
			-- return nil, "iso14443b card - SLOT MARKER failed"
		-- end
		-- len = tonumber(resp.arg1) * 2
		-- data = string.sub(resp.data, 0, len)
		-- infoAttrib, err = parse1443b_attrib(data)
		-- print( infoAttrib.attrib, infoAttrib.crc)		
	-- else
		-- err ="No response from card"
		-- print(err) 
		-- return nil, err
	-- end
	
	--ATTRIB
	local cid = '00'
	result, err = sendRaw('1D'..infoReqb.uid..'000801'..cid, 1, 1)
	if result then
		showData(result)
		resp = Command.parse( result )
		if resp.arg1 == 0 then 
			return nil, "iso14443b card - ATTRIB failed"
		end
		len = tonumber(resp.arg1) * 2
		data = string.sub(resp.data, 0, len)
		infoAttrib, err = parse1443b_attrib(data)
		infoReqb.cid = infoAttrib.attrib:sub(2,2)
	else
		err ="No response from card"
		print(err) 
		return nil, err
	end
	
	--PING / PONG - Custom Anticollison for Navigo.
	local ping = ('BA00')
	result, err = sendRaw(ping, 1, 1)
	if result then
		resp = Command.parse( result )
		if arg1 == 0 then 
			return nil, "iso14443b card - PING/PONG failed"
		end		
		showData(result)
	else
		err = "No response from card"
		print(err) 
		return nil, err
	end

	return infoReqb
end

---
-- Waits for a mifare card to be placed within the vicinity of the reader. 
-- @return if successfull: an table containing card info
-- @return if unsuccessfull : nil, error
local function waitFor14443b()
	print("Waiting for card... press any key to quit")
	while not core.ukbhit() do
		res, err = select1443b()
		if res then return res end
		-- err means that there was no response from card
	end
	return nil, "Aborted by user"
end

local function disconnect(uid)

	local halt = ('50'..uid) -- 50 UID0 UID1 UID2 UID3 CRC1 CRC2
	result, err = sendRaw(halt, 1, 1)
	if result then
		resp = Command.parse( result )
		showData(result)  -- expected answer is 00 CRC1 CRC2
	else
		err = "No response from card"
		print(err) 
		return nil, err
	end

	-- shutdown raw command / pm3 device.
	local command = Command:new{ cmd = cmds.CMD_ISO_14443B_COMMAND, arg1 = 0, arg2 = 0, arg3 = 0 }
	-- We can ignore the response here, no ACK is returned for this command
	-- Check /armsrc/iso14443b.c, SendRawCommand14443B() for details
	return sendToDevice(command, 0) 
end

local library = {
	select1443b = select1443b,
	select 	= select1443b,
	waitFor14443b = waitFor14443b,
	sendToDevice = sendToDevice,
	disconnect = disconnect,
	sendRaw = sendRaw,
	showData = showData,
}

return library