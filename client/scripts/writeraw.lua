local cmds = require('commands')
local desc =
[[

This script is a work in progress, not yet functional. It is an attempt to use the raw-writing 
capabilities already present within the devices

]]

print(desc)

-- Some raw data
local rawdata = "6000F57b" --mf_auth
local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds

function show(usbpacket)
	if usbpacket then
		local response = Command.parse(usbpacket)
		print(response)
	end
end

-- Want to do both connect and send raw, so we should AND the two commands
-- ISO14A_COMMAND.ISO14A_RAW and ISO14A_CONNECT. However, we don't have a 
-- bitlib yet, so we'll do it manually, 1 & 8 == 9
-- ISO14A_NO_DISCONNECT = 2

print(string.len(rawdata))
local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = 9, 
									arg2 = string.len(rawdata), 
									data = rawdata}
core.clearCommandBuffer()
print("Sending")
print(command)
local err = core.SendCommand(command:getBytes())
if err then
	print(err)
	return nil, err
end
local cardselect = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
print("Card select:")
show(cardselect)
local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
print("Raw response:")
show(response)
