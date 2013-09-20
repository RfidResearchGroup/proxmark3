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
-- ISO14A_COMMAND.ISO14A_RAW(8) and ISO14A_CONNECT (1). However, we don't have a 
-- bitlib yet, so we'll do it manually, 1 & 8 == 9
-- ISO14A_NO_DISCONNECT = 2 ==> 11

print(string.len(rawdata))
local command = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = 3, -- Connect (1) and don't disconnect (2)
									arg2 = 0
                  }
local mf_auth = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = 10, -- Send raw 
									-- arg2 contains the length. 
									-- Remember; rawdata is an ascii string containing
									-- ASCII characters. Thus; rawdata= "FF" are two bytes in length
									-- but when converted to true hexvalues internally inside the Command 
									-- constructor, 0xFF is only one byte. So, the bytelength is the 
									-- length of the ASCII-string divided by two. Thanks jonor!

									arg2 = string.len(rawdata)/2, 
									data = rawdata}
local quit = Command:new{cmd = cmds.CMD_READER_ISO_14443a, 
									arg1 = 0, -- Nothing 
									}
									
core.clearCommandBuffer()
--print("Sending")
--print(command)
local err = core.SendCommand(command:getBytes())
if err then
	print(err)
	return nil, err
end
local cardselect = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
print("Card select:")
show(cardselect)
--local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
--print("Raw response:")
--show(response)

local answer = ""
while answer ~='q' do
  	
	local err = core.SendCommand(mf_auth:getBytes())
		if err then
			print(err)
			return nil, err
		end
	local nonce = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)
	print("Nonce:")
	show(nonce)
  	io.write("Write q to quit, hit any char to get a nonce ")
  	io.flush()
  	answer=io.read(1)

end--]]
