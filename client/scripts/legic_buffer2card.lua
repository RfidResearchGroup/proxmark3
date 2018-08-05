-- this script writes bytes 8 to 256 on the Legic MIM256
example = "Script writes to Legic Prime Tag from position 0x07 until 0xFF with the value 0x01"
author = "Mosci"
desc =
[[
This is a script which writes value 0x01 to bytes from position 0x07 until 0xFF on a Legic Prime Tag (MIM256 or MIM1024)
(created with 'hf legic save my_dump.hex') 
	
optional arguments :
	-h       - Help text

Examples : 
	script run legic_buffer2card
]]

local utils = require('utils')
local getopt = require('getopt')
--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
	return nil, err
   end
--- 
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end
--
-- simple loop-write from 0x07 to 0xff
function main()

	-- parse arguments for the script
	for o, a in getopt.getopt(args, 'h') do
		if o == "h" then return help() end
	end

	local cmd = ''
	local i
	for i = 7, 255 do
	    cmd = ('hf legic write 0x%02x 0x01'):format(i)
	    print(cmd)
		core.clearCommandBuffer()
	    core.console(cmd)
		
		-- got a 'cmd-buffer overflow' on my mac - so just wait a little
		-- works without that pause on my linux-box
		utils.Sleep(0.1)
	end
end

main()
