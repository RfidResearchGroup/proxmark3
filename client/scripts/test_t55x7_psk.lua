local cmds = require('commands')
local getopt = require('getopt')
local bin = require('bin')
local utils = require('utils')
local dumplib = require('html_dumplib')

example =[[
	1. script run tracetest
	2. script run tracetest -o 

]]
author = "Iceman"
usage = "script run test_t55x7_psk -o <filename>"
desc =[[
This script will program a T55x7 TAG with the configuration: block 0x00 data 0x00088040
The outlined procedure is as following:

"lf t55xx write 0 00088040"
"lf read"
"data samples"
"data pskdet"
"data psknrz"
"data pskindala"
"data psknrzraw"

Loop OUTER:
	change the configuretion block 0 with:
    -xxxx8xxx = PSK RF/2 with Manchester modulation
    -xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
    -xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
    -xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)
	Loop INNER
	    for each outer configuration, also do 
			XXXXX0XX = PSK RF/2
			XXXXX4XX = PSK RF/4
			XXXXX8XX = PSK RF/8

In all 12 individual test for the PSK demod

Arguments:
	-h             : this help
	-o             : logfile name
]]

local TIMEOUT = 2000 -- Shouldn't take longer than 2 seconds
local DEBUG = true -- the debug flag

--BLOCK 0 = 00088040
local config1 = '0008'
local config2 = '40'
	
local procedurecmds = {
	[1] = '%s%s%s%s',
	[2] = 'lf read',
	--[3] = '',
	[3] = 'data samples',
	[4] = 'data pskdetectclock',
	[5] = 'data psknrzrawdemod',
	[6] = 'data pskindalademod',
}

--- 
-- A debug printout-function
function dbg(args)
	if not DEBUG then
		return
	end
	
    if type(args) == "table" then
		local i = 1
		while args[i] do
			dbg(args[i])
			i = i+1
		end
	else
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
--
-- Exit message
function ExitMsg(msg)
	print( string.rep('--',20) )
	print( string.rep('--',20) )
	print(msg)
	print()
end

function pskTest(modulation)
	local y
	for y = 0, 8, 4 do
		for _ = 1, #procedurecmds do
			local cmd = procedurecmds[_]
			
			if #cmd == 0 then  
			
			elseif _ == 1 then

				dbg("Writing to T55x7 TAG")
		
				local configdata = cmd:format( config1, modulation , y, config2)
				
				dbg( configdata)
				
				local writecommand = Command:new{cmd = cmds.CMD_T55XX_WRITE_BLOCK, arg1 = configdata ,arg2 = 0, arg3 = 0}
				local err = core.SendCommand(writecommand:getBytes())
				if err then return oops(err) end
				local response = core.WaitForResponseTimeout(cmds.CMD_ACK,TIMEOUT)

				if response then
					local count,cmd,arg0 = bin.unpack('LL',response)
					if(arg0==1) then
						dbg("Writing success")
					else
						return nil, "Couldn't read block.." 
					end
				end

			else
				dbg(cmd)
				core.console( cmd )
			end
		end
		core.clearCommandBuffer()	
	end
	print( string.rep('--',20) )

end

local function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )

	local outputTemplate = os.date("testpsk_%Y-%m-%d_%H%M%S")

	-- Arguments for the script
	for o, arg in getopt.getopt(args, 'ho:') do
		if o == "h" then return help() end
		if o == "o" then outputTemplate = arg end		
	end

	core.clearCommandBuffer()

	pskTest(1)
	pskTest(2)
	pskTest(3)
	pskTest(8)
	
	print( string.rep('--',20) )
end
main(args)

-- Where it iterates over 
  -- xxxx8xxx = PSK RF/2 with Manchester modulation
  -- xxxx1xxx = PSK RF/2 with PSK1 modulation (phase change when input changes)
  -- xxxx2xxx = PSK RF/2 with PSk2 modulation (phase change on bitclk if input high)
  -- xxxx3xxx = PSK RF/2 with PSk3 modulation (phase change on rising edge of input)

    -- XXXXX0XX = PSK RF/2
    -- XXXXX4XX = PSK RF/4
    -- XXXXX8XX = PSK RF/8