local getopt = require('getopt')
local bin = require('bin')

copyright = 'Copyright (c) 2019 Bogito. All rights reserved.'
author = 'Bogito'
version = 'v1.1.0'
desc =
[[
This script will read the flash memory of RDV4 using SPIFFS and print the stored passwords.
It was meant to be used as a help tool after using the BogRun standalone mode.
]]
example =
[[
    -- This will read the hf_bog.log file in SPIFFS and print the stored passwords
    script run read_pwd_mem_spiffs

    -- This will read the other.log file in SPIFFS and print the stored passwords
    script run read_pwd_mem_spiffs -f other.log
]]
usage =
[[
Usage:
    script run read_pwd_mem_spiffs -h -f <filename>

Arguments:
    -h              :  this help
    -f <filename>   :  filename in SPIFFS
]]
---
-- This is only meant to be used when errors occur
local function oops(err)
    print('ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end
---
-- Usage help
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print('Example usage')
    print(example)
    print(usage)
end
---
-- The main entry point
local function main(args)

    print( string.rep('--',20) )
	print('Read passwords stored in memory (SPIFFS)')
    print( string.rep('--',20) )
    print()

    local data, length, err
    local cnt = 0
    local filename = 'hf_bog.log'
	local keylength = 4

    for o, a in getopt.getopt(args, 'f:h') do

        -- help
        if o == 'h' then return help() end

        -- offset
        if o == 'f' then filename = a end

	end

    data, length, err = core.GetFromFlashMemSpiffs(filename)
    if data == nil then return oops('Problem while reading file from SPIFFS') end

    --print('Filename', filename)
	--print('Filesize (B)', length)

	_, s = bin.unpack('H'..length, data)

	local cnt = 0, i
	for i = 1, length/keylength do
		key  = string.sub(s, (i-1)*8+1, i*8)
		if key == 'FFFFFFFF' then break end
		print(string.format('[%02d] %s',i, key))
		cnt = cnt + 1
	end
	print( string.rep('--',20) )
	print( ('[+] found %d passwords'):format(cnt))

end

main(args)
