local utils = require('utils')
local getopt = require('getopt')
local ansicolors  = require('ansicolors')
-- this script writes bytes 8 to 256 on the Legic MIM256

copyright = ''
author = 'Mosci'
version = 'v1.0.2'
desc =
[[
This is a script which writes value 0x01 to bytes from position 0x07 until 0xFF on a Legic Prime Tag (MIM256 or MIM1024)  -- (created with 'hf legic save my_dump.hex') --
]]
example = [[
    script run legic_buffer2card
]]
usage = [[
script run legic_buffer2card -h
]]
arguments = [[
    -h       - Help text
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
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
--
-- simple loop-write from 0x07 to 0xff
function main()

    -- parse arguments for the script
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end

    local cmd = ''
    local i
    for i = 7, 255 do
        cmd = ('hf legic write o %02x d 01'):format(i)
        print(cmd)
        core.clearCommandBuffer()
        core.console(cmd)

        -- got a 'cmd-buffer overflow' on my mac - so just wait a little
        -- works without that pause on my linux-box
        utils.Sleep(0.1)
    end
end

main()
