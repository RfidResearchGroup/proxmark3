local reader = require('hf_reader')
local getopt = require('getopt')
local ansicolors  = require('ansicolors')

copyright = ''
author = ''
version = 'v1.0.1'
desc = [[
This script tries to detect a HF card. Just like 'hf search' does but this is experimental
]]
example = [[
    1. script run hf_read
]]
usage = [[
script run hf_read
]]
arguments = [[
    -h             - this help
]]
---
-- This is only meant to be used when errors occur
local function dbg(err)
    if not DEBUG then return end
    if type(args) == 'table' then
        local i = 1
        while args[i] do
            dbg(args[i])
            i = i+1
        end
    else
        print('###', args)
    end
end
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
---
--
local function main(args)
    -- Arguments for the script
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return help() end
    end
    
    print("WORK IN PROGRESS - not expected to be functional yet")
    info, err = reader.waitForTag()

    if err then
        print(err)
        return
    end
    local k,v
    print("Tag info")
    for k,v in pairs(info) do
        print(string.format("    %s : %s", tostring(k), tostring(v)))
    end
    return
end

main(args)
