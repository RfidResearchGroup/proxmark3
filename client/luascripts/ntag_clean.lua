local reader = require('read14a')
local ansicolors  = require('ansicolors')

copyright = 'Trigat'
author = 'Trigat'
version = 'v0.0.1'
desc = [[
This script zero-fills NTAG pages in a user-specified range,
or defaults to pages 4–39.

Pages 0–3 (UID and configuration) cannot be erased.
]]
example = [[
    -- Zero-fill default range (pages 4–39) with 0x00
    1. script run ntag_clean

    -- Zero-fill a custom range (pages 6–10)
    2. script run ntag_clean -s 6 -e 10

    -- Fill pages 4–39 with 0xFF
    3. script run ntag_clean -d FF
]]
usage = [[
script run ntag_clean [-s <start>] [-e <end>] [-d <hex>]
]]
arguments = [[
    -h             : this help
    -s <start>     : start page (default 4)
    -e <end>       : end page (default 39)
    -d <hex>       : data to write (8 hex chars, e.g. 00000000)
                     If 2 hex chars are given (e.g. FF), it repeats to 8 (FFFFFFFF).
]]

local function normalize_hex(h)
    if not h then return nil end
    h = h:gsub("%s+", "")
    if not h:match("^[0-9a-fA-F]+$") then return nil end
    if #h == 2 then
        h = h:rep(4)   -- "FF" converted to "FFFFFFFF"
    end
    if #h ~= 8 then
        return nil
    end
    return h:upper()
end

local function parse_args(argv)
    local opts = {}
    local i = 1
    while i <= #argv do
        local a = argv[i]
        if a == "-h" then
            opts.h = true
        elseif a == "-s" then
            opts.s = tonumber(argv[i+1]); i = i + 1
        elseif a == "-e" then
            opts.e = tonumber(argv[i+1]); i = i + 1
        elseif a == "-d" then
            opts.d = argv[i+1]; i = i + 1
        end
        i = i + 1
    end
    return opts
end

-- check if card exists
local function card_present()
    local tag, err = reader.read()
    if not tag then
        print("No card detected. Aborting.")
        return false
    end

    print("Card detected:", tag.uid, tag.name)
    return true
end

-- Help output
local function help()
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

-- convert global args string into table
local function split_args(argstr)
    local t = {}
    if not argstr then return t end
    for word in argstr:gmatch("%S+") do
        table.insert(t, word)
    end
    return t
end

local function main(args)
    local start_block = 4
    local end_block   = 39  -- Can be modified by user
    local data        = "00000000"

    local argv = split_args(args)
    local opts = parse_args(argv)

    if opts.h then return help() end
    if opts.s then start_block = opts.s end
    if opts.e then end_block   = opts.e end
    if opts.d then
        local norm = normalize_hex(opts.d)
        if not norm then
            print("Invalid -d <hex>. Use 8 hex chars (e.g. 00000000) or 2 chars (e.g. FF).")
            return
        end
        data = norm
    end

    if start_block < 4 then
        print("Cannot clean page 0-3. Those are UID and Config pages.")
        return
    end
    if end_block < start_block then
        print("End block must be greater than or equal to start page.")
        return
    end

    -- check if card is present on reader
    if not card_present() then
        return
    end

    print(string.format("Zero-fill (%s) to pages %d..%d", data, start_block, end_block))
    for b = start_block, end_block do
        core.console(string.format("hf mfu wrbl -b %d -d %s", b, data))
    end
    print("Done.")
end

main(args)
