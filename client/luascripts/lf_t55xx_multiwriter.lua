local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')
local os = require('os')
local dash = string.rep('--', 32)
local dir = os.getenv('HOME') .. '/.proxmark3/logs/'
local logfile = (io.popen('dir /a-d /o-d /tw /b/s "' .. dir .. '" 2>nul:'):read("*a"):match("%C+"))
local command = core.console
local pm3 = require('pm3')
p = pm3.pm3()
command('clear')
author = ' jareckib - 12.03.2025'
version = ' v1.06'
mod = ' 20.03.2025'
desc = [[

  This simple script stores 1, 2 or 3 different EM4102 on a single T5577.
  There is an option to enter the number engraved on the fob in decimal form.
  The script can therefore be useful if the original EM4102 doesn't work but
  has an engraved ID number. By entering such an ID as a single EM4102, we
  can create a working copy of our damaged fob.
  A tag T5577 created in this way works with the following USB readers:

  - ACM08Y
  - ACM26C
  - Sycreader R60D
  - Elatech Multitech TWN4
]]
usage = [[
  script run lf_t55xx_multiwriter
]]
arguments = [[
  script run lf_t55xx_multiwriter -h    : this help
]]

local function help()
    print()
    print(ac.yellow..'  Author:'..ac.reset..author)
    print(ac.yellow..'  Version:'..ac.reset..version)
    print(ac.yellow..'  Modification date:'..ac.reset..mod)
    print(desc)
    print(ac.cyan .. '  Usage' .. ac.reset)
    print(usage)
    print(ac.cyan .. '  Arguments' .. ac.reset)
    print(arguments)
end

local function sleep(n)
    os.execute("sleep " ..tonumber(n))
end

function wait(msec)
   local t = os.clock()
   repeat
   until os.clock() > t + msec * 1e-3
end

local function timer(n)
    while n > 0 do
        io.write(ac.cyan.."::::: "..ac.yellow.. tonumber(n) ..ac.yellow.." sec "..ac.cyan..":::::\r"..ac.reset)
        sleep(1)
        io.flush()
        n = n-1
    end
end

local function reset_log_file()
    local file = io.open(logfile, "w+")
    file:write("")
    file:close()
end

local function read_log_file(logfile)
    local file = io.open(logfile, "r")
    if not file then
        return nil
    end
    local content = file:read("*all")
    file:close()
    return content
end

local function extract_uid(log_content)
    for line in log_content:gmatch("[^\r\n]+") do
        local uid = line:match("%[%s*%+%]%s*EM%s*410x%s*ID%s*([A-F0-9]+)")
        if uid then
            return uid
        end
    end
    return nil
end

local function hex_to_bin(hex_value)
    if not hex_value:match("^[A-Fa-f0-9]+$") or #hex_value ~= 10 then
        error("Invalid UID format. Must be a valid 5-byte HEX value.")
    end
    local decimal_value = tonumber(hex_value, 16)
    if not decimal_value then
        error("Error: Invalid HEX conversion.")
    end
    local binary = ""
    for i = 39, 0, -1 do
        binary = binary .. ((decimal_value & (1 << i)) ~= 0 and "1" or "0")
    end
    if #binary ~= 40 then
        error("Unexpected UID length after conversion to binary.")
    end
    return binary
end

local function even_parity(bits)
    return (bits:gsub("0", ""):len() % 2 == 0) and "0" or "1"
end

local function encode_uid(uid)
    local uid_bin = hex_to_bin(uid)
    local start_bits = '1' .. string.rep('1', 8)
    local data_with_parity = ''
    for i = 1, 40, 4 do
        local nibble = uid_bin:sub(i, i + 3)
        local parity_bit = even_parity(nibble)
        data_with_parity = data_with_parity .. nibble .. parity_bit
    end
    local col_parity_bits = ''
    for i = 1, 4 do
        local col_bits = ''
        for j = i, #data_with_parity, 5 do
            col_bits = col_bits .. data_with_parity:sub(j, j)
        end
        col_parity_bits = col_parity_bits .. even_parity(col_bits)
    end
    local stop_bit = '0'
    local full_bin = start_bits .. data_with_parity .. col_parity_bits .. stop_bit
    return string.format("%X", tonumber(full_bin, 2))
end

local function get_uid_from_user()
    while true do
        print(dash)
        io.write(ac.cyan .. '(1)' .. ac.reset .. ' Manual entry UID |' .. ac.cyan .. ' (2)' .. ac.reset .. ' Read via Proxmark3 ')

        local choice
        repeat
            choice = io.read()
            if choice ~= "1" and choice ~= "2" then
                io.write(ac.yellow .. "Invalid choice. Please enter (1) or (2)  " .. ac.reset)
            end
        until choice == "1" or choice == "2"
        if choice == "1" then
            local format
            repeat
                io.write("Choose format HEX or DEC (engraved ID) "..ac.cyan.."(h/d) "..ac.reset)
                format = io.read():lower()
                if format ~= "h" and format ~= "d" then
                    print(ac.yellow .. "Invalid choice. Choose format HEX or DEC" .. ac.reset)
                end
            until format == "h" or format == "d"
            while true do
                io.write("Enter 10-character UID: "..ac.green)
                local uid = io.read():upper()
                if format == "h" and uid:match("^[A-F0-9]+$") and #uid == 10 then
                    return uid
                elseif format == "d" and uid:match("^%d%d%d%d%d%d%d%d%d%d$") then
                    return string.format("%010X", tonumber(uid))
                else
                    print(ac.yellow .. "Invalid UID format. Enter exactly 10 characters in selected format." .. ac.reset)
                end
            end
        elseif choice == "2" then
            io.write("Place original FOB on coil for reading and press" ..ac.cyan.." Enter..." .. ac.reset)
            io.read()
            while true do
                reset_log_file()
                p:console('lf em 410x read')
                local log_content = read_log_file(logfile)
                local uid = extract_uid(log_content)
                if uid and #uid == 10 then
                    print("Readed EM4102 ID: " ..ac.green.. uid ..ac.reset)
                    return uid
                else
                    io.write(ac.yellow .. "Error reading UID. Please adjust FOB position and press Enter..." .. ac.reset)
                    io.read()
                end
            end
        end
    end
end

local function verify_written_data(blocks, block0_value, uid_count)
    reset_log_file()
    p:console('lf t55 detect')
    for i = 0, #blocks do
        p:console('lf t55 read -b ' .. i)
    end
    local log_content = read_log_file(logfile)
    local verified = true
    local pattern_block0 = "%[%s*%+%]%s*00%s*|%s*([A-F0-9]+)"
    local found_block0 = log_content:match(pattern_block0)
    if not found_block0 or found_block0:upper() ~= block0_value:upper() then
        print("Error in block 0 ...expected: " .. ac.green .. block0_value .. ac.reset .. " ...found: " .. ac.green .. (found_block0 or "N/A") .. ac.reset)
        verified = false
    end
    for i = 1, #blocks do
        local expected_block = blocks[i]
        local pattern = "%[%s*%+%]%s*" .. string.format("%02X", i) .. " |%s*([A-F0-9]+)"
        local found_block = log_content:match(pattern)
        if not found_block or found_block:upper() ~= expected_block:upper() then
            print("Error in block " .. i .. " ...expected: " .. ac.green .. expected_block .. ac.reset .. " ...found: " .. ac.green .. (found_block or "N/A") .. ac.reset)
            verified = false
        end
    end
    return verified
end

local function write(blocks, block0_value)
    p:console('lf t55xx write -b 0 -d ' .. block0_value)
    for i = 1, #blocks do
        p:console('lf t55xx write -b ' .. i .. ' -d ' .. blocks[i])
    end
end

local function main(args)
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then
            return help()
        end
    end
    local blocks = {}
    local uid_count = 0
    for i = 1, 3 do
        local uid = get_uid_from_user()
        local encoded_hex = encode_uid(uid)
        blocks[#blocks + 1] = encoded_hex:sub(1, 8)
        blocks[#blocks + 1] = encoded_hex:sub(9, 16)
        uid_count = uid_count + 1
        if i < 3 then
            local next_choice
            repeat
                io.write(ac.reset.."Do you want to add another UID? "..ac.cyan.."(y/n)  "..ac.reset)
                next_choice = io.read():lower()
                if next_choice ~= "y" and next_choice ~= "n" then
                    print(ac.yellow .. "Invalid choice. Please enter (y) for yes or (n) for no." .. ac.reset)
                end
            until next_choice == "y" or next_choice == "n"
            if next_choice == "y" then
                print(dash)
                print(ac.yellow .. (i == 1 and "::: Second UID :::" or "::: Third UID :::") .. ac.reset)
            elseif next_choice == "n" then
                break
            end
        end
    end
    local block0_value = (uid_count == 1) and "00148040" or (uid_count == 2) and "00148080" or "001480C0"
    io.write("Place the " .. ac.cyan .. "T5577" .. ac.reset .. " tag on the coil for writing and press " .. ac.cyan .. "Enter..." .. ac.reset)
    io.read()
    write(blocks, block0_value)
    print(dash)
    timer(3)
    local verified = verify_written_data(blocks, block0_value, uid_count)
    while not verified do
        print("Verification failed." .. ac.reset .. " Please adjust the " .. ac.cyan .. "T5577" .. ac.reset .. " position and try again.")
        io.write("Press " .. ac.cyan .. "Enter" .. ac.reset .. " to retry...")
        io.read()
        write(blocks, block0_value)
        timer(3)
        verified = verify_written_data(blocks, block0_value, uid_count)
    end
    print(ac.green .. "Successfully written " .. ac.reset .. uid_count .. ac.green .. " EM4102 UID(s) to T5577" .. ac.reset)
end

main(args)
