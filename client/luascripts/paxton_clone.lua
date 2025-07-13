local getopt = require('getopt')
local utils = require('utils')
local ac = require('ansicolors')
local os = require('os')
local dash = string.rep('--', 32)
local dir = os.getenv('HOME') .. '/.proxmark3/logs/'
local logfilecmd

--Determine platform for logfile handling (Windows vs Unix/Linux)
if package.config:sub(1,1) == "\\" then
  logfilecmd = 'dir /a-d /o-d /tw /b/s "' .. dir .. '" 2>nul:'
else
  logfilecmd = 'find "' .. dir .. '" -type f -printf "%T@ %p\\n" | sort -nr | cut -d" " -f2-'
end

local logfile = (io.popen(logfilecmd):read("*a"):match("%C+"))
local log_file_path = dir .. "Paxton_log.txt"
local nam = ""
local pm3 = require('pm3')
p = pm3.pm3()
local command = core.console
command('clear')

author = '  Author: jareckib - 30.01.2025'
tutorial = '  Based on Equipter tutorial - Downgrade Paxton to EM4102'
version = '  version v1.20'
desc = [[
  The script automates the copying of Paxton fobs read - write.
  It also allows manual input of data for blocks 4-7.
  The third option is reading data stored in the log file and create new fob.
  Additionally, the script calculates the ID for downgrading Paxton to EM4102.

 ]]
usage = [[
  script run paxton_clone
]]
arguments = [[
  script run paxton_clone -h    : this help
]]

local debug = true

local function dbg(args)
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

local function help()
    print()
    print(author)
    print(tutorial)
    print(version)
    print(desc)
    print(ac.cyan..'  Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'  Arguments'..ac.reset)
    print(arguments)
end

local function reset_log_file()
    local file = io.open(logfile, "w+")
    file:write("")
    file:close()
end

local function read_log_file(logfile)
    local file = io.open(logfile, "r")
    if not file then
        error(" Could not open the file")
    end
    local content = file:read("*all")
    file:close()
    return content
end

local function parse_blocks(result)
    local blocks = {}
    for line in result:gmatch("[^\r\n]+") do
        local block_num, block_data = line:match("%[%=%]%s+%d/0x0([4-7])%s+%|%s+([0-9A-F ]+)")
        if block_num and block_data then
            block_num = tonumber(block_num)
            block_data = block_data:gsub("%s+", "")
            blocks[block_num] = block_data
        end
    end
    return blocks
end

local function hex_to_bin(hex_string)
    local bin_string = ""
    local hex_to_bin_map = {
        ['0'] = "0000", ['1'] = "0001", ['2'] = "0010", ['3'] = "0011",
        ['4'] = "0100", ['5'] = "0101", ['6'] = "0110", ['7'] = "0111",
        ['8'] = "1000", ['9'] = "1001", ['A'] = "1010", ['B'] = "1011",
        ['C'] = "1100", ['D'] = "1101", ['E'] = "1110", ['F'] = "1111"
    }
    for i = 1, #hex_string do
        bin_string = bin_string .. hex_to_bin_map[hex_string:sub(i, i)]
    end
    return bin_string
end

local function remove_last_two_bits(binary_str)
    return binary_str:sub(1, #binary_str - 2)
end

local function split_into_5bit_chunks(binary_str)
    local chunks = {}
    for i = 1, #binary_str, 5 do
        table.insert(chunks, binary_str:sub(i, i + 4))
    end
    return chunks
end

local function remove_parity_bit(chunks)
    local no_parity_chunks = {}
    for _, chunk in ipairs(chunks) do
        if #chunk == 5 then
            table.insert(no_parity_chunks, chunk:sub(2))
        end
    end
    return no_parity_chunks
end

local function convert_to_hex(chunks)
    local hex_values = {}
    for _, chunk in ipairs(chunks) do
        if #chunk > 0 then
            table.insert(hex_values, string.format("%X", tonumber(chunk, 2)))
        end
    end
    return hex_values
end

local function convert_to_decimal(chunks)
    local decimal_values = {}
    for _, chunk in ipairs(chunks) do
        table.insert(decimal_values, tonumber(chunk, 2))
    end
    return decimal_values
end

local function find_until_before_f(hex_values)
    local result = {}
    for _, value in ipairs(hex_values) do
        if value == 'F' then
            break
        end
        table.insert(result, value)
    end
    return result
end

local function process_block(block)
    local binary_str = hex_to_bin(block)
    binary_str = remove_last_two_bits(binary_str)
    local chunks = split_into_5bit_chunks(binary_str)
    local no_parity_chunks = remove_parity_bit(chunks)
    return no_parity_chunks
end

local function calculate_id_net(blocks)
    local all_hex_values = {}
    for _, block in ipairs(blocks) do
        local hex_values = convert_to_hex(process_block(block))
        for _, hex in ipairs(hex_values) do
            table.insert(all_hex_values, hex)
        end
    end
    local selected_hex_values = find_until_before_f(all_hex_values)
    if #selected_hex_values == 0 then
        error(ac.red..'  Error: '..ac.reset..'No valid data found in blocks 4 and 5')
    end
    local combined_hex = table.concat(selected_hex_values)
    if not combined_hex:match("^%x+$") then
        error(ac.red..'  Error: '..ac.reset..'Invalid data in blocks 4 and 5')
    end
    local decimal_id = tonumber(combined_hex)
    local stripped_hex_id = string.format("%X", decimal_id)
    local padded_hex_id = string.format("%010X", decimal_id)
    return decimal_id, padded_hex_id
end

local function calculate_id_switch(blocks)
    local all_decimal_values = {}
    for _, block in ipairs(blocks) do
        local decimal_values = convert_to_decimal(process_block(block))
        for _, dec in ipairs(decimal_values) do
            table.insert(all_decimal_values, dec)
        end
    end
    if #all_decimal_values < 15 then
        error(ac.red..' Error:'..ac.reset..' Not enough data after processing blocks 4, 5, 6, and 7')
    end
    local id_positions = {9, 11, 13, 15, 2, 4, 6, 8}
    local id_numbers = {}
    for _, pos in ipairs(id_positions) do
        table.insert(id_numbers, all_decimal_values[pos])
    end
    local decimal_id = tonumber(table.concat(id_numbers))
    local padded_hex_id = string.format("%010X", decimal_id)
    return decimal_id, padded_hex_id
end

local function name_exists_in_log(name)
    local file = io.open(log_file_path, "r")
    if not file then
        return false
    end
    local pattern = "^Name:%s*" .. name .. "%s*$"
    for line in file:lines() do
        if line:match(pattern) then
            file:close()
            return true
        end
    end
    file:close()
    return false
end

local function log_result(blocks, em410_id, name)
    local log_file = io.open(log_file_path, "a")
    if log_file then
        log_file:write("Name: " .. name .. "\n")
        log_file:write("Date: ", os.date("%Y-%m-%d %H:%M:%S"), "\n")
        for i = 4, 7 do
            log_file:write(string.format("Block %d: %s\n", i, blocks[i] or "nil"))
        end
        log_file:write(string.format('EM4102 ID: %s\n', em410_id or "nil"))
        log_file:write('--------------------------\n')
        log_file:close()
        print('  Log saved as: pm3/.proxmark3/logs/' ..ac.yellow..' Paxton_log.txt'..ac.reset)
    else
        print("  Failed to open log file for writing.")
    end
end

local function verify_written_data(original_blocks)
    p:console('lf hitag read --ht2 -k BDF5E846')
    local result = read_log_file(logfile)
    local verified_blocks = parse_blocks(result)
    local success = true
    for i = 4, 7 do
        if original_blocks[i] ~= verified_blocks[i] then
            print('  Verification failed.. Block '..ac.green.. i ..ac.reset.. ' inconsistent.')
            success = false
        end
    end

    if success then
        print(ac.green..'  Verification successful. Data was written correctly.' .. ac.reset)
    else
        print(ac.yellow.. '  Adjust the position of the Paxton fob on the coil.' .. ac.reset)
    end
end

local function handle_cloning(decimal_id, padded_hex_id, blocks, was_option_3)
    while true do
        io.write("  Create Paxton choose " .. ac.cyan .. "1" .. ac.reset .. " or EM4102 choose " .. ac.cyan .. "2  " .. ac.reset)
        local choice = io.read()
        if choice == "1" then
            io.write("  Place the" .. ac.cyan .. " Paxton " .. ac.reset .. "Fob on the coil to write.." .. ac.green .. " ENTER " .. ac.reset .. "to continue..")
            io.read()
            print(dash)
            p:console("lf hitag wrbl --ht2 -p 4 -d " .. blocks[4] .. " -k BDF5E846")
            p:console("lf hitag wrbl --ht2 -p 5 -d " .. blocks[5] .. " -k BDF5E846")
            p:console("lf hitag wrbl --ht2 -p 6 -d " .. blocks[6] .. " -k BDF5E846")
            p:console("lf hitag wrbl --ht2 -p 7 -d " .. blocks[7] .. " -k BDF5E846")
            reset_log_file()
            --timer(5)
            verify_written_data(blocks)
        elseif choice == "2" then
            io.write("  Place the" .. ac.cyan .. " T5577 " .. ac.reset .. "tag on the coil and press" .. ac.green .. " ENTER " .. ac.reset .. "to continue..")
            io.read()
            p:console("lf em 410x clone --id " .. padded_hex_id)
            print('  Cloned EM4102 to T5577 with ID ' ..ac.green.. padded_hex_id ..ac.reset)
        else
            print(ac.yellow .. "  Invalid choice." .. ac.reset .. " Please enter " .. ac.cyan .. "1" .. ac.reset .. " or " .. ac.cyan .. "2" .. ac.reset)
            goto ask_again
        end
        while true do
            print(dash)
            io.write("  Make next RFID Fob"..ac.cyan.." (y/n)  "..ac.reset)
            local another = io.read()
            if another:lower() == "n" then
                if was_option_3 then
                    print("  No writing to Paxton_log.txt - Name: " ..ac.green.. nam .. ac.reset.. " exist")
                    return
                end
                print()
                print(ac.green .. "  Saving Paxton_log file..." .. ac.reset)
                while true do
                    io.write("  Enter a name for database (cannot be empty/duplicate): "..ac.yellow)
                    name = io.read()
                    io.write(ac.reset..'')
                    if name == nil or name:match("^%s*$") then
                        print(ac.red .. '  ERROR:'..ac.reset..' Name cannot be empty.')
                    else
                        if name_exists_in_log(name) then
                            print(ac.yellow .. '  Name exists!!! '..ac.reset.. 'Please choose a different name.')
                        else
                            break
                        end
                    end
                end
                log_result(blocks, padded_hex_id, name)
                print(ac.green .. "  Log saved successfully!" .. ac.reset)
                reset_log_file()
                return
            elseif another:lower() == "y" then
                goto ask_again
            else
                print(ac.yellow.."  Invalid response."..ac.reset.." Please enter"..ac.cyan.." y"..ac.reset.." or"..ac.cyan.." n"..ac.reset)
            end
        end
        ::ask_again::
    end
end

local function is_valid_hex(input)
    return #input == 8 and input:match("^[0-9A-Fa-f]+$")
end

local function main(args)
    while true do
        for o, a in getopt.getopt(args, 'h') do
             if o == 'h' then return help() end
        end
        command('clear')
        print(dash)
        print(ac.green .. '  Select option: ' .. ac.reset)
        print(ac.cyan .. '  1' .. ac.reset .. ' - Read Paxton blocks 4-7 to make a copy')
        print(ac.cyan .. '  2' .. ac.reset .. ' - Manually input data for Paxton blocks 4-7')
        print(ac.cyan .. "  3" .. ac.reset .. " - Search in Paxton_log by name and use the data")
        print(dash)
        while true do
            io.write('  Your choice '..ac.cyan..'(1/2/3): ' .. ac.reset)
            input_option = io.read()
            if input_option == "1" or input_option == "2" or input_option == "3" then
                break
            else
                print(ac.yellow .. '  Invalid choice.' .. ac.reset .. ' Please enter ' .. ac.cyan .. '1' .. ac.reset .. ' or ' .. ac.cyan .. '2' .. ac.reset..' or'..ac.cyan..' 3'..ac.reset)
            end
        end
        local was_option_3 = false
        if input_option == "1" then
            local show_place_message = true
            while true do
                if show_place_message then
                    io.write('  Place the' .. ac.cyan .. ' Paxton' .. ac.reset .. ' Fob on the coil to read..' .. ac.green .. 'ENTER' .. ac.reset .. ' to continue..')
                end
                io.read()
                print(dash)
                p:console('lf hitag read --ht2 -k BDF5E846')
                if not logfile then
                    error("  No files in this directory")
                end
                local result = read_log_file(logfile)
                local blocks = parse_blocks(result)
                local empty_block = false
                for i = 4, 7 do
                    if not blocks[i] then
                        empty_block = true
                        break
                    end
                end
                if empty_block then
                    io.write(ac.yellow .. '  Adjust the Fob position on the coil.' .. ac.reset .. ' Press' .. ac.green .. ' ENTER' .. ac.reset .. ' to continue..')
                    show_place_message = false
                else
                    print('                        Readed blocks:')
                    print()
                    for i = 4, 7 do
                        if blocks[i] then
                            print(string.format("                        Block %d: %s%s%s", i, ac.yellow, blocks[i], ac.reset))
                        end
                    end
                    local decimal_id, padded_hex_id
                    if blocks[5] and (blocks[5]:sub(4, 4) == 'F' or blocks[5]:sub(4, 4) == 'f') then
                        print(dash)
                        print('  Identified Paxton ' .. ac.cyan .. 'Net2' .. ac.reset)
                        decimal_id, padded_hex_id = calculate_id_net({blocks[4], blocks[5]})
                    else
                        print(dash)
                        print('  Identified Paxton ' .. ac.cyan .. 'Switch2' .. ac.reset)
                        decimal_id, padded_hex_id = calculate_id_switch({blocks[4], blocks[5], blocks[6], blocks[7]})
                    end
                    print(string.format("  ID for EM4102 is: %s", ac.green .. padded_hex_id .. ac.reset))
                    print(dash)
                    handle_cloning(decimal_id, padded_hex_id, blocks, was_option_3)
                    break
                end
            end
        elseif input_option == "2" then
            local blocks = {}
            for i = 4, 7 do
                while true do
                    io.write(ac.reset..'  Enter data for block ' .. i .. ': ' .. ac.yellow)
                    local input = io.read()
                    input = input:upper()
                    if is_valid_hex(input) then
                        blocks[i] = input
                        break
                    else
                        print(ac.yellow .. '  Invalid input.' .. ac.reset .. ' Each block must be 4 bytes (8 hex characters).')
                    end
                end
            end
            local decimal_id, padded_hex_id
            if blocks[5] and (blocks[5]:sub(4, 4) == 'F' or blocks[5]:sub(4, 4) == 'f') then
                print(ac.reset.. dash)
                print('  Identified Paxton ' .. ac.cyan .. 'Net2' .. ac.reset)
                decimal_id, padded_hex_id = calculate_id_net({blocks[4], blocks[5]})
            else
                print(ac.reset.. dash)
                print('  Identified Paxton ' .. ac.cyan .. 'Switch2' .. ac.reset)
                decimal_id, padded_hex_id = calculate_id_switch({blocks[4], blocks[5], blocks[6], blocks[7]})
            end
            print(dash)
            print(string.format("  ID for EM4102 is: %s", ac.green .. padded_hex_id .. ac.reset))
            print(dash)
            if not padded_hex_id then
                print(ac.red..'  ERROR: '..ac.reset.. 'Invalid block data provided')
                return
            end
            handle_cloning(decimal_id, padded_hex_id, blocks, was_option_3)
            break
        elseif input_option == "3" then
            was_option_3 = true
            local retries = 3
            while retries > 0 do
                io.write('  Enter the name to search ('..retries..' attempts) : '..ac.yellow)
                local user_input = io.read()
                io.write(ac.reset..'')
                if user_input == nil or user_input:match("^%s*$") then
                    print(ac.yellow..'  Error: '..ac.reset.. 'Empty name !!!')
                end
                local name_clean = "^Name:%s*" .. user_input:gsub("%s", "%%s") .. "%s*$"
                local file = io.open(log_file_path, "r")
                if not file then
                    print(ac.red .. '  Error:'..ac.reset.. 'Could not open log file.')
                    return
                end
                local lines = {}
                for line in file:lines() do
                    table.insert(lines, line)
                end
                file:close()
                local found = false
                for i = 1, #lines do
                    if lines[i]:match(name_clean) then
                        nam = user_input
                        local blocks = {
                            [4] = lines[i + 2]:match("Block 4: (.+)"),
                            [5] = lines[i + 3]:match("Block 5: (.+)"),
                            [6] = lines[i + 4]:match("Block 6: (.+)"),
                            [7] = lines[i + 5]:match("Block 7: (.+)")
                        }
                        local em4102_id = lines[i + 6]:match("EM4102 ID: (.+)")
                        print(dash)
                        print('            I found the data under the name: '..ac.yellow ..nam.. ac.reset)
                        for j = 4, 7 do
                            print(string.format("                   Block %d: %s%s%s", j, ac.yellow, blocks[j] or "N/A", ac.reset))
                        end
                        print("                 EM4102 ID: " .. ac.green .. (em4102_id or "N/A") .. ac.reset)
                        print(dash)
                        local decimal_id, padded_hex_id = em4102_id, em4102_id
                        handle_cloning(decimal_id, padded_hex_id, blocks, was_option_3, nam)
                        found = true
                        break
                    end
                end
                if not found then
                    retries = retries - 1
                else
                    break
                end
            end
            if retries == 0 then
                print(ac.yellow .. "  Name not found after 3 attempts." .. ac.reset)
            end
        end
        print(dash)
        print('  Exiting script Lua...')
        return
    end
end

main(args)
