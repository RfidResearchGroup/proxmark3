local os = require("os")
local ac = require('ansicolors')
local utils = require('utils')
local getopt = require('getopt')
local dash = string.rep('--', 32)

author = '    Author: jareckib - created 01.02.2025'
version = '    version v1.01'
desc = [[
    A simple script for searching the password for T5577. The script creates a
    dictionary starting from the entered starting year to the entered ending year.
    There are two search methods - DDMMYYYY or YYYYMMDD. Checking the entire year
    takes about 1 minute and 50 seconds. Date from 1900 to 2100. The script may be
    useful if the password is, for example, a date of birth.
]]
usage = [[
  script run lf_t55xx_chk_date
]]
arguments = [[
  script run lf_t55xx_chk_date -h    : this help
]]

local DEBUG = true

local function dbg(args)
    if not DEBUG then return end
    if type(args) == 'table' then
        for _, v in ipairs(args) do
            dbg(v)
        end
    else
        print('###', args)
    end
end

local function help()
    print()
    print(ac.green..author)
    print(version)
    print(ac.yellow..desc)
    print(ac.cyan..'  Usage'..ac.reset)
    print(usage)
    print(ac.cyan..'  Arguments'..ac.reset)
    print(arguments)
end

local dir = os.getenv('HOME') .. '/proxmark3/client/dictionaries/'
local dictionary_path = dir .. 'T5577date.dic'

local days_in_month = {
    [1] = 31, [2] = 28, [3] = 31, [4] = 30, [5] = 31, [6] = 30,
    [7] = 31, [8] = 31, [9] = 30, [10] = 31, [11] = 30, [12] = 31
}

local function generate_dictionary(start_year, end_year, mode)
    local file = io.open(dictionary_path, "w")
    if not file then
        print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Cannot create T5577date.dic')
        return false
    end

    for year = start_year, end_year do
        for month = 1, 12 do
            local days_in_current_month = days_in_month[month]
            if month == 2 and ((year % 4 == 0 and year % 100 ~= 0) or (year % 400 == 0)) then
                days_in_current_month = 29
            end

            for day = 1, days_in_current_month do
                local month_str = string.format("%02d", month)
                local day_str = string.format("%02d", day)
                local year_str = tostring(year)
                local entry = (mode == "1") and (year_str .. month_str .. day_str) or (day_str .. month_str .. year_str)
                file:write(entry .. "\n")
            end
        end
    end

    file:close()
    return true
end

local function get_valid_year_input(prompt)
    local year
    while true do
        io.write(prompt)
        local input = io.read()
        if input == "" then
            print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Year cannot be empty')
        else
            year = tonumber(input)
            if not year then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Invalid input (digits only)')
            elseif year < 1900 then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Year cannot be less than 1900')
            elseif year > 2100 then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Year cannot be greater than 2100')
            else
                break
            end
        end
    end
    return year
end

local function get_valid_ending_year_input(start_year)
    local end_year
    while true do
        io.write("  Enter the ending year: " .. ac.yellow)
        local input = io.read()
        io.write(ac.reset..'')
        if input == "" then
            print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Ending year cannot be empty')
        else
            end_year = tonumber(input)
            if not end_year then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Invalid input (digits only)')
            elseif end_year < 1900 or end_year > 2100 then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Year must be between 1900 and 2100')
            elseif end_year < start_year then
                print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Ending year cannot be less than the starting year')
            else
                break
            end
        end
    end
    return end_year
end

local function get_valid_mode_input()
    local mode
    while true do
        io.write('  Choose the searching mode ('..ac.cyan..'1'..ac.reset..' - YYYYMMDD '..ac.cyan..'2'..ac.reset..' - DDMMYYYY): ')
        mode = io.read()
        if mode == "1" or mode == "2" then
            return mode
        else
            print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Invalid choice. Please enter 1 or 2.')
        end
    end
end

local function main(args)
    for o, a in getopt.getopt(args, 'h') do
         if o == 'h' then return help() end
    end
    core.console('clear')
    print(dash)
    print(dash)
    local start_year = get_valid_year_input("  Enter the starting year: " .. ac.yellow)
    io.write(ac.reset..'')
    local end_year = get_valid_ending_year_input(start_year)
    local mode = get_valid_mode_input()

    if generate_dictionary(start_year, end_year, mode) then
        print(ac.green .. "  File created: " .. dictionary_path .. ac.reset)
        print(ac.cyan .. "  Starting password testing on T5577..." .. ac.reset)
        core.console('lf t55 chk -f ' .. dictionary_path)
    else
        print(ac.yellow .. '  ERROR: ' .. ac.reset .. 'Problem saving the file.')
    end
end

main(args)
