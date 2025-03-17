local os = require("os")
local ac = require('ansicolors')
local getopt = require('getopt')
local dir = os.getenv('HOME') .. '/proxmark3/client/dictionaries/'
local dictionary_path = dir .. 'T5577date.dic'
local cyan = ac.cyan
local res = ac.reset
local red = ac.red
local green = ac.green

author = '    Author: jareckib - created 04.02.2025'
version = '    version v1.05'
desc = [[
    A simple script for searching the password for T5577. The script creates a
    dictionary starting from the entered starting year to the entered ending year.
    There are two search methods - DDMMYYYY or YYYYMMDD. Checking the entire year
    takes about 1 minute and 50 seconds. Date from 1900 to 2100. The script may be
    useful if the password is for example a date of birth.
]]

usage = [[
    script run lf_t55xx_chk [-s start_year] [-e end_year] [-d | -y]
]]
options = [[
    -h                    this help
    -s start_year         starting year (required)
    -e end_year           ending year (optional, default: current year)
    -d                    search method: DDMMYYYY
    -y                    search method: YYYYMMDD
]]
examples = [[
    script run lf_t55xx_chk -s 1999 -d             -> start 1999, end is current year, method 01011999
    script run lf_t55xx_chk -s 1999 -y             -> start 1999, end is current year, method 19990101
    script run lf_t55xx_chk -s 1999 -e 2001 -y     -> start 1999, end year 2001, method 19990101
    script run lf_t55xx_chk -s 1999 -e 2001 -d     -> start 1999, end year 2001, method 01011999
]]

local function help()
    print()
    print(ac.yellow..author)
    print(version)
    print(res..desc)
    print(green..'    Usage:'..res)
    print(usage)
    print(green..'    Options:'..res)
    print(options)
    print(green..'    Examples:'..res)
    print(examples)
end

local function oops(err)
    core.console('clear')
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    print(ac.red..'                ERROR:'..res.. err)
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    return nil, err
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
        print(ac.yellow .. '  ERROR: ' .. res .. 'Cannot create T5577date.dic')
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
                local entry = (mode == "y") and (year_str .. month_str .. day_str) or (day_str .. month_str .. year_str)
                file:write(entry .. "\n")
            end
        end
    end

    file:close()
    return true
end

local function main(args)
    if #args == 0 then return help() end

    local start_year, end_year, mode = nil, nil, nil
    local current_year = tonumber(os.date("%Y"))

    for o, a in getopt.getopt(args, 'hs:e:dy') do
        if o == 'h' then return help() end
        if o == 's' then
            start_year = tonumber(a)
            if not start_year then return oops(' Invalid start year') end
        end
        if o == 'e' then
            end_year = tonumber(a)
            if not end_year then return oops(' Invalid end year') end
        end
        if o == 'd' then mode = "d" end
        if o == 'y' then mode = "y" end
    end

    if not start_year then return oops(' Starting year is required') end
    if start_year < 1900 or start_year > 2100 then
        return oops(' Start year must be between 1900 and 2100')
    end
    if args[#args] == "-e" then return oops(' Ending year cannot be empty') end
    if not end_year then end_year = current_year end
    if end_year < 1900 or end_year > 2100 then
        return oops(' End year must be between 1900 and 2100')
    end

    if end_year < start_year then return oops(' End year cannot be earlier than start year') end
    if not mode then return oops(' You must select searching method'..cyan..' d'..res.. ' or '..cyan.. 'y'..res) end

    if generate_dictionary(start_year, end_year, mode) then
        print(ac.green .. "  File created: " .. dictionary_path .. res)
        print(cyan .. "  Starting password testing on T5577..." .. res)
        core.console('lf t55 chk -f ' .. dictionary_path)
    else
        return oops('Problem saving the file')
    end
end
 main(args)
