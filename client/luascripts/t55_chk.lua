local os = require("os")
local ac = require('ansicolors')
local getopt = require('getopt')
local dir = os.getenv('HOME') .. '/proxmark3/client/dictionaries/'
local dictionary_path = dir .. 'T5577date.dic'
local cyan = ac.cyan
local res = ac.reset

author = '    Author: jareckib - created 02.02.2025'
version = '    version v1.00'
desc = [[  
    A simple script for searching the password for T5577. The script creates a
    dictionary starting from the entered starting year to the entered ending year.
    There are two search methods - DDMMYYYY or YYYYMMDD. Checking the entire year
    takes about 1 minute and 50 seconds. Date from 1900 to 2100. The script may be
    useful if the password is, for example, a date of birth.
]]

usage = [[
    script run t55_chk [-s start_year] [-e end_year] [-d | -y]
]]
options = [[
    -h                    Show this help message
    -s                    Starting year (required)
    -e                    Ending year (default: current year)
    -d                    Search method: DDMMYYYY
    -y                    Search method: YYYYMMDD
]]
examples = [[
    script run t55_chk -s 1999 -d             - start from 1999, end year is current year, method 01011999
    script run t55_chk -s 1999 -y             - start from 1999, end year is current year, method 19990101
    script run t55_chk -s 1999 -e 2001 -y     - start from 1999, end year 2001, method 19990101
    script run t55_chk -s 1999 -e 2001 -d     - start from 1999, end year 2001, method 01011999
]]

local function help()
    print(ac.green..author..res)
    print(version)
    print(desc)
    print(cyan..'    Usage:'..res)
    print(usage)
    print(cyan..'    Options:'..res)
    print(options)
    print(cyan..'    Examples:'..res)
    print(examples)
end

local function generate_dictionary(start_year, end_year, mode)
    local file = io.open(dictionary_path, "w")
    if not file then
        print(ac.yellow .. '  ERROR: ' .. res .. 'Cannot create T5577date.dic')
        return false
    end

    for year = start_year, end_year do
        for month = 1, 12 do
            for day = 1, 31 do
                local entry = (mode == "y") and 
                    (string.format("%04d%02d%02d", year, month, day)) or 
                    (string.format("%02d%02d%04d", day, month, year))
                file:write(entry .. "\n")
            end
        end
    end

    file:close()
    return true
end

local function oops(err)
    core.console('clear')
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    print(ac.red..'               ERROR:'..res.. err)
    print( string.rep('--',39) )
    print( string.rep('--',39) )
    return nil, err
end

local function main(args)
    if #args == 0 then return help() end

    local start_year, end_year, mode = nil, nil, nil
    local current_year = tonumber(os.date("%Y"))

    for o, a in getopt.getopt(args, 'hs:e:dy') do
        if o == 'h' then return help() end
        if o == 's' then 
            start_year = tonumber(a)
            if not start_year then return oops('Invalid start year') end
        end
        if o == 'e' then 
            end_year = tonumber(a)
            if not end_year then return oops('Invalid end year (-e)') end
        end
        if o == 'd' then mode = "d" end
        if o == 'y' then mode = "y" end
    end

    if not start_year then return oops('Starting year is required') end
    if start_year < 1900 or start_year > 2100 then 
        return oops('Start year must be between 1900 and 2100') 
    end
    if args[#args] == "-e" then return oops('Ending year cannot be empty') end
    if not end_year then end_year = current_year end
    if end_year < 1900 or end_year > 2100 then 
        return oops('End year must be between 1900 and 2100') 
    end

    if end_year < start_year then return oops('End year cannot be earlier than start year') end
    if not mode then return oops('You must select searching method'..cyan..' -d'..res.. ' or '..cyan.. '-y'..res) end

    if generate_dictionary(start_year, end_year, mode) then
        print(ac.green .. "  File created: " .. dictionary_path .. res)
        print(cyan .. "  Starting password testing on T5577..." .. res)
        core.console('lf t55 chk -f ' .. dictionary_path) 
    else
        return oops('Problem saving the file')
    end
end

main(args)