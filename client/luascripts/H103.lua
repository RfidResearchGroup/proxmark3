local getopt = require('getopt')
local cmds = require('commands')

local successfulWrites = {}
local facilityCode = 10 -- default value
local cardNumber = 1000 -- default value
local timestamp = os.date('%Y-%m-%d %H:%M:%S', os.time())

local function showHelp()
    print("Usage: script run <scriptname> [-h]")
    print("Options:")
    print("-h \t Display this help message")
end

local function main(args)
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return showHelp() end
    end
    
    print("Enter starting Facility Code:")
    facilityCode = tonumber(io.read()) or facilityCode
    
    print("Enter starting Card Number:")
    cardNumber = tonumber(io.read()) or cardNumber
    
    while true do
        print(string.format("Writing Facility Code: %d, Card Number: %d", facilityCode, cardNumber))

        local command = string.format("lf hid clone -w H10301 --fc %d --cn %d", facilityCode, cardNumber)
        core.console(command)

        table.insert(successfulWrites, string.format("%d,%d", facilityCode, cardNumber))

        print("Press Enter to write the next card, type 'r' and press Enter to retry, or type 'q' and press Enter to quit.")
        local user_input = io.read()
        
        if user_input:lower() == 'q' then
            print("Timestamp: ", timestamp)
            print("Successful Writes:")
            for _, v in ipairs(successfulWrites) do print(v) end
            break
        elseif user_input:lower() ~= 'r' then
            cardNumber = cardNumber + 1
        end
    end
end

main(args)

--[[
Notes:
1. The `lf hid clone` command is used to write HID formatted data to T5577 cards, using the H10301 format.
2. The script prompts the user for the initial facility code and card number at the start of the session.
3. Users can continue to write to the next card, retry the current write, or quit the session by responding to the prompts.
4. Upon quitting, the script prints all successful writes along with a timestamp.
5. Password-related features have been removed in this version of the script as they are not supported by the `lf hid clone` command.
]]
