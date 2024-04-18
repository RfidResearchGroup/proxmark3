local getopt = require('getopt')
local cmds = require('commands')

local successfulWrites = {}
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
    local facilityCode = tonumber(io.read())

    print("Enter starting Card Number:")
    local cardNumber = tonumber(io.read())

    while true do
        print(string.format("Setting fob to Facility Code: %d, Card Number: %d", facilityCode, cardNumber))

        -- Writing to block 0 with the specific data for ioProx card format
        core.console("lf t55xx write -b 0 -d 00147040")

        -- Command to set facility code and card number on the fob
        local command = string.format("lf io clone --vn 2 --fc %d --cn %d", facilityCode, cardNumber)
        core.console(command)

        table.insert(successfulWrites, string.format("%d,%d", facilityCode, cardNumber))
        print("Fob created successfully.")

        print("Press Enter to create the next fob, type 'r' and press Enter to retry, or type 'q' and press Enter to quit.")
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
