local getopt = require('getopt')

-- Example starting values
local facilityCode = 255  -- Example facility code
local cardNumber = 59615  -- Example starting card number
local sessionStart = os.date("%Y_%m_%d_%H_%M_%S")  -- Capture the session start time

local function showHelp()
    print("Usage: script run <scriptname> [-h]")
    print("Options:")
    print("-h \t This help")
end

local function main(args)
    for o, a in getopt.getopt(args, 'h') do
        if o == 'h' then return showHelp() end
    end
    
    print("Session Start: " .. sessionStart)
    print("Facility Code,Card Number")
    
    while true do
        print(string.format("Preparing to Write: Facility Code %d, Card Number %d", facilityCode, cardNumber))
        
        local command = string.format("lf awid clone --fmt 26 --fc %d --cn %d", facilityCode, cardNumber)
        core.console(command)
        
        print(string.format("%d,%d", facilityCode, cardNumber))
        
        print("Press Enter to continue with the next card number or type 'q' and press Enter to quit.")
        local user_input = io.read()
        
        if user_input:lower() == 'q' then
            break
        else
            cardNumber = cardNumber + 1
        end
    end
end

main(args)