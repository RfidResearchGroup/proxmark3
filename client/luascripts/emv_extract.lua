copyright = "Trigat"
author = "Trigat"
desc = "This script scans an EMV (credit or debit) card and extracts Track 2 information."

local home = os.getenv("HOME")
local json_file = home .. "/emv_output.json"

core.console(string.format("emv scan -at %s", json_file))

os.execute("sleep 1")

-- Read JSON content
local f = io.open(json_file, "r")
if not f then
    print("[!!] Could not open JSON output")
    return
end

local content = f:read("*a")
f:close()

local track2 = nil
local found = false

-- Iterate over all "value" fields in JSON
for value_field in content:gmatch('"value"%s*:%s*"(.-)"') do
    -- Look for 57 13 anywhere in the string
    track2 = value_field:match('57%s*13%s*([0-9A-Fa-f%s]+)')
    if track2 then
        -- Remove spaces to get clean hex
        track2 = track2:gsub("%s+", "")
        print("[++] Track 2 data found: 57 13 " .. track2 .. "\n")
        found = true
        break -- remove break if you want all occurrences
    end
end

if not found then
    print("[!!] Track 2 data not found in JSON")
    return
end

-- Remove 57 + Length prefix (first 4 hex digits = 57 13)
track2 = track2:gsub("^57%x%x", "")

-- Convert hex string into individual nibbles (1 hex digit each)
local nibbles = {}
for hex_digit in track2:gmatch("%x") do
    table.insert(nibbles, hex_digit)
end

-- Find 'D' separator
local sep_index
for i, nib in ipairs(nibbles) do
    if nib == "D" then
        sep_index = i
        break
    end
end

if not sep_index then
    print("[!!] Could not find 'D' separator in Track 2")
    return
end

-- Extract Primary Account Number (all nibbles before D)
local pan = table.concat(nibbles, "", 1, sep_index-1)

-- Expiry is next 4 nibbles after D
local yy = nibbles[sep_index + 1] .. nibbles[sep_index + 2]
local mm = nibbles[sep_index + 3] .. nibbles[sep_index + 4]

-- Service code: next 3 nibbles
local service = table.concat(nibbles, "", sep_index + 5, sep_index + 7) or "N/A"

print("[++] PAN: " .. pan)
print("[++] Expiry (MM/YY): " .. mm .. "/" .. yy)
print("[++] Service code: " .. service)

os.execute('rm -f ' .. json_file)
