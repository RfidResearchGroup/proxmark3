--[[
    Simple Trace Parser library

    -- fair warning, this is best to just get trace data values, I didn't see any better implementation for this, so I just made one myself

    -- Example Usage
    -- Load the traceParser library
    local traceParser = require("trace_parse")

    -- Parse the trace file
    local trace_data = traceParser.parse_trace_file(filename)

    -- Print the parsed data
    for _, record in ipairs(trace_data) do
        -- Format the data bytes
        local data_bytes = {}
        for i = 1, #record.data do
            table.insert(data_bytes, string.format("%02X", record.data:byte(i)))
        end
        local data_str = table.concat(data_bytes, "")
        print("Data: " .. data_str)
    end

 ]]

local bit = require("bit")  -- Requires Lua bitwise library (bit)
local traceParser = {}

-- Function to read a 4-byte unsigned integer (little-endian)
local function read_u32_le(data, pos)
    if pos + 3 > #data then return nil, pos end
    local b1, b2, b3, b4 = data:byte(pos, pos + 3)
    return (b4 * 2^24) + (b3 * 2^16) + (b2 * 2^8) + b1, pos + 4
end

-- Function to read a 2-byte unsigned integer (little-endian)
local function read_u16_le(data, pos)
    if pos + 1 > #data then return nil, pos end
    local b1, b2 = data:byte(pos, pos + 1)
    return (b2 * 2^8) + b1, pos + 2
end

-- Function to parse a single record from the trace file
local function parse_record(trace, pos)
    local record = {}

    -- Read the 32-bit timestamp (4 bytes, little-endian)
    record.timestamp_start, pos = read_u32_le(trace, pos)

    -- Read the 16-bit duration (2 bytes, little-endian)
    record.duration, pos = read_u16_le(trace, pos)

    -- Read the 15-bit data length and 1-bit isResponse flag
    local data_len_and_flag, pos = read_u16_le(trace, pos)
    record.data_len = bit.band(data_len_and_flag, 0x7FFF)  -- 15 bits for data length
    record.is_response = bit.rshift(data_len_and_flag, 15) == 1  -- 1 bit for isResponse

    -- Read the data bytes
    record.data, pos = trace:sub(pos, pos + record.data_len - 1), pos + record.data_len

    -- Read the parity bytes (parity length is ceil(data_len / 8))
    local parity_len = math.ceil(record.data_len / 8)
    record.parity, pos = trace:sub(pos, pos + parity_len - 1), pos + parity_len

    return record, pos
end

-- Function to parse the entire trace file
function traceParser.parse_trace_file(file_path)
    local trace_data = {}
    local trace_file = io.open(file_path, "rb")

    if not trace_file then
        error("Could not open file: " .. file_path)
    end

    -- Read the entire content of the file
    local content = trace_file:read("*all")
    trace_file:close()

    -- Parse records in the file
    local pos = 1
    while pos <= #content do
        local record
        record, pos = parse_record(content, pos)
        if record then
            table.insert(trace_data, record)
        else
            break  -- Stop if the record is invalid or incomplete
        end
    end

    return trace_data
end


return traceParser

