local cmds = require('commands')
local getopt = require('getopt')
local lib14a = require('read14a')
local utils =  require('utils')
local ansicolors  = require('ansicolors')
local bxor = bit32.bxor



copyright = '\nLicensed under GNU GPL v3.0. Team orangeBlue.'
author = 'Team '..ansicolors.yellow..'orange'..ansicolors.cyan..'Blue'..ansicolors.reset -- Disinformation
version = 'v1.0'
date = 'Created - Aug 2023'
desc = [[
Script to set UID on USCUID using any means possible. No warranties given!
See below for capabilities.

This script is compatible with the ICs listed below:
* GDMIC
* UCUID
* M1-7B
* Other chips, showing up as "Gen 4 GDM"
This script does not claim full compatibility with the ICs listed below:
* UFUID
* PFUID*

WHY? Unfortunately, these are cut down versions. Checks show that they only acknowledge bytes 0-1, 7, 8, and 15 of the configuration.

* WARNING: The config commands are inversed. Nothing will work.

Ready to start? Set the first 2 bytes of your config to 7AFF and use -t 4.
]]
example = [[
    -- Set UID 7 bytes long via 20-23 wakeup
    1. script run hf_mf_uscuid_prog -t 2 -u 04A72B85489F51
    -- Set UID 4 bytes long via 40-43 wakeup
    2. script run hf_mf_uscuid_prog -t 4 -u A72B571

]]
usage = [[
script run hf_mf_uscuid_uid_prog [-h] [-u <uid>] [-t] [-3] [-s <signature>] [-w 1] [-R/-B <blk>] [-S/-E <sec>] [-g/-c/-b/-2/-7/-d/-a/-n/-r <0/1>]
]]
arguments = [[
    -h      this help
    -t      Magic wakeup type (2 for 0x20, 4 for 0x40)
    -u      New tag UID
    -s      New signature data
    -3      Update UID for F3 Perso
    -w 1    Wipe tag (take caution!)
    -R      Read block
    -B      Read backdoor block
    -S      Read sector
    -E      Read backdoor sector
    [ConfigStar]
    To enable an option, pass "1". To disable, pass "0". Unmarked data will not be edited.
    -g      Gen1 mode
    -c      Gen1 command (1 for 20-23; 0 for 40-43)
    -b      Block key B if readable by ACL
    -2      Gen2/CUID mode
    -7      CL2 mode (1 for F0 unfused; 0 for off)
    -d      Shadow mode
    -a      Magic auth
    -n      Static encrypted nonces
    -r      Signature sector
]]
changelog = [[
Welcome, proxmark user!
Here's a secret changelog of this script as its' life started.

v0.1 - Initial developer release. Super unstable, coding the basic UID programming functions, mainly 7 byte because it was just easier.
v0.6 - Basic UID editor release. Flexible programming of UIDs (4<->7 byte conversions and programming)
v0.7 - Signature support! If USCUID supports it, so should we.
v0.8a - Incomplete release. Try the newly added functions at your own risk!
v0.8 - Now with wiping the tag! Why not. Helps.
v0.9 - Manual configurator. Very well.
v1.0 - Memory access. Just like in the proxmark client.
]]
-- [[ Start introducing functions that get called later on ]] --
-- give up
local function oops(err)
    print(ansicolors.red.."[!]"..ansicolors.reset..' ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end
local function help()
    print(copyright)
    print(author)
    print(version)
    print(desc)
    print(ansicolors.cyan..'Usage'..ansicolors.reset)
    print(usage)
    print(ansicolors.cyan..'Arguments'..ansicolors.reset)
    print(arguments)
    print(ansicolors.cyan..'Example usage'..ansicolors.reset)
    print(example)
end
-- Sorry, didn't care to figure out custom bit amounts with the 14a lua lib. So here's this thing
local function wupc2()
	return {
	[0] = 'hf 14a raw -akb 7 20',
	[1] = 'hf 14a raw -k 23',
	}
end

local function wupc()
	return{
	[0] = 'hf 14a raw -akb 7 40',
	[1] = 'hf 14a raw -k 43',
	}
end

local function makenuid(uid)
	core.console('ana nuid -d '..uid)
end
local function sendCmds(cmds)
    for i = 0, #cmds do
        if cmds[i]  then
            core.console(cmds[i])
            core.clearCommandBuffer()
        end
    end
end
local function wakeupmagic(writetype)
	if writetype=="2" then sendCmds(wupc2()) elseif writetype=="4" then sendCmds(wupc()) end
end
local function calculate_block0(useruid)
    local uidbytes = utils.ConvertHexToBytes(useruid)
    local i = 1
    local bcc = bxor(uidbytes[i], uidbytes[i+1]);
    local length = #useruid / 2;

    -- bcc
    for i = 3, length, 1 do bcc = bxor(bcc, uidbytes[i]) end

    -- block0
    local block0 = ""
    for i = 1, length, 1 do block0 = block0..string.format('%02X', uidbytes[i]) end

    return block0..string.format('%02X', bcc)
end
local function cltwo_block0(uid)
	payload = uid
	payload = payload .. "884400000000000000"
	return payload
end
local function SectorHeader(sector)
	print("["..ansicolors.yellow.."="..ansicolors.reset.."]    #  | sector "..ansicolors.green..string.format("%02d", sector)..ansicolors.reset.." / "..ansicolors.green..string.format("0x%02X", sector)..ansicolors.reset)
    	print("["..ansicolors.yellow.."="..ansicolors.reset.."]   ----+------------------------------------------------")
end
local function BlockParser(data, block)
    	if block == "0" or block == 0 then -- for block 0
    		print("["..ansicolors.yellow.."="..ansicolors.reset.."]    "..string.format("%02d", block).." | "..ansicolors.red..string.sub(data,1,2).." "..string.sub(data,3,4).." "..string.sub(data,5,6).." "..string.sub(data,7,8).." "..string.sub(data,9,10).." "..string.sub(data,11,12).." "..string.sub(data,13,14).." "..string.sub(data,15,16).." "..string.sub(data,17,18).." "..string.sub(data,19,20).." "..string.sub(data,21,22).." "..string.sub(data,23,24).." "..string.sub(data,25,26).." "..string.sub(data,27,28).." "..string.sub(data,29,30).." "..string.sub(data,31,32)..ansicolors.reset)
    	elseif (block+1)%4 == 0 then -- for ST
    		print("["..ansicolors.yellow.."="..ansicolors.reset.."]    "..string.format("%02d", block).." | "..ansicolors.yellow..string.sub(data,1,2).." "..string.sub(data,3,4).." "..string.sub(data,5,6).." "..string.sub(data,7,8).." "..string.sub(data,9,10).." "..string.sub(data,11,12).." "..ansicolors.magenta..string.sub(data,13,14).." "..string.sub(data,15,16).." "..string.sub(data,17,18).." "..ansicolors.reset..string.sub(data,19,20).." "..ansicolors.yellow..string.sub(data,21,22).." "..string.sub(data,23,24).." "..string.sub(data,25,26).." "..string.sub(data,27,28).." "..string.sub(data,29,30).." "..string.sub(data,31,32)..ansicolors.reset)
    	else
    		print("["..ansicolors.yellow.."="..ansicolors.reset.."]    "..string.format("%02d", block).." | "..string.sub(data,1,2).." "..string.sub(data,3,4).." "..string.sub(data,5,6).." "..string.sub(data,7,8).." "..string.sub(data,9,10).." "..string.sub(data,11,12).." "..string.sub(data,13,14).." "..string.sub(data,15,16).." "..string.sub(data,17,18).." "..string.sub(data,19,20).." "..string.sub(data,21,22).." "..string.sub(data,23,24).." "..string.sub(data,25,26).." "..string.sub(data,27,28).." "..string.sub(data,29,30).." "..string.sub(data,31,32)) end
end
local function sendRaw(rawdata, keep)
    flags = lib14a.ISO14A_COMMAND.ISO14A_RAW + lib14a.ISO14A_COMMAND.ISO14A_APPEND_CRC
    if keep == true then flags = flags + lib14a.ISO14A_COMMAND.ISO14A_NO_DISCONNECT end
    local command = Command:newMIX{cmd = cmds.CMD_HF_ISO14443A_READER,
                                    arg1 = flags, -- Send raw
                                    arg2 = string.len(rawdata) / 2, -- arg2 contains the length, which is half the length of the ASCII-string rawdata
                                    data = rawdata
                                    }
    local ignore_response = false
    local result, err = command:sendMIX(ignore_response)
    if result then
        --local count,cmd,arg1,arg2,arg3,data = bin.unpack('LLLLH512',result)
		local p = command.parse(result)
        arg1 = p["arg1"]
        data = p["data"]
        returned_bytes = string.sub(data, 1, arg1 * 2)
        if #returned_bytes > 0 then return returned_bytes else return nil end
    end
end
-- Functions to work with configuration data (E000, E100 cmds)
local function readconf()
	configbuffer = sendRaw("E000", true)
	if string.len(configbuffer) ~= 36 then
    		oops("Tag sent wrong length of config!")
    		lib14a.disconnect()
    	return 1 end
    	return utils.ConvertHexToBytes(string.sub(configbuffer,1,32))
end
local function writeconf(configbuffer)
	configbuffer=utils.ConvertBytesToHex(configbuffer)
	print(ansicolors.yellow.."[|]".. ansicolors.reset .." The new config is: "..configbuffer)
	if sendRaw("E100", true) == "0A" then
		if sendRaw(configbuffer, true) == "0A" then
			print(ansicolors.yellow.."[/]".. ansicolors.reset .." Config updated successfully")
		else
			oops("Tag did not ACK config update!")
			lib14a.disconnect()
		return 1 end
	else oops("Tag did not ACK `E100` command!")
		lib14a.disconnect()
	return 1 end
end
-- End config functions

-- [[ All have been created ]] --


function main(args)
    if args == nil or #args == 0 then return help() end
    -- Save data to process
    local writetype = "4"
    local uid = nil
    local payload = nil
    local f3perso = false
    local signature = nil
    local wipe = false

    local targetblk = nil
    local targetbblk = nil
    local targetbsec = nil
    local targetsec = nil
    -- ConfigStar data. These are all booleans. If nil, ignored.
    local gen1 = nil
    local gen1com = nil
    local keyblock = nil
    local cuid = nil
    local cl2mode = nil -- Sorry, I'll only parse either 5A or 00. You can turn on the rest yourself using perso
    local shadowmode = nil
    local magicauth = nil
    local statenc = nil
    local sigsec = nil

    local configwrite = nil
    -- End of ConfigStar
    -- Parse arguments
    -- Note: wrong order of arguments makes the script just not work. Like in some cases the script dies and doesnt call anything, in others it wants data for bool arguments. DESIGN???
    for o,a in getopt.getopt(args, 'g:c:b:2:7:d:a:n:r:u:t:s:R:B:S:E:hw3') do
    	if o == "h" then return help() end
        if o == 'u' then uid = a end
        if o == 's' then signature = a end
        if o == 't' then writetype = a end
        if o == '3' then f3perso = true end
        if o == 'R' then targetblk = a end
        if o == 'B' then targetbblk = a end
        if o == 'S' then targetsec = a end
        if o == 'E' then targetbsec = a end
        if o == 'w' then wipe = true end
        -- So one odd thing I noticed is the bool args like -h, -w don't work without a 2nd argument. So you now must do -h 1.. what? Why?
        -- ConfigStar
	if o == 'g' then if a == "1" then gen1 = true elseif a == "0" then gen1 = false end end
	if o == 'c' then if a == "1" then gen1com= true elseif a == "0" then gen1com= false end end
	if o == 'b' then if a == "1" then keyblock= true elseif a == "0" then keyblock= false end end
	if o == '2' then if a == "1" then cuid= true elseif a == "0" then cuid= false end end
	if o == '7' then if a == "1" then cl2mode= true elseif a == "0" then cl2mode= false end end
	if o == 'd' then if a == "1" then shadowmode = true elseif a == "0" then shadowmode = false end end
	if o == 'a' then if a == "1" then magicauth= true elseif a == "0" then magicauth= false end end
	if o == 'n' then if a == "1" then statenc= true elseif a == "0" then statenc= false end end
	if o == 'r' then if a == "1" then sigsec = true elseif a == "0" then sigsec= false end end
    end
    if gen1 ~= nil or gen1com~= nil or keyblock~= nil or cuid~= nil or cl2mode~= nil or shadowmode~= nil or magicauth~= nil or statenc~= nil or sigsec~= nil then configwrite = true end

    if targetbblk then if tonumber(targetbblk)>63 then oops("Block is above 63") return 1 end end
    if targetblk then if tonumber(targetblk)>63 then oops("Block is above 63") return 1 end end
    if targetsec then if tonumber(targetsec)>15 then oops("Sector is above 15") return 1 end end
    if targetbsec then if tonumber(targetbsec)>15 then oops("Sector is above 15") return 1 end end
    --
    -- Alright, here's the logic.
    -- 1. Set the write type (0x20, 0x40, 8000 auth, etc...)
    -- 2. Get UID length
    -- 3. Form data to write
    -- 4. Issue commands
    if wipe == true then
    	print(ansicolors.red.."[/]"..ansicolors.reset.." Wipe issued! Nullifying other arguments!")
    	print(ansicolors.red.."[-]"..ansicolors.reset.." DO NOT REMOVE YOUR TAG!")
    	uid = nil
    	signature = nil
    	configwrite = nil
    	wakeupmagic(writetype)
    	if sendRaw("F000", true) ~= "0A" then
    		oops("DANGER! Tag did not ACK wipe command. The field has NOT been reset.")
    		print("[ ] If you think the wipe succeeded, immediately do this:")
    		print("hf 14a raw -kc E100; hf 14a raw -c 7AFF0000000000000000000000000008")
    	return 1 end
    	writeconf(utils.ConvertHexToBytes("7AFF0000000000000000005A00000008"))
    	sendRaw("F800", true) -- here you only wipe the backdoor blocks and they're not super critical so might as well not check.
    	sendRaw("A000", true) -- By this point I just rely on the tag.
    	sendRaw("DE7715B8040804000000000000000000", true)
    	for i =0,15 do
    		blk=string.format("%02x", 4*i+3):gsub("0x","")
    		sendRaw("A0"..blk, true)
    		sendRaw("FFFFFFFFFFFFFF078069FFFFFFFFFFFF",true)
    		sendRaw("A8"..blk,true)
    		sendRaw("FFFFFFFFFFFFFF078069FFFFFFFFFFFF",true)
    	end
    	sendRaw("A807", true)
    	sendRaw("75CCB59C9BED70F0F8694B791BEA7BCC",true)
    	print(ansicolors.yellow.."[-]"..ansicolors.reset.." Wipe completed successfully")
    	lib14a.disconnect()
    end
    -- Separator
    if targetblk or targetbblk or targetsec or targetbsec then
    	uid = nil
    	signature = nil
    	configwrite = nil
    	wakeupmagic(writetype)
    	print("")
    	if targetblk or targetsec then
    		if targetblk then data = sendRaw("30"..string.format("%02x", targetblk), false) end
    		if targetblk then SectorHeader(targetblk/4) else SectorHeader(targetsec) end
    		if targetblk then BlockParser(data, targetblk) else for i=0,3 do BlockParser(sendRaw("30"..string.format("%02x", targetsec*4+i), true), targetsec*4+i) end end
    	elseif targetbblk or targetbsec then
    		if targetbblk then data=sendRaw("38"..string.format("%02x", targetbblk), false) end
    		if targetbblk then SectorHeader(targetbblk/4) else SectorHeader(targetbsec) end
    		if targetbblk then BlockParser(data, targetbblk) else for i=0,3 do BlockParser(sendRaw("38"..string.format("%02x", targetbsec*4+i), true), targetbsec*4+i) end end
    		-- Actually is there an sprintf_hex in lua?
    	end
	lib14a.disconnect()
    end
    -- Separator
    if uid then
    	if writetype == "2" or writetype == "4" then
    		if string.len(uid) == 8 then
    			payload = calculate_block0(uid)
    			-- Calculate BCC
    			-- Append SAK
    			payload = payload .. "08"
    			-- Empty manuf bytes
    			payload = payload .. "04000000000000000000"
    		elseif string.len(uid) == 14 then
    			-- Same logic, but with raw anticollision data because that's what the tag accepts. :P
    			payload = calculate_block0("88"..string.sub(uid,1,6))
    			payload = payload .. "04"
    			payload = payload .. calculate_block0(string.sub(uid,7,14))
    			payload = payload .. "08"
    			payload = payload .. "00000000"
    		end
    	end
    	core.clearCommandBuffer()
    	-- Now, let's write! 1. We wake up the tag in magic mode.
    	-- 2. We will deal with the "easier" 7 byte UID stuff
    	if uid then
    	if string.len(uid) == 14 then
    		wakeupmagic(writetype)
    		if f3perso == true then print("[?] WARNING: F3 perso write is set, but 7 byte UID is passed. Ignoring -3 argument") end
    		local configdata = readconf()
    		if configdata[10] ~= 0x5A and configdata[10] ~= 0xC3 and configdata[10] ~= 0xA5 then -- Enable CL2 mode if necessary
    			print("[?] WARNING: Tag is not in 7 byte UID mode. Automatically updating to F0 unfused")
    			print(ansicolors.yellow.."[-]".. ansicolors.reset .." This is because the configuration byte responsible for CL2 was not found to be equal to 0x5A, 0xC3 or 0xA5, but rather: ".. string.format("%02x", configdata[10]))
    			print(ansicolors.yellow.."[\\]".. ansicolors.reset .." The old config is: ".. utils.ConvertBytesToHex(configdata))
    			configdata[10]=0x5A
    			writeconf(configdata)
    		end
    		if sendRaw("A800", true) ~= "0A" then
    			oops("Tag did not ACK `A800` command!")
     			lib14a.disconnect()
     		return 1 end
     		print("[?] WARNING: nUID should be updated with this value:")
		print(makenuid(uid))
		print(ansicolors.yellow.."[/]".. ansicolors.reset .." Use `--f3d` to update nUID for Perso F3 only.")
		if sendRaw(payload, true) ~= "0A" then
			oops("Tag did not ACK data to write!")
			lib14a.disconnect()
		return 1 end
		print(ansicolors.yellow.."[-]".. ansicolors.reset .." Updating real block 0")
		if sendRaw("A000", true) ~= "0A" then
			oops("Tag did not ACK `A000` command!")
			lib14a.disconnect()
		return 1 end
		if sendRaw(cltwo_block0(uid), false) ~="0A" then oops("Tag did not ACK data to write!") end
	-- Now, let's work with 4 byte UIDs.
	elseif string.len(uid)==8 then
		wakeupmagic(writetype)
		local configdata = readconf()
		if configdata[10] == 0x69 or f3perso == true then -- If we have Perso: F3, then write backdoor blk 1
			if f3perso == true then print ("[?] WARNING: F3 flag enabled. Updating UID used for F3 perso") end
			if sendRaw("A801", true) ~= "0A" then
    				oops("Tag did not ACK `A801` command!")
     				lib14a.disconnect()
     			return 1 end
     		else -- Otherwise write real block 0.
     			if configdata[10] == 0x5a or configdata[10] == 0xc3 or configdata[10] == 0xa5 then -- Disable CL2 if necessary
     				print("[?] WARNING: Tag is not in 4 byte UID mode. Automatically disabling")
    				print(ansicolors.yellow.."[-]".. ansicolors.reset .." This is because the configuration byte responsible for CL2 was found to be equal to: ".. string.format("%02x", configdata[10]))
    				print(ansicolors.yellow.."[\\]".. ansicolors.reset .." The old config is: ".. utils.ConvertBytesToHex(configdata))
    				configdata[10]=0x00
    				writeconf(configdata)
    			end
     			if sendRaw("A000", true) ~= "0A" then
    				oops("Tag did not ACK `A000` command!")
     				lib14a.disconnect()
     				return 1 end
     		end
     		if sendRaw(payload, false) ~= "0A" then oops("Tag did not ACK data to write!") end
     	    end
     	end
    end
    -- Separator
    if signature then
    	wakeupmagic(writetype)
    	local configdata = readconf()
    	if configdata[14] ~= 0x5A then
    		print("[?] WARNING: Signature sector is not enabled. Automatically enabling")
    		configdata[14] = 0x5A
    		writeconf(configdata)
    	end
    	if sendRaw("A805", true) ~= "0A" then
    		oops("Tag did not ACK `A805` command!")
     		lib14a.disconnect()
     	return 1 end
     	if sendRaw(string.sub(signature,1,32), true) ~= "0A" then
    		oops("Tag did not ACK data 1 to write!")
     		lib14a.disconnect()
     	return 1 end
     	if sendRaw("A806", true) ~= "0A" then
    		oops("Tag did not ACK `A806` command!")
     		lib14a.disconnect()
     	return 1 end
     	if sendRaw(string.sub(signature,33,64), false) ~= "0A" then
     	    	oops("Tag did not ACK data 2 to write!")
     		lib14a.disconnect()
     	return 1 end
    end
    if configwrite then
    	print(ansicolors.yellow.."[|]"..ansicolors.reset.." Welcome to ConfigStar!")
    	wakeupmagic(writetype)
    	config=readconf()
    	if (gen1 == false and magicauth == false) or ((config[1]==0x85 and config[2] == 0x00) and magicauth==false) or ((config[12]==0x00) and gen1 == false) then
    		oops("What you are about to do is potentially dangerous. \n    If you really want to continue (potentially leaving your tag in an unusable state), enter this line as given, without quotation marks:\n    \"Yes, do as I say!\"")
    		local ans=io.read()
    		if ans ~="Yes, do as I say!" then
    			lib14a.disconnect()
    			return 1
    		else print(ansicolors.red.."[/]"..ansicolors.reset.." Brace yourself.") end
    		end
    	-- Baby oh baby
    	-- Prepare for disappointment
    	if gen1 == true then
    		config[1] = 0x7A
    		config[2] = 0xFF
    	elseif gen1 == false then
    		config[1] = 0x85
    		config[2] = 0x00
    	end
    	if gen1com == true then
    		config[3] = 0x85
    	elseif gen1com == false then
    		config[3] = 0x00
    	end
    	if keyblock == true then
    		config[7] = 0x5A
    	elseif keyblock == false then
    		config[7] = 0x00
    	end
    	if cuid == true then
    		config[8] = 0x5A
    	elseif cuid == false then
    		config[8] = 0x00
    	end
    	if cl2mode == true then
    		config[10] = 0x5A
    	elseif cl2mode == false then
    		config[10] = 0x00
    	end
    	if shadowmode == true then
    		config[11] = 0x5A
    	elseif shadowmode == false then
    		config[11] = 0x00
    	end
    	if magicauth == true then
    		config[12] = 0x5A
    	elseif magicauth == false then
    		config[12] = 0x00
    	end
    	if statenc == true then
    		config[13] = 0x5A
    	elseif statenc == false then
    		config[13] = 0x00
    	end
    	if sigsec == true then
    		config[14] = 0x5A
    	elseif sigsec == false then
    		config[14] = 0x00
    	end
    	writeconf(config)
    	print(ansicolors.yellow.."[\\]"..ansicolors.reset.." Completed!")
    	lib14a.disconnect()
    end
end
main(args)
