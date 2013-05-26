local desc = "How would the classic mifare hack look in lua? Let's find out "
print(desc);

print("This script isn't even remotely finished!")
print("Checking preconditions");
print("core", core)
print("core.SendCommand", core.SendCommand)
print("core.WaitForResponseTimeout", core.WaitForResponseTimeout)
print("core.nonce2key", core.nonce2key)
-- To actually send something meaningful, we need to include the 'Binlib' or 'lpack' library. 
local cmd = 0x0611 -- CMD_READER_MIFARE - uint_64
local arg1, arg2, arg3  = "0","0","0" -- 3 x uint_64
local d  =  string.rep("00",512)-- 512 bytes
local usbcommand = bin.pack("LLLLH",cmd, arg1, arg2, arg3,d);
print("len(usbcommand): ", string.len(usbcommand));
local x = core.SendCommand(usbcommand);
local result
repeat 
	result = core.WaitForResponseTimeout(cmd,1000)
	print(".")
until result

local r_cmd, r_arg1, r_arg2, r_arg3,r_data;
--[[
response = bin.unpack()
isOK  = resp.arg[0] & 0xff;
	
uid = (uint32_t)bytes_to_num(resp.d.asBytes +  0, 4);
nt =  (uint32_t)bytes_to_num(resp.d.asBytes +  4, 4);
par_list = bytes_to_num(resp.d.asBytes +  8, 8);
ks_list = bytes_to_num(resp.d.asBytes +  16, 8);
	

end
--]]
--- Oh, and nonce2Key is not 'glued' yet. 
print("err", result)