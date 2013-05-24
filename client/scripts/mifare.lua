local desc = "How would the classic mifare hack look in lua? Let's find out "
print(desc);

print("This script isn't even remotely finished!")
print("Checking preconditions");
print("core", core)
print("core.SendCommand", core.SendCommand)
print("core.WaitForResponseTimeout", core.WaitForResponseTimeout)
print("core.nonce2key", core.nonce2key)
-- To actually send something meaningful, we need to include the 'Binlib' or 'lpack' library. 
local x = core.SendCommand("aaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000ggggaaaabbbb2222111100000gggg12345678901234567890123456789012345678901234")
local result = core.WaitForResponseTimeout(0x0611,1000)
--- Oh, and nonce2Key is not 'glued' yet. 
print("err", result)