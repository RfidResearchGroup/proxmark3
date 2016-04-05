--[[
local _errorcodes = {
	SW_NO_ERROR = 0x9000,
	SW_BYTES_REMAINING_00 = 0x6100, -- Response bytes remaining 
	SW_WARNING_STATE_UNCHANGED = 0x6200,  -- Warning, card state unchanged = 
	SW_WRONG_LENGTH = 0x6700, -- : Wrong length
	SW_WRONG_P1P2 = 0x6B00, --  : Incorrect parameters (P1,P2)
	SW_CORRECT_LENGTH_00 = 0x6C00, -- : Correct Expected Length (Le)
	SW_INS_NOT_SUPPORTED = 0x6D00, --  : INS value not supported
	SW_CLA_NOT_SUPPORTED = 0x6E00, --  : CLA value not supported
	SW_UNKNOWN = 0x6F00, --  : No precise diagnosis

	SW_LOGICAL_CHANNEL_NOT_SUPPORTED  = 0x6881, -- : Card does not support the operation on the specified logical channel
	SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882, --  : Card does not support secure messaging
	SW_LAST_COMMAND_EXPECTED = 0x6883, --  : Last command in chain expected
	SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884, --  : Command chaining not supported

	SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982, --  : Security condition not satisfied
	SW_FILE_INVALID = 0x6983, -- : File invalid 
	SW_DATA_INVALID = 0x6984, --  : Data invalid
	SW_CONDITIONS_NOT_SATISFIED = 0x6985, -- : Conditions of use not satisfied
	SW_COMMAND_NOT_ALLOWED = 0x6986, --  : Command not allowed (no current EF)
	SW_APPLET_SELECT_FAILED = 0x6999, --  : Applet selection failed

	SW_WRONG_DATA = 0x6A80, --  : Wrong data
	SW_FUNC_NOT_SUPPORTED = 0x6A81, --  : Function not supported
	SW_FILE_NOT_FOUND = 0x6A82, --  : File not found
	SW_RECORD_NOT_FOUND = 0x6A83, --  : Record not found
	SW_FILE_FULL = 0x6A84, --  : Not enough memory space in the file
	SW_INCORRECT_P1P2 = 0x6A86, --  : Incorrect parameters (P1,P2)
}
--]]
local _errorcodes = {
	SW_NO_ERROR = '9000',
	SW_BYTES_REMAINING_00 = '6100', -- Response bytes remaining 
	SW_WARNING_STATE_UNCHANGED = '6200',  -- Warning', card state unchanged = 
	SW_WRONG_LENGTH = '6700', -- : Wrong length
	SW_WRONG_P1P2 = '6B00', --  : Incorrect parameters (P1,P2)
	SW_CORRECT_LENGTH_00 = '6C00', -- : Correct Expected Length (Le)
	SW_INS_NOT_SUPPORTED = '6D00', --  : INS value not supported
	SW_CLA_NOT_SUPPORTED = '6E00', --  : CLA value not supported
	SW_UNKNOWN = '6F00', --  : No precise diagnosis

	SW_LOGICAL_CHANNEL_NOT_SUPPORTED  = '6881', -- : Card does not support the operation on the specified logical channel
	SW_SECURE_MESSAGING_NOT_SUPPORTED = '6882', --  : Card does not support secure messaging
	SW_LAST_COMMAND_EXPECTED = '6883', --  : Last command in chain expected
	SW_COMMAND_CHAINING_NOT_SUPPORTED = '6884', --  : Command chaining not supported

	SW_SECURITY_STATUS_NOT_SATISFIED = '6982', --  : Security condition not satisfied
	SW_FILE_INVALID = '6983', -- : File invalid 
	SW_DATA_INVALID = '6984', --  : Data invalid
	SW_CONDITIONS_NOT_SATISFIED = '6985', -- : Conditions of use not satisfied
	SW_COMMAND_NOT_ALLOWED = '6986', --  : Command not allowed (no current EF)
	SW_APPLET_SELECT_FAILED = '6999', --  : Applet selection failed

	SW_WRONG_DATA = '6A80', --  : Wrong data
	SW_FUNC_NOT_SUPPORTED = '6A81', --  : Function not supported
	SW_FILE_NOT_FOUND = '6A82', --  : File not found
	SW_RECORD_NOT_FOUND = '6A83', --  : Record not found
	SW_FILE_FULL = '6A84', --  : Not enough memory space in the file
	SW_INCORRECT_P1P2 = '6A86', --  : Incorrect parameters (P1,P2)
}

local _reverse_lookup,k,v = {}
for k, v in pairs(_errorcodes) do
	_reverse_lookup[v] =  k
end

_errorcodes.tostring = function(command)
	if(type(command) == 'string') then
		return ("%s (%d)"):format(_reverse_lookup[command] or "ERROR UNDEFINED!", command) 
	end
	if(type(command) == 'number') then
		return ("%s (%d)"):format(_reverse_lookup[ tostring(command)] or "ERROR UNDEFINED!", command) 
	end
	return ("Error, numeric or string argument expected, got : %s"):format(tostring(command))
end
return _errorcodes