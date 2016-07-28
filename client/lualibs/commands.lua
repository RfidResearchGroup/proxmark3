--[[
These are command definitions. This file should correspond exactly to usb_cmd.h. 
--]]
--// For the bootloader
local _commands = {
	CMD_DEVICE_INFO =                                                    0x0000,
	CMD_SETUP_WRITE =                                                    0x0001,
	CMD_FINISH_WRITE =                                                   0x0003,
	CMD_HARDWARE_RESET =                                                 0x0004,
	CMD_START_FLASH =                                                    0x0005,
	CMD_NACK =                                                           0x00fe,
	CMD_ACK =                                                            0x00ff,

	--// For general mucking around
	CMD_DEBUG_PRINT_STRING =                                             0x0100,
	CMD_DEBUG_PRINT_INTEGERS =                                           0x0101,
	CMD_DEBUG_PRINT_BYTES =                                              0x0102,
	CMD_LCD_RESET =                                                      0x0103,
	CMD_LCD =                                                            0x0104,
	CMD_BUFF_CLEAR =                                                     0x0105,
	CMD_READ_MEM =                                                       0x0106,
	CMD_VERSION =                                                        0x0107,
	CMD_STATUS =                                                         0x0108,
	CMD_PING =                                                           0x0109,
	CMD_DOWNLOAD_EML_BIGBUF =											 0x0110,
	CMD_DOWNLOADED_EML_BIGBUF =											 0x0111,

	--// For low-frequency tags
	CMD_READ_TI_TYPE =                                                   0x0202,
	CMD_WRITE_TI_TYPE =                                                  0x0203,
	CMD_DOWNLOADED_RAW_BITS_TI_TYPE =                                    0x0204,
	CMD_ACQUIRE_RAW_ADC_SAMPLES_125K =                                   0x0205,
	CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K =                          0x0206,
	CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K =                                  0x0207,
	CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K =                                0x0208,
	CMD_DOWNLOADED_SIM_SAMPLES_125K =                                    0x0209,
	CMD_SIMULATE_TAG_125K =                                              0x020A,
	CMD_HID_DEMOD_FSK =                                                  0x020B,
	CMD_HID_SIM_TAG =                                                    0x020C,
	CMD_SET_LF_DIVISOR =                                                 0x020D,
	CMD_LF_SIMULATE_BIDIR =                                              0x020E,
	CMD_SET_ADC_MUX =                                                    0x020F,
	CMD_HID_CLONE_TAG =                                                  0x0210,
	CMD_EM410X_WRITE_TAG =                                               0x0211,
	CMD_INDALA_CLONE_TAG =                                               0x0212,
	--// for 224 bits UID
	CMD_INDALA_CLONE_TAG_L =                                             0x0213,
	CMD_T55XX_READ_BLOCK =                                               0x0214,
	CMD_T55XX_WRITE_BLOCK =                                              0x0215,
	CMD_T55XX_RESET_READ =                                               0x0216,
	CMD_PCF7931_READ =                                                   0x0217,
	CMD_PCF7931_WRITE =                                                  0x0223,
	CMD_EM4X_READ_WORD =                                                 0x0218,
	CMD_EM4X_WRITE_WORD =                                                0x0219,
	CMD_IO_DEMOD_FSK =                                                   0x021A,
	CMD_IO_CLONE_TAG =                                                   0x021B,
	CMD_EM410X_DEMOD =                                                   0x021c,
	CMD_SET_LF_SAMPLING_CONFIG =                                         0x021d,
	CMD_FSK_SIM_TAG =                                                    0x021E,
	CMD_ASK_SIM_TAG =                                                    0x021F,
	CMD_PSK_SIM_TAG =                                                    0x0220,
	CMD_AWID_DEMOD_FSK =                                                 0x0221,
	CMD_VIKING_CLONE_TAG =                                               0x0222,
	CMD_T55XX_WAKEUP =	                                              	 0x0224,
	
	--/* CMD_SET_ADC_MUX: ext1 is 0 for lopkd, 1 for loraw, 2 for hipkd, 3 for hiraw */

	--// For the 13.56 MHz tags
	CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693 =                              0x0300,
	CMD_READ_SRI_TAG =                                                   0x0303,
	CMD_ISO_14443B_COMMAND =											 0x0305,
	CMD_READER_ISO_15693 =                                               0x0310,
	CMD_SIMTAG_ISO_15693 =                                               0x0311,
	CMD_RECORD_RAW_ADC_SAMPLES_ISO_15693 =                               0x0312,
	CMD_ISO_15693_COMMAND =                                              0x0313,
	CMD_ISO_15693_COMMAND_DONE =                                         0x0314,
	CMD_ISO_15693_FIND_AFI =                                             0x0315,
	CMD_ISO_15693_DEBUG =                                                0x0316,
	CMD_LF_SNOOP_RAW_ADC_SAMPLES =                                       0x0317,

	--// For Hitag2 transponders
	CMD_SNOOP_HITAG =                                                    0x0370,
	CMD_SIMULATE_HITAG =                                                 0x0371,
	CMD_READER_HITAG =                                                   0x0372,

	--// For HitagS
	CMD_TEST_HITAGS_TRACES =											 0x0367,
	CMD_SIMULATE_HITAG_S =												 0x0368,
	CMD_READ_HITAG_S =													 0x0373,
	CMD_WR_HITAG_S =													 0x0375,
	CMD_EMU_HITAG_S =													 0x0376,
	
	CMD_SIMULATE_TAG_ISO_14443B =                                        0x0381,
	CMD_SNOOP_ISO_14443B =                                               0x0382,
	CMD_SNOOP_ISO_14443a =                                               0x0383,
	CMD_SIMULATE_TAG_ISO_14443a =                                        0x0384,
	CMD_READER_ISO_14443a =                                              0x0385,
	CMD_RAW_WRITER_LEGIC_RF =											 0x0386,
	CMD_SIMULATE_TAG_LEGIC_RF =                                          0x0387,
	CMD_READER_LEGIC_RF =                                                0x0388,
	CMD_WRITER_LEGIC_RF =                                                0x0389,
	CMD_EPA_PACE_COLLECT_NONCE =                                         0x038A,
	CMD_EPA_PACE_REPLAY =                                                0x038B,

	CMD_ICLASS_READCHECK =                                               0x038F,
	CMD_ICLASS_CLONE =                                                   0x0390,
	CMD_ICLASS_DUMP =                                                    0x0391,
	CMD_SNOOP_ICLASS =                                                   0x0392,
	CMD_SIMULATE_TAG_ICLASS =                                            0x0393,
	CMD_READER_ICLASS =                                                  0x0394,
	CMD_READER_ICLASS_REPLAY =											 0x0395,
	CMD_ICLASS_READBLOCK =                                               0x0396,
	CMD_ICLASS_WRITEBLOCK =                                              0x0397,
	CMD_ICLASS_EML_MEMSET =                                              0x0398,
	CMD_ICLASS_AUTHENTICATION =                                          0x0399,

	--// For measurements of the antenna tuning
	CMD_MEASURE_ANTENNA_TUNING =                                         0x0400,
	CMD_MEASURE_ANTENNA_TUNING_HF =                                      0x0401,
	CMD_MEASURED_ANTENNA_TUNING =                                        0x0410,
	CMD_LISTEN_READER_FIELD =                                            0x0420,

	--// For direct FPGA control
	CMD_FPGA_MAJOR_MODE_OFF =                                            0x0500,

	--// For mifare commands
	CMD_MIFARE_SET_DBGMODE =                                             0x0600,
	CMD_MIFARE_EML_MEMCLR =                                              0x0601,
	CMD_MIFARE_EML_MEMSET =                                              0x0602,
	CMD_MIFARE_EML_MEMGET =                                              0x0603,
	CMD_MIFARE_EML_CARDLOAD =                                            0x0604,
	
	--// magic chinese card commands
	CMD_MIFARE_CSETBLOCK =                                               0x0605,
	CMD_MIFARE_CGETBLOCK =                                               0x0606,
	CMD_MIFARE_CIDENT =                                                  0x0607,

	CMD_SIMULATE_MIFARE_CARD =                                           0x0610,

	CMD_READER_MIFARE =                                                  0x0611,
	CMD_MIFARE_NESTED =                                                  0x0612,
	CMD_MIFARE_ACQUIRE_ENCRYPTED_NONCES =                                0x0613,

	CMD_MIFARE_READBL =                                                  0x0620,
	CMD_MIFAREU_READBL =                                                 0x0720,
	
	CMD_MIFARE_READSC =                                                  0x0621,
	CMD_MIFAREU_READCARD =                                               0x0721,
	
	CMD_MIFARE_WRITEBL =                                                 0x0622,
	CMD_MIFAREU_WRITEBL =                                                0x0722,
	CMD_MIFAREU_WRITEBL_COMPAT =                                         0x0723,
	
	CMD_MIFARE_CHKKEYS =                                                 0x0623,

	CMD_MIFARE_SNIFFER =                                                 0x0630,

	--//ultralightC
	CMD_MIFAREUC_AUTH =                                                  0x0724,
	CMD_MIFAREUC_SETPWD =												 0x0727,
	CMD_MIFAREU_SETUID = 							                     0x0728,

	--// mifare desfire
	CMD_MIFARE_DESFIRE_READBL =                                          0x0728,
	CMD_MIFARE_DESFIRE_WRITEBL =                                         0x0729,
	CMD_MIFARE_DESFIRE_AUTH1 =                                           0x072a,
	CMD_MIFARE_DESFIRE_AUTH2 =                                           0x072b,
	CMD_MIFARE_DES_READER =                                              0x072c,
	CMD_MIFARE_DESFIRE_INFO =                                            0x072d,
	CMD_MIFARE_DESFIRE =                                                 0x072e,
    CMD_HF_SNIFFER =                                                     0x0800,	

	
	--// For EMV Commands
	CMD_EMV_READ_RECORD =                                                0x0700,
	CMD_EMV_TRANSACTION =                                                0x0701,
	CMD_EMV_CLONE =                                                      0x0702,
	CMD_EMV_SIM =                                                        0x0703,
	CMD_EMV_TEST =                                                       0x0704,
	CMD_EMV_FUZZ_RATS =                                                  0x0705,
	CMD_EMV_GET_RANDOM_NUM =                                             0x0706,
	CMD_EMV_LOAD_VALUE =                                                 0x0707,
	CMD_EMV_DUMP_CARD =                                                  0x0708,
	
	CMD_UNKNOWN =                                                        0xFFFF,
}


local _reverse_lookup,k,v = {}
for k, v in pairs(_commands) do
	_reverse_lookup[v] =  k
end
_commands.tostring = function(command)
	if(type(command) == 'number') then
		return ("%s (%d)"):format(_reverse_lookup[command]or "ERROR UNDEFINED!", command) 
	end
	return ("Error, numeric argument expected, got : %s"):format(tostring(command))
end

Command = {

	new = function(self, o)

		local o = o or {}   -- create object if user does not provide one
		setmetatable(o, self) -- DIY inheritance a'la javascript
		self.__index = self

		o.cmd = o.cmd or _commands.CMD_UNKNOWN
		o.arg1 = o.arg1 or 0
		o.arg2 = o.arg2 or 0
		o.arg3 = o.arg3 or 0 
		local data = o.data or "0"

		if(type(data) == 'string') then
			-- We need to check if it is correct length, otherwise pad it
			local len = string.len(data)
			if(len < 1024) then  
				--Should be 1024 hex characters to represent 512 bytes of data 
				data = data .. string.rep("0",1024 - len ) 
			end
			if(len > 1024) then
				-- OOps, a bit too much data here
				print( ( "WARNING: data size too large, was %s chars, will be truncated "):format(len) )
				--
				data = data:sub(1,1024)
			end
		else 
			print(("WARNING; data was NOT a (hex-) string, but was %s"):format(type(data)))
		end
		o.data = data	
		return o
	end,
	parse = function(packet)
		local count, cmd, arg1, arg2, arg3, data = bin.unpack('LLLLH511', packet)
		return Command:new{cmd = cmd, arg1 = arg1, arg2 = arg2, arg3 = arg3, data = data}
	end

}
function Command:__tostring()
	local output = ("%s\r\nargs : (%s, %s, %s)\r\ndata:\r\n%s\r\n"):format(
		_commands.tostring(self.cmd),
		tostring(self.arg1),
	 	tostring(self.arg2),
	 	tostring(self.arg3),
	 	tostring(self.data))
	return output
end
function Command:getBytes()
	--If a hex-string has been used
	local data  = self.data
	local cmd = self.cmd 
	local arg1, arg2, arg3 = self.arg1, self.arg2, self.arg3
	return bin.pack("LLLLH", cmd, arg1, arg2, arg3, data);
end
return _commands
