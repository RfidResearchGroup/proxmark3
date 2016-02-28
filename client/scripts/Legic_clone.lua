--[[
	script to create a clone-dump with new crc
  Author: mosci
   my Fork: https://github.com/icsom/proxmark3.git
	Upstream: https://github.com/Proxmark/proxmark3.git

	1. read tag-dump, xor byte 22..end with byte 0x05 of the inputfile
	2. write to outfile 
	3. set byte 0x05 to newcrc
	4. until byte 0x21 plain like in inputfile
	5. from 0x22..end xored with newcrc
	6. calculate new crc on each segment (needs to know the new MCD & MSN0..2)
	
	simplest usage:
	read a valid legic tag with 'hf legic reader'
	save the dump with 'hf legic save orig.hex'
  place your 'empty' tag on the reader and run 'script run Legic_clone -i orig.hex -w'
  you will see some output like:
		read 1024 bytes from legic_dumps/j_0000.hex
		
		place your empty tag onto the PM3 to read and display the MCD & MSN0..2
		the values will be shown below
		 confirm whnen ready [y/n] ?y
		#db# setting up legic card
		#db# MIM 256 card found, reading card ...
		#db# Card read, use 'hf legic decode' or
		#db# 'data hexsamples 8' to view results
		0b ad c0 de  <- !! here you'll see the MCD & MSN of your empty tag, which has to be typed in manually as seen below !!
		type in  MCD as 2-digit value - e.g.: 00 (default: 79 )
		 > 0b
		type in MSN0 as 2-digit value - e.g.: 01 (default: 28 )
		 > ad
		type in MSN1 as 2-digit value - e.g.: 02 (default: d1 )
		 > c0
		type in MSN2 as 2-digit value - e.g.: 03 (default: 43 )
		 > de
		MCD:0b, MSN:ad c0 de, MCC:79 <- this crc is calculated from the MCD & MSN and must match the one on yout empty tag
		
		wrote 1024 bytes to myLegicClone.hex
		enter number of bytes to write? (default: 86 )
		
		loaded 1024 samples
		#db# setting up legic card
		#db# MIM 256 card found, writing 0x00 - 0x01 ...
		#db# write successful
		...
		#db# setting up legic card
		#db# MIM 256 card found, writing 0x56 - 0x01 ...
		#db# write successful
		proxmark3>
	
	the default value (number of bytes to write) is calculated over all valid segments and should be ok - just hit enter, wait until write has finished
	and your clone should be ready (except there has to be a additional KGH-CRC to be calculated - which credentials are unknown until yet)
	
	the '-w' switch will only work with my fork - it needs the binary legic_crc8 which is not part of the proxmark3-master-branch
	also the ability to write DCF is not possible with the proxmark3-master-branch
	but creating dumpfile-clone files will be possible (without valid segment-crc - this has to done manually with) 

	
	(example)	Legic-Prime Layout with 'Kaba Group Header'
			+----+----+----+----+----+----+----+----+
  0x00|MCD |MSN0|MSN1|MSN2|MCC | 60 | ea | 9f |		
			+----+----+----+----+----+----+----+----+
	0x08| ff | 00 | 00 | 00 | 11 |Bck0|Bck1|Bck2|
			+----+----+----+----+----+----+----+----+
	0x10|Bck3|Bck4|Bck5|BCC | 00 | 00 |Seg0|Seg1|
			+----+----+----+----+----+----+----+----+
	0x18|Seg2|Seg3|SegC|Stp0|Stp1|Stp2|Stp3|UID0|
			+----+----+----+----+----+----+----+----+
	0x20|UID1|UID2|kghC|
			+----+----+----+
					
				MCD=	ManufacturerID						(1 Byte)
		MSN0..2=	ManufactureSerialNumber		(3 Byte)
				MCC=	CRC												(1 Byte) calculated over MCD,MSN0..2
				DCF=	DecrementalField					(2 Byte) 'credential' (enduser-Tag) seems to have always DCF-low=0x60 DCF-high=0xea
		Bck0..5=	Backup										(6 Byte) Bck0 'dirty-flag', Bck1..5 SegmentHeader-Backup 
				BCC=	BackupCRC									(1 Byte) CRC calculated over Bck1..5
		Seg0..3=	SegmentHeader 						(on MIM 4 Byte )
			 SegC=	SegmentCRC								(1 Byte) calculated over MCD,MSN0..2,Seg0..3
		Stp0..n=	Stamp0...									(variable length) length = Segment-Len - UserData - 1
		UID0..n=	UserDater									(variable length - with KGH hex 0x00-0x63 / dec 0-99) length = Segment-Len - WRP - WRC - 1 
		 	 kghC=	KabaGroupHeader						(1 Byte + addr 0x0c must be 0x11)
	as seen on ths example: addr 0x05..0x08 & 0x0c must have been set to this values - otherwise kghCRC will not be created by a official reader (not accepted)
--]]

example = "Script create a clone-dump of a dump from a Legic Prime Tag"
author = "Mosci"
desc =
[[
This is a script which create a clone-dump of a dump from a Legic Prime Tag (MIM256 or MIM1024)
(created with 'hf legic save my_dump.hex') 
requiered arguments:
	-i <input file>		(file to read data from)
	
optional arguments :
	-h                  - Help text
	-o <output file> 	- requieres option -c to be given
	-c <new-tag crc> 	- requieres option -o to be given
	-d					- Display content of found Segments
	-s					- Display summary at the end
	-w					- write directly to Tag - a file myLegicClone.hex wille be generated also
	
	e.g.: 
	hint: using the CRC '00' will result in a plain dump ( -c 00 )

Examples : 
	script run legic_clone -i my_dump.hex -o my_clone.hex -c f8
	script run legic_clone -i my_dump.hex -d -s
]]

local utils = require('utils')
local getopt = require('getopt')
local bxor = bit32.bxor

-- we need always 2 digits
function prepend_zero(s) 
	if (string.len(s)==1) then return "0" .. s
	else 
		if (string.len(s)==0) then return "00"
		else return s
		end
	end
end

--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
	return nil, err
end

--- 
-- Usage help
function help()
	print(desc)
	print("Example usage")
	print(example)
end

-- Check availability of file
function file_check(file_name)
  local file_found=io.open(file_name, "r")      
  if file_found==nil then
    file_found=false
  else
    file_found=true
  end
  return file_found
end

--- xor-wrapper
-- xor all from addr 0x22 (start counting from 1 => 23)
function xorme(hex, xor, index)
	if ( index >= 23 ) then
		return ('%02x'):format(bxor( tonumber(hex,16) , tonumber(xor,16) ))
	else
		return hex
	end
end

-- read input-file into array
function getInputBytes(infile)
	local line
	local bytes = {}

	local fhi,err = io.open(infile)
	if err then print("OOps ... faild to read from file ".. infile); return false; end

	while true do
		line = fhi:read()
		if line == nil then break end

		for byte in line:gmatch("%w+") do 
			table.insert(bytes, byte)
		end
	end
	
	fhi:close()

	print("\nread ".. #bytes .." bytes from ".. infile)
	return bytes
end

-- write to file
function writeOutputBytes(bytes, outfile)
	local line
	local bcnt=0
	local fho,err = io.open(outfile,"w")
	if err then print("OOps ... faild to open output-file ".. outfile); return false; end

	for i = 1, #bytes do
		if (bcnt == 0) then 
			line=bytes[i]
		elseif (bcnt <= 7) then 
			line=line.." "..bytes[i]
		end
		if (bcnt == 7) then
			-- write line to new file
			fho:write(line.."\n")
			-- reset counter & line
			bcnt=-1
			line=""
		end
		bcnt=bcnt+1
	end
	fho:close()
	print("\nwrote ".. #bytes .." bytes to " .. outfile)
	return true
end

-- xore certain bytes
function xorBytes(inBytes, crc)
	local bytes = {}
	for index = 1, #inBytes do
		bytes[index] = xorme(inBytes[index], crc, index)
	end
	if (#inBytes == #bytes) then
		-- replace crc
		bytes[5] = string.sub(crc,-2)
		return bytes
	else
		print("error: byte-count missmatch")
		return false
	end
end

-- get raw segment-data
function getSegmentData(bytes, start, index)
	local raw, len, valid, last, wrp, wrc, rd, crc
	local segment = {}
	segment[0] = bytes[start].." "..bytes[start+1].." "..bytes[start+2].." "..bytes[start+3]
	-- flag = high nibble of byte 1
	segment[1] = string.sub(bytes[start+1],0,1)

	-- valid = bit 6 of byte 1
	segment[2] = tonumber(bit32.extract("0x"..bytes[start+1],6,1),16)

	-- last = bit 7 of byte 1
	segment[3] = tonumber(bit32.extract("0x"..bytes[start+1],7,1),16)

	-- len = (byte 0)+(bit0-3 of byte 1)
  segment[4] = tonumber(("%03x"):format(tonumber(bit32.extract("0x"..bytes[start+1],0,3),16)..tonumber(bytes[start],16)),16)
  
	-- wrp (write proteted) = byte 2
	segment[5] = tonumber(bytes[start+2])

	-- wrc (write control) - bit 4-6 of byte 3
	segment[6] = tonumber(bit32.extract("0x"..bytes[start+3],4,3),16)

	-- rd (read disabled) - bit 7 of byte 3
	segment[7] = tonumber(bit32.extract("0x"..bytes[start+3],7,1),16)

	-- crc byte 4
	segment[8] = bytes[start+4]

	-- segment index
	segment[9] = index

	-- # crc-byte
	segment[10] = start+4
  return segment
end

--- Kaba Group Header
-- checks if a segment does have a kghCRC
-- returns boolean false if no kgh has being detected or the kghCRC if a kgh was detected
function CheckKgh(bytes, segStart, segEnd)
  if (bytes[8]=='9f' and bytes[9]=='ff' and bytes[13]=='11') then
    local i
    local data = {}
    segStart=tonumber(segStart,10)
    segEnd=tonumber(segEnd,10)
    local dataLen = segEnd-segStart-5
    --- gather creadentials for verify
    local WRP = bytes[(segStart+2)]
    local WRC = ("%02x"):format(tonumber(bit32.extract("0x"..bytes[segStart+3],4,3),16))
    local RD = ("%02x"):format(tonumber(bit32.extract("0x"..bytes[segStart+3],7,1),16))
    local XX = "00"  
    cmd = bytes[1]..bytes[2]..bytes[3]..bytes[4]..WRP..WRC..RD..XX
    for i=(segStart+5), (segStart+5+dataLen-2) do
      cmd = cmd..bytes[i]
    end
    local KGH=("%02x"):format(utils.Crc8Legic(cmd))
    if (KGH==bytes[segEnd-1]) then
      return KGH
    else
      return false
    end
  else
    return false
  end
end

-- get only the addresses of segemnt-crc's and the length of bytes
function getSegmentCrcBytes(bytes)
	local start=23
	local index=0
	local crcbytes = {}
	repeat
		seg = getSegmentData(bytes,start,index)
		crcbytes[index]= seg[10]
		start = start + seg[4]
		index = index + 1
	until (seg[3] == 1 or tonumber(seg[9]) == 126 )	
	crcbytes[index] = start
	return crcbytes
end

-- print segment-data (hf legic decode like)
function displaySegments(bytes)
	--display segment header(s)
	start=23
	index="00"
	
	--repeat until last-flag ist set to 1 or segment-index has reached 126
	repeat
		wrc=""
		wrp=""
		pld=""
		Seg = getSegmentData(bytes,start,index)
    KGH = CheckKgh(bytes,start,(start+tonumber(Seg[4],10)))
		printSegment(Seg)

		-- wrc
		if(Seg[6]>0) then
			print("WRC protected area:")
			-- length of wrc = wrc
			for i=1, Seg[6] do
				-- starts at (segment-start + segment-header + segment-crc)-1 
				wrc = wrc..bytes[(start+4+1+i)-1].." " 
			end
			print(wrc)
		elseif(Seg[5]>0) then
			print("Remaining write protected area:")
			-- length of wrp = (wrp-wrc)
			for i=1, (Seg[5]-Seg[6]) do
				-- starts at (segment-start + segment-header + segment-crc + wrc)-1 
				wrp = wrp..bytes[(start+4+1+Seg[6]+i)-1].." " 
			end
			print(wrp)
		end
		
		-- payload 
		print("Remaining segment payload:")
		--length of payload = segment-len - segment-header - segment-crc - wrp -wrc
		for i=1, (Seg[4]-4-1-Seg[5]-Seg[6]) do
			-- starts at (segment-start + segment-header + segment-crc + segment-wrp + segemnt-wrc)-1
			pld = pld..bytes[(start+4+1+Seg[5]+Seg[6]+i)-1].." " 
		end
		print(pld)
    if (KGH) then print("'Kaba Group Header' detected"); end
		start = start+Seg[4]
		index = prepend_zero(tonumber(Seg[9])+1)
    
	until (Seg[3] == 1 or tonumber(Seg[9]) == 126 )
end

-- print Segment values
function printSegment(SegmentData)
	res = "\nSegment "..SegmentData[9]..": "
	res = res..	"raw header="..SegmentData[0]..", "
	res = res..	"flag="..SegmentData[1].." (valid="..SegmentData[2].." last="..SegmentData[3].."), "
	res = res..	"len="..("%04d"):format(SegmentData[4])..", "
	res = res..	"WRP="..prepend_zero(SegmentData[5])..", "
	res = res..	"WRC="..prepend_zero(SegmentData[6])..", "
	res = res.. "RD="..SegmentData[7]..", "
	res = res.. "crc="..SegmentData[8]
	print(res)	
end

-- write clone-data to tag
function writeToTag(plainBytes)
	local SegCrcs = {}
	if(utils.confirm("\nplace your empty tag onto the PM3 to read and display the MCD & MSN0..2\nthe values will be shown below\n confirm when ready") == false) then
    return
  end

	-- gather MCD & MSN from new Tag - this must be enterd manually
	cmd = 'hf legic read 0x00 0x04'
	core.console(cmd)
	print("\nthese are the MCD MSN0 MSN1 MSN2 from the Tag that has being read:")
	cmd = 'data hexsamples 4'
	core.console(cmd)
  print("^^ use this values as input for the following answers (one 2-digit-value per question/answer):")
	-- enter MCD & MSN (in hex)
	MCD  = utils.input("type in  MCD as 2-digit value - e.g.: 00", plainBytes[1])
	MSN0 = utils.input("type in MSN0 as 2-digit value - e.g.: 01", plainBytes[2])
	MSN1 = utils.input("type in MSN1 as 2-digit value - e.g.: 02", plainBytes[3])
	MSN2 = utils.input("type in MSN2 as 2-digit value - e.g.: 03", plainBytes[4])

	-- calculate crc8 over MCD & MSN
	cmd = MCD..MSN0..MSN1..MSN2
	MCC = ("%02x"):format(utils.Crc8Legic(cmd))
	print("MCD:"..MCD..", MSN:"..MSN0.." "..MSN1.." "..MSN2..", MCC:"..MCC)

	-- calculate new Segment-CRC for each valid segment
	SegCrcs = getSegmentCrcBytes(plainBytes)
	for i=0, (#SegCrcs-1) do   
    -- SegCrcs[i]-4 = address of first byte of segmentHeader (low byte segment-length)
    segLen=tonumber(("%1x"):format(tonumber(bit32.extract("0x"..plainBytes[(SegCrcs[i]-3)],0,3),16))..("%02x"):format(tonumber(plainBytes[SegCrcs[i]-4],16)),16)
    segStart=(SegCrcs[i]-4)
    segEnd=(SegCrcs[i]-4+segLen)
    KGH=CheckKgh(plainBytes,segStart,segEnd)
    if (KGH) then 
      print("'Kaba Group Header' detected - re-calculate...")
    end
		cmd = MCD..MSN0..MSN1..MSN2..plainBytes[SegCrcs[i]-4]..plainBytes[SegCrcs[i]-3]..plainBytes[SegCrcs[i]-2]..plainBytes[SegCrcs[i]-1]
		plainBytes[SegCrcs[i]] = ("%02x"):format(utils.Crc8Legic(cmd))
	end

	-- apply MCD & MSN to plain data
	plainBytes[1] = MCD
	plainBytes[2] = MSN0
	plainBytes[3] = MSN1
	plainBytes[4] = MSN2
	plainBytes[5] = MCC
	
	-- prepare plainBytes for writing (xor plain data with new MCC)
	bytes = xorBytes(plainBytes, MCC)
	
	-- write data to file
	if (writeOutputBytes(bytes, "myLegicClone.hex")) then
		WriteBytes = utils.input("enter number of bytes to write?", SegCrcs[#SegCrcs])

		-- load file into pm3-buffer
		cmd = 'hf legic load myLegicClone.hex'
		core.console(cmd)
		
		-- write pm3-buffer to Tag
		for i=0, WriteBytes do
			if ( i<5 or i>6) then
				cmd = ('hf legic write 0x%02x 0x01'):format(i)
				core.console(cmd)
			elseif (i == 6) then
				-- write DCF in reverse order (requires 'mosci-patch')
				cmd = 'hf legic write 0x05 0x02'
				core.console(cmd)
			else
				print("skipping byte 0x05 - will be written next step")
			end				
			utils.Sleep(0.2)
		end
	end
end

-- main function
function main(args)
	-- some variables
	local i=0
	local oldcrc, newcrc, infile, outfile
	local bytes = {}
	local segments = {}
	
	-- parse arguments for the script
	for o, a in getopt.getopt(args, 'hwsdc:i::o:') do
		-- output file
		if o == "o" then 
			outfile = a
			ofs = true
			if (file_check(a)) then
				local answer = utils.confirm("\nthe output-file "..a.." alredy exists!\nthis will delete the previous content!\ncontinue?")
				if (answer==false) then return oops("quiting") end
			end
		end		
		-- input file
		if o == "i" then
			infile = a 
			if (file_check(infile)==false) then
				return oops("input file: "..infile.." not found")
			else
				bytes = getInputBytes(infile)
				oldcrc = bytes[5]
				ifs = true
				if (bytes == false) then return oops('couldnt get input bytes') end
			end
			i = i+1
		end
		-- new crc
		if o == "c" then 
			newcrc = a
			ncs = true
		end
		-- display segments switch
		if o == "d" then ds = true; end
		-- display summary switch
		if o == "s" then ss = true; end
		-- write to tag switch
		if o == "w" then ws = true; end
		-- help
		if o == "h" then return help() end
	end
	
	if (not ifs) then return oops("option -i <input file> is required but missing") end
	
	-- bytes to plain
	bytes = xorBytes(bytes, oldcrc)
	
	-- show segments (works only on plain bytes)
	if (ds) then
		print("+------------------------------------------- Segments -------------------------------------------+") 
		displaySegments(bytes); 
	end

	if (ofs and ncs) then
		-- xor bytes with new crc
		newBytes = xorBytes(bytes, newcrc)
		-- write output
		if (writeOutputBytes(newBytes, outfile)) then
			-- show summary if requested
			if (ss) then
				-- information
				res = "\n+-------------------------------------------- Summary -------------------------------------------+"
				res = res .."\ncreated clone_dump from\n\t"..infile.." crc: "..oldcrc.."\ndump_file:"
				res = res .."\n\t"..outfile.." crc: "..string.sub(newcrc,-2)
				res = res .."\nyou may load the new file with: hf legic load "..outfile
				res = res .."\n\nif you don't write to tag immediately ('-w' switch) you will need to recalculate each segmentCRC"
				res = res .."\nafter writing this dump to a tag!"
				res = res .."\n\na segmentCRC gets calculated over MCD,MSN0..3,Segment-Header0..3"
				res = res .."\ne.g. (based on Segment00 of the data from "..infile.."):"
				res = res .."\nhf legic crc8 "..bytes[1]..bytes[2]..bytes[3]..bytes[4]..bytes[23]..bytes[24]..bytes[25]..bytes[26]
				-- this can not be calculated without knowing the new MCD, MSN0..2
				print(res)
			end
		end
	else
		if (ss) then
			-- show why the output-file was not written
			print("\nnew file not written - some arguments are missing ..")
			print("output file: ".. (ofs and outfile or "not given"))
			print("new crc: ".. (ncs and newcrc or "not given"))
		end
	end
	-- write to tag
	if (ws and #bytes == 1024) then
			writeToTag(bytes)
	end
end

-- call main with arguments
main(args)