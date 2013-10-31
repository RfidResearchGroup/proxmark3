local reader = require('hf_reader')

local function main(args)
	print("WORK IN PROGRESS - not expected to be functional yet")
	info, err = reader.waitForTag()

	if err then 
		print(err)
		return
	end
	local k,v
	print("Tag info")
	for k,v in pairs(info) do
		print(string.format("	%s : %s", tostring(k), tostring(v)))
	end
	return
end
main(args)