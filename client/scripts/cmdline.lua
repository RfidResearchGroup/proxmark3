print("This is how a cmd-line interface could be implemented\nPrint 'exit' to exit.\n")
local answer
repeat
  	io.write("$>")
  	io.flush()
  	answer=io.read()
  	if answer ~= 'exit' then
  		local func = assert(loadstring("return " .. answer))
  		io.write("\n"..tostring(func() or "").."\n");
  	end--]]
until answer=="exit" 
print("Bye\n");
