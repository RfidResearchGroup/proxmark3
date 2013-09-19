local foo = "This shows how to use some standard libraries"
print(foo)
local answer
repeat
  	io.write("Continue with this operation (y/n)? ")
  	io.flush()
  	answer=io.read()
until answer=="y" or answer=="n"
local x = "Ok then, %s"
print (x:format("whatever"))