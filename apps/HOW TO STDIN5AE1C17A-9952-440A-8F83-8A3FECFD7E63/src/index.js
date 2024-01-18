/**
  This is a sample Node.js script
  explaining how to interact with
  stdin and stdout using the
  colors library.
*/

const dns = require('dns')
const readline = require('readline')
const strings = require('./strings')
const colors = require('colors/safe')

colors.enable()

const print = (msg) => {
  console.log(msg)
}

const resolveAddress = (host) => {
  dns.lookup(
  host, (err, addr, type) => {
    print('')
    if (err) {
      print(strings.error)
      print(colors.red(err.code)) 
    }
    
    if (addr) { 
      print(strings.result)
      print(colors.green.underline(addr)) 
    }
    
    print('——\n')
    process.stdout.write(strings.prompt)
  })
}

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
})

rl.on('line', (line) => {
  var host = line.replace(/\0/g, '')
  resolveAddress(host)
})

print(strings.help)
print('')
process.stdout.write(strings.prompt)
