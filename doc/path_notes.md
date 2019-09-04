# Notes on paths.


With the recent (2019-09-01) changes and creation of _make install_  command it is still easy to get lost.

We are adapting the client to use searchFile when creating or calling a Proxmark3 command with a filename.
Here is where it tries to find the file and in which precedense order it takes.




## binary paths
This is where the executable / shellscripts will be copied to.

```
/usr/share/proxmark3
/usr/local/share/proxmark3
```

## User given paths
```
~/.proxmark3/
./
```

## Proxmark3 client essential files
```
/resources
/dictionaries
/lualibs
/luascripts
/cmdscripts
```

## seaching for a file
First instance where a file is found will be used in the client. 

1. share  (install paths)
2. $HOME/.proxmark3   (user home directory
3. ./    (current working directory)


## What is where?
/resources
command like 

/dictionaries 
Here you find the default dictionaries or your own used for commands like `hf mf chk`, `hf mf fchk`, `lf t55xx chk`
A dictionary file is a text based file with one key per line in hexdecimal form.
The length of the key is decided by the Proxmark3 client for the different commands.  All chars afterwards on line is ignored.
if key isn't a hex number, the key is igonored.

- t55xx, Mifare Ultralight/NTAG  - uses 4 hexbytes (11223344) 
- Mifare classic uses 6 hexbytes (112233445566)
- iClass uses 8 hexbytes (1122334455667788)

/luascripts
Here you find existing lua scripts available,  or where you put your own custom lua scripts. Look at existing scripts for ideas how to create your own scripts.

/lualibs
Here is the supporting lua libraries used for lua scripts. basically reused functions in a lua file like converting string to hex etc.

/cmdscripts
Here you find the proxmark3 client command line scripts.  The client can run a text file containing Proxmark3 commands.

a samplefile could be like this.
```
$> cat myscript.cmd

rem running some HF-based info commands
hf 14a info
hf mfu info
rem done
```

You call it with:
`$> pm3 -c myscript.cmd`  

The client will execute eachone of the commands in order and then exit.   There are also a possibility to remain in the client afterward with the -i parameter
`pm3 -c myscript.cmd -i`
