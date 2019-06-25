
2018-12-20 Iceman
2019-03-11 Iceman chg
=======================================

The latest firmware for the SIM MODULE is :   SIM011.bin

You can use it to upgrade you sim module via the pm3 client.

pm3 --> sc upgrade -h
pm3 --> sc upgrade f ../tools/simmodule/SIM011.bin


Even its a quite fast command you should be warned.  You may brick it if you interrupt it.


Run hw status command to verify that the upgrade went well.

pm3 -->  hw status



If you didn't download this file from the RRG Repo be aware that it might be corrupt or faulty.

You find to hash text files in this folder.   They were generated with the following linux commands.


md5sum -b SIM011.bin > SIM011.md5.txt
sha512sum -b SIM011.bin > SIM011.sha512.txt


You should validate the SIM011.bin file against these hash files in order to be sure the file is not corrupt or faulty.