clear

rem  Test of Motorola clone & read
lf t55xx wipe
lf motorola clone --raw a0000000a0002021
lf motorola read
lf search

rem  Test of Nexwatch clone & read
lf t55xx wipe
lf nexwatch clone --cn 1337 -m 1 -n
lf nexwatch read
lf search

rem  Test of keri clone & read
lf t55xx wipe
lf keri clone --id 1337
lf keri read
lf search

rem  Test of Indala clone & read
lf t55xx wipe
lf indala clone --fc 7 --cn 1337
lf indala read
lf search

rem done, just wiping your tag.
lf t55xx wipe
