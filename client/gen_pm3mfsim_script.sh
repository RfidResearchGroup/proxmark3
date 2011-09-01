#!/bin/bash

# Andrei Costin <zveriu@gmail.com>, 2011
# gen_pm3mfsim_script.sh
# Generates Mifare Classic emulation script file that will load a given EML dump into PM3 and start emulation automagically

# http://www.linuxquestions.org/questions/programming-9/bash-script-parsing-optional-parameters-621728/

# show program usage
show_usage()
{
    echo
    echo "Usage:"
    echo "${0##/} input_eml_without_extension output.pm3scr"
    exit
}

# Minimum number of arguments needed by this program
MINARGS=2

# get the number of command-line arguments given
ARGC=$#

# check to make sure enough arguments were given or exit
if [[ $ARGC -lt $MINARGS ]] ; then
    echo "Too few arguments given (Minimum:$MINARGS)"
    echo
    show_usage
fi

rm $2
echo "hf mf eclr" >> $2
echo "hf mf eload" $1 >> $2
echo "hf mf ekeyprn" >> $2
echo "hf mf sim" `cat $1.eml | (read -n 8 uid; echo $uid)` >> $2