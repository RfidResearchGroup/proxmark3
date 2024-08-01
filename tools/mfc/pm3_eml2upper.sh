#!/usr/bin/env bash

# Andrei Costin <zveriu@gmail.com>, 2011
# pm3_eml2upper.sh
# Converts PM3 Mifare Classic emulator EML file to UPPER case (for easier comparison in some text-comparison tools)

# http://www.linuxquestions.org/questions/programming-9/bash-script-parsing-optional-parameters-621728/

# show program usage
show_usage()
{
    echo
    echo "Usage:"
    echo "${0##/} input.eml output.eml"
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

tr '[:lower:]' '[:upper:]' < $1 > $2
