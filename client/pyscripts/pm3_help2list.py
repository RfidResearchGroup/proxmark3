#!/usr/bin/env python3
"""
PM3 Help 2 List

This script takes the full text help output from the PM3 client and converts it to a list to be used for readline autocomplete.

It is based on pm3_help2JSON.py by
Original Authors / Maintainers:
 - Samuel Windall

This version
 - Iceman

Note:
    This script is used as a helper script to generate the pm3line_vocabulary.h file.
    It need a working proxmark3 client to extract the help text.

    Ie: this script can't be used inside the normal build sequence.
"""

import re
import datetime
import argparse
import logging

##############################################################################
# Script version data: (Please increment when making updates)

APP_NAME = 'PM3Help2List'

VERSION_MAJOR = 1
VERSION_MINOR = 0

##############################################################################
# Main Application Code:


def main():
    """The main function for the script"""
    args = build_arg_parser().parse_args()
    logging_format = '%(message)s'
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format=logging_format)
    else:
        logging.basicConfig(level=logging.WARN, format=logging_format)
    logging.info(f'{get_version()} starting...')
    help_text = args.input_file.read()
    command_data = parse_all_command_data(help_text)

    args.output_file.write("""//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// readline auto complete utilities
//-----------------------------------------------------------------------------

#ifndef PM3LINE_VOCABULARY_H__
#define PM3LINE_VOCABULARY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

typedef struct vocabulary_s {
    bool offline;
    const char *name;
} vocabulary_t;

const static vocabulary_t vocabulary[] = {\n""")

    for key, values in command_data.items():
        offline = 0
        if (values['offline'] == True):
            offline = 1

        cmd = values['command']

        args.output_file.write('    {{ {}, "{}" }},\n'.format(offline, cmd))

    args.output_file.write("""    {0, NULL}\n};

#ifdef __cplusplus
}
#endif

#endif""")

    logging.info(f'{get_version()} completed!')


def build_arg_parser():
    """Build the argument parser for reading the program arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Source of full text help from the PM3 client.')
    parser.add_argument('output_file', type=argparse.FileType('w'), help='Destination for list output.')
    parser.add_argument('--version', '-v', action='version', version=get_version(), help='Version data about this app.')
    parser.add_argument('--debug', '-d', action='store_true', help='Log debug messages.')
    return parser


def build_help_regex():
    """The regex uses to parse the full text output of help data from the pm3 client."""
    # Reads the divider followed by the command itself
    re_command = r'-{87}\n(?P<command>.+)\n'

    # Reads if the command is available offline
    re_offline = r'available offline: (?P<offline>yes|no)\n+'

    return re.compile(re_command+re_offline, re.MULTILINE);


def parse_all_command_data(help_text):
    """Turns the full text output of help data from the pm3 client into a list of dictionaries"""
    command_dicts = {}
    # Strip out ANSI escape sequences
    help_text = remove_ansi_escape_codes(help_text)
    # Find all commands in the full text help output
    matches = build_help_regex().finditer(help_text)
    for match in matches:
        # Turn a match into a dictionary with keys for the extracted fields
        command_object = parse_command_data(match)
        # Store this command against its name for easy lookup
        command_dicts[command_object['command']] = command_object
    return command_dicts


def parse_command_data(match):
    """Turns a regex match of a command in the help text and converts it into a dictionary"""
    logging.info('Parsing new command...')
    # Get and clean the command string
    command = remove_extra_whitespace(match.group('command'))
    logging.info(f'    Command: {command}')

    # Get the online status as a boolean. Note: the regex only picks up 'yes' or 'no' so this check is safe.
    offline = (match.group('offline') == 'yes')
    logging.debug(f'    Offline: {offline}')

    # Construct the command dictionary
    command_data = {
        'command': command,
        'offline': offline,
    }
    logging.info('Completed parsing command!')
    return command_data


##############################################################################
# Helper Functions:


def get_version():
    """Get the version string for this script"""
    return f'{APP_NAME} v{VERSION_MAJOR}.{VERSION_MINOR:02}'


def remove_ansi_escape_codes(text):
    """Remove ANSI escape sequences that may be left in the text."""
    re_ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return re_ansi_escape.sub('', str(text)).lower()


def remove_extra_whitespace(text):
    """Removes extra whitespace that may be in the text."""
    # Ensure input is a string
    text = str(text)
    # Remove whitespace from the start and end of the text
    text = text.strip()
    # Deduplicate spaces in the string
    text = re.sub(r' +', ' ', text)
    return text


def text_to_oneliner(text):
    """Converts a multi line string into a single line string and removes extra whitespace"""
    # Ensure input is a string
    text = str(text)
    # Replace newlines with spaces
    text = re.sub(r'\n+', ' ', text)
    # Remove the extra whitespace
    text = remove_extra_whitespace(text)
    return text


def text_to_list(text):
    """Converts a multi line string into a list of lines and removes extra whitespace"""
    # Ensure input is a string
    text = str(text)
    # Get all the lines
    lines = text.strip().split('\n')
    # For each line clean up any extra whitespace
    return [remove_extra_whitespace(line) for line in lines]


##############################################################################
# Application entrypoint:

if __name__ == '__main__':
    main()
