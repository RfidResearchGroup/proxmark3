#!/usr/bin/env python3
"""
PM3 Help 2 JSON

This script takes the full text help output from the PM3 client and converts it to JSON.

Authors / Maintainers:
 - Samuel Windall

Note:
    This file is used during the pm3 client build
    any changes to the call script parameters should be reflected in the makefile
"""

import re
import json
import datetime
import argparse
import logging

##############################################################################
# Script version data: (Please increment when making updates)

APP_NAME = 'PM3Help2JSON'

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
    meta_data = build_metadata(args.meta, command_data)
    output_data = {
        'metadata': meta_data,
        'commands': command_data,
    }
    json.dump(output_data, args.output_file, indent=4, sort_keys=True)
    logging.info(f'{get_version()} completed!')


def build_arg_parser():
    """Build the argument parser for reading the program arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Source of full text help from the PM3 client.')
    parser.add_argument('output_file', type=argparse.FileType('w'), help='Destination for JSON output.')
    parser.add_argument('--meta', action='append', help='Additional metadata to be included.', metavar='key:value')
    parser.add_argument('--version', '-v', action='version', version=get_version(), help='Version data about this app.')
    parser.add_argument('--debug', '-d', action='store_true', help='Log debug messages.')
    return parser


def build_help_regex():
    re_command = r'-{87}\n(?P<command>.+)\n'
    # Reads if the command is available offline
    re_offline = r'available offline: (?P<offline>yes|no)\n+'
    # Reads the description lines
    re_description = r'(?P<description>\n[\s\S]*?(?=usage:))'
    # Reads the usage string
    re_usage = r'(?:usage:\n(?P<usage>(?:.+\n)+)\n+)?'
    # Reads the options and there individual descriptions
    re_options = r'(?:options:\n(?P<options>(?:.+\n)+)\n+)?'
    # Reads the notes and examples
    re_notes = r'(?:examples\/notes:\n(?P<notes>[\s\S]*?(?=(===|---|\n\n))))'
    # Combine them into a single regex object
    re_full = re.compile(re_command+re_offline+re_description+re_usage+re_options+re_notes, re.MULTILINE)
    return re_full


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
    # Get and clean the description paragraph
    description = text_to_oneliner(match.group('description'))
    logging.debug(f'    Description: {description}')
    # Get and clen the usage string
    usage = text_to_oneliner(match.group('usage'))
    logging.debug(f'    Usage: {usage}')
    # Get and clean the list of options
    options = text_to_list(match.group('options'))
    logging.debug(f'    Options: {options}')
    # Get and clean the list of examples and notes
    notes = text_to_list(match.group('notes'))
    logging.debug(f'    Notes: {notes}')
    # Construct the command dictionary
    command_data = {
        'command': command,
        'offline': offline,
        'description': description,
        'usage': usage,
        'options': options,
        'notes': notes
    }
    logging.info('Completed parsing command!')
    return command_data


def build_metadata(extra_data, command_data):
    """Turns the full text output of help data from the pm3 client into a list of dictionaries."""
    logging.info('Building metadata...')
    metadata = {
        'extracted_by': get_version(),
        'extracted_on': datetime.datetime.utcnow().replace(microsecond=0).isoformat(),
        'commands_extracted': len(command_data)
    }
    for key, value in metadata.items():
        logging.debug(f'    {key} - {value}')
    if extra_data:
        for extra in extra_data:
            parts = extra.split(':')
            if len(parts) == 2:
                metadata[parts[0]] = parts[1]
                logging.debug(f'    {parts[0]} - {parts[1]}')
            else:
                logging.warning(f'Error building metadata. '
                                f'Skipped "{extra}". '
                                f'Extra metadata must be in the format "key:value".')
    logging.info('Completed building metadata!')
    return metadata


##############################################################################
# Helper Functions:


def get_version():
    """Get the version string for this script"""
    return f'{APP_NAME} v{VERSION_MAJOR}.{VERSION_MINOR:02}'


def remove_ansi_escape_codes(text):
    """Remove ANSI escape sequences that may be left in the text."""
    re_ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return re_ansi_escape.sub('', str(text))


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
    if text is None:
        return ""
    # Ensure input is a string
    text = str(text)
    # Replace newlines with spaces
    text = re.sub(r'\n+', ' ', text)
    # Remove the extra whitespace
    text = remove_extra_whitespace(text)
    return text


def text_to_list(text):
    """Converts a multi line string into a list of lines and removes extra whitespace"""
    if text is None:
        return []
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
