#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to convert amiibo nfc Flipper Zero files to eml files to be used with Proxmark3
Date: 18/05/2023
Script Author: OscarAkaElvis
Tested on: Linux and Windows
OscarAkaElvis - https://twitter.com/OscarAkaElvis
"""

import re
import argparse
import os
from os import path
from sys import argv

# Vars
script_name = path.basename(argv[0])
script_version = "1.0"

# Function to print script's version
def print_version():
    print()
    return 'v{}'.format(script_version)

# Check if the input file is a text file based on its content
def is_text_file(file_path):
    with open(file_path, 'rb') as file:
        try:
            file_content = file.read().decode('utf-8')
            return all(ord(char) < 128 for char in file_content)
        except UnicodeDecodeError:
            return False

# Main script code
def main():
    # Text help data
    description_text = "Script to convert amiibo nfc Flipper Zero files to eml files to be used with Proxmark3."
    epilog_text = 'Example:\n    python3 ' + script_name + ' -i file.nfc -o output.eml'

    # Create an argument parser
    parser = argparse.ArgumentParser(exit_on_error=False, description=description_text, formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog_text)
    # Add the input file argument
    parser.add_argument("-i", "--input", required=True, help="Path to the input nfc file.")
    # Add the output file argument
    parser.add_argument("-o", "--output", required=True, help="Name of the output eml file.")
    # Add the version argument
    parser.add_argument('-v', '--version', action='version', version=print_version(), help="Show script's version number and exit")

    # Parse the command-line arguments

    args = parser.parse_args()

    # Extract the file paths from the command-line arguments
    file_path = args.input
    output_file = args.output

    # Check if the target file exists
    if not os.path.isfile(file_path):
        print(f"[!] The input file '{file_path}' does not exist.")
        exit(0)

    # Validation to check if the input file is a text file based on its content
    if not is_text_file(file_path):
        print("[!] The input file does not appear to be a nfc text file.")

    # Check if the input file name has the .nfc extension
    if not file_path.lower().endswith('.nfc'):
        print("[+] Warning. The input file should have the '.nfc' extension.")

    # Get the absolute path of the output file
    output_file_path = os.path.abspath(output_file)

    # Check if the directory of the output file is writable
    output_dir = os.path.dirname(output_file_path)
    if not os.access(output_dir, os.W_OK):
        print(f"[!] The output directory '{output_dir}' is not writable or doesn't exist.")

    # Check if the output file name has the .eml extension
    if not output_file.lower().endswith('.eml'):
        print("[+] Warning. The output file should have the '.eml' extension.")

    # Read the target file
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Extract the data from each "Page X" line
    matches = re.findall(r'Page \d+:(.*?)$', file_content, re.MULTILINE | re.DOTALL)

    if matches:
        # Remove spaces and convert to lowercase for each match
        extracted_data = [re.sub(r'\s', '', match).lower() for match in matches]

        # Join the extracted data with line feeds
        result = '\n'.join(extracted_data)

        # Write the extracted data to the output file
        with open(output_file_path, 'w', newline='\n') as output_file:
            output_file.write(result)
            print(f"[*] File converted successfully. Output eml file written as '{os.path.basename(output_file.name)}'.")
    else:
        # If the needed data is not there
        print("[!] Provided input file seems to not be a valid nfc file to work with.")

# Application entrypoint
if __name__ == '__main__':
    try:
        main()
    except:
        pass

