#!/usr/bin/env python3

"""
-----------------------------------------------------------------------------
Name: update_amiibo_tools_lua.py

Author: Cory Solovewicz

Description:
This is a python script to automate what the updating of the amiibo_tools.lua
file which holds a lua table of all known amiibos. Previously updating the
amiibo_tools.lua was a very manual process.

This script automates the following original command:
curl https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/amiibo.json | jq 'del(.amiibos[].release)' | jq 'del(.characters)' | pbcopy --> transform to table
And outputs the formatted file as amiibo_tools.lua
If everything goes well, this should be an updated copy of amiibo_tools.lua
which can then be placed in the /lualibs/ directory.
The temporary amiibo.json file is then deleted

Dependencies:
python3 -m pip install jq

How to run:
python update_amiibo_tools_lua.py
The script will create the file amiibo_tools.lua

After running, manually backup the original /lualibs/amiibo_tools.lua and move the
updated amiibo_tools.lua to the /lualibs/ directory.
-----------------------------------------------------------------------------
"""

import os
import re
import subprocess
import json
from jq import jq

def fetch_data():
    print("Fetching amiibo.json")
    # Perform the curl command
    curl_command = "curl https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/amiibo.json"
    curl_process = subprocess.Popen(curl_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = curl_process.communicate()

    if curl_process.returncode != 0:
        print("Error fetching data: ", error.decode())
        return None
    return output

def filter_data(data):
    print("Filtering downloaded data")
    # Convert the output to JSON and use jq to filter data
    data_json = json.loads(data)
    filtered_data_json = jq('del(.amiibos[].release) | del(.characters)').transform(data_json)
    # Convert the filtered JSON data back to a string, preserving Unicode characters
    filtered_data = json.dumps(filtered_data_json, indent=2, ensure_ascii=False)
    return filtered_data

def save_data(filtered_data, filename):
    # Save filtered data to file
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(filtered_data)
    print(f"Data saved to {filename}")

def process_file(filename):
    # Open the file
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read()

    # Perform the replacements
    data = data.replace('"name"', 'name')
    data = data.replace('"amiibo_series"', 'amiibo_series')
    data = data.replace('"amiibos"', 'amiibos')
    data = data.replace('"game_series"', 'game_series')
    data = data.replace('"types"', 'types')
    data = data.replace(':', ' =')
    data = re.sub('"0x', '["0x', data)
    data = re.sub('" =', '"] =', data)

    # Prepend the text
    prepend_text = 'local amiibo_tools = {}\n\n-- curl https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/amiibo.json | jq \'del(.amiibos[].release)\' | jq \'del(.characters)\' | pbcopy --> transform to table\namiibo_tools.db =\n'
    data = prepend_text + data

    # Append the text
    append_text = '\n\nreturn amiibo_tools\n'
    data = data + append_text

    return data

def write_to_file(data, filename):
    # Write the output
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(data)
    print(f"Output written to {filename}")

def delete_file(filename):
    try:
        os.remove(filename)
        print(f"Temporary file {filename} deleted")
    except OSError as e:
        print(f"Error deleting file {filename}: ", e)

def main():
    data = fetch_data()
    if data:
        filtered_data = filter_data(data)
        save_data(filtered_data, 'amiibo.json')
        processed_data = process_file('amiibo.json')
        write_to_file(processed_data, 'amiibo_tools.lua')
        delete_file('amiibo.json')

if __name__ == "__main__":
    main()
