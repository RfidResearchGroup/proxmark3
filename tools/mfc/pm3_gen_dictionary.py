#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pexpect
from colors import color
import re
import argparse
import os
import fnmatch

'''
# pm3_gen_dictionary.py
# Christian Herrmann, Iceman,  <iceman@icesql.se> 2023
# version = 'v1.0.0'
#
#  This code is copyright (c) Christian Herrmann, 2023, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#
# Dependencies:
#
# pip3 install pexpect ansicolors
#
# Usage:
#
# ./pm3_gen_dictionary.py --path folder --fn mydictionary.dic -v
#
# Info:
#   Will search all dump files files in given folder and all its subfolders
#   With the option to save found keys to a text file.
#
'''

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', str(line)).lower()

def parse_keys(line):
    """
    Parse keys from a line and return them as a set.
    Keys must be 12 hex characters long
    :param line: string containing keys.
    :return: A set of keys read from the line
    """
    keys = set()
    key_regex = re.compile('[0-9a-fA-F]{12}')

    key = key_regex.findall(line)
    if not key:
        return []

    try:
        keys.add(key[0])
        keys.add(key[1])
    except AttributeError:
        pass
    return keys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", help="Path to folder")
    parser.add_argument("--fn", help="Dictionary file name")
    parser.add_argument("-v", help="verbose output", action="store_true")
    args = parser.parse_args()

    path = args.path
    verbose = args.v
    # Check if the directory exists
    if not os.path.isdir(path):
        print("The provided directory does not exist.")
        return

    # start pm3
    child = pexpect.spawnu('./pm3 -o')
    i = child.expect('pm3 --> ')
    print("[+] Proxmark3 client open")


    # MIFARE CLASSIC dumps
    pattern = 'hf-mf-*-dump*'

    print(f'[+] Iterating all dumpfiles in... ', color(f'{path}', fg='cyan'))
    # Walk through the directory
    keys = set()
    for root, dirs, files in os.walk(path):
        for file in files:
            # Check if the file name starts with the given prefix
            if fnmatch.fnmatch(file, pattern):
                if ":Zone.Identifier" in file:
                    continue
                if ":OECustomProperty" in file:
                    continue

                f = os.path.join(root, file)
                cmd = f'hf mf view -v -f {f}'
                if verbose:
                    print(cmd)

                # Send proxmark3 commnad
                child.sendline(cmd)
                i = child.expect('pm3 --> ')
                msg = escape_ansi(str(child.before))

                # extract key table from msg
                found = False
                for line in msg.splitlines():

                    if found == False:
                        key_row = line.find('000 | 003')
                        if key_row > -1:
                            found = True

                    if found:
                        foo = parse_keys(line)
                        if not foo:
                            found = False
                            continue

                        # append found set
                        keys |= foo

    # shut down proxmark3 client connection
    child.sendline('quit')
    child.expect(pexpect.EOF)
    print("[+] Proxmark3 client closed")

    # print all found keys
    if verbose:
        for k in keys:
            print(f'{k}')
        print("")

    # save keys
    if args.fn:
        print(f'[+] Writing keys to dictionary file... ', color(f'{args.fn}', fg='cyan'))
        with open(args.fn, 'w') as f:
            for k in keys:
                f.write(f'{k}\n')

    return 0

if __name__ == "__main__":
    main()
