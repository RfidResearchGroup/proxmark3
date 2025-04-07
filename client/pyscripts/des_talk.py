"""
DES Talk - A Proxmark3 DESFire Communication Tool

Copyright (C) 2025 Trigat

Description:
This script simplifies the creation and deletion of
DESFire applications and files. It supports USB, Bluetooth,
and Termux connections and has been tested on Android and Linux.

Note: Modify TCP_PORT below if using TCP app with Android or Termux

License: GNU General Public License v3.0

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

Full license text: <https://www.gnu.org/licenses/gpl-3.0.html>
"""


import subprocess
import time
import sys
import os
import re

try:
    import pm3  # Used when inside the pm3 environment
    PM3_AVAILABLE = True
    p = pm3.pm3()
except ImportError:
    PM3_AVAILABLE = False  # Use subprocess instead

# SPECIFY PORT IF USING TCP APP WITH ANDROID OR TERMUX
TCP_PORT = 4444

def detect_proxmark_device():

    # Detect the Proxmark3 connection type (USB, Bluetooth, or TCP).
    try:
        # Try running `pm3 --list` to detect available Proxmark devices
        result = subprocess.run(["pm3", "--list"], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()

        for line in lines:
            if ":" in line:  # Expected format: "1: /dev/ttyACM0" or "1: bt:xx:xx:xx:xx:xx"
                device = line.split(": ", 1)[1].strip()
                print(f"✅ Using Proxmark device: {device}")
                return device
    except Exception:
        print("⚠️ `pm3 --list` failed, falling back to manual detection.")

    # If `pm3 --list` doesn't work, check manually (Android or fallback mode)
    usb_devices = ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0", "/dev/ttyUSB1"]
    for dev in usb_devices:
        if os.path.exists(dev):
            print(f"✅ Using USB device: {dev}")
            return dev

    # Default to TCP mode for Android Termux
    print(f"⚠️ No USB or Bluetooth device found, defaulting to TCP (localhost:{TCP_PORT})")
    return f"tcp:localhost:{TCP_PORT}"

def send_proxmark_command(command):

    if PM3_AVAILABLE:
        p.console(command)
        return p.grabbed_output.strip()

    else:
        full_command = f"{command}\n"
        host_device = detect_proxmark_device()

        process = subprocess.Popen(
            ["proxmark3", host_device],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output, error = process.communicate(full_command)

        time.sleep(0.2)  # Small delay to let Proxmark process fully

        # Combine stdout and stderr
        response_lines = (output or "").splitlines() + (error or "").splitlines()

        # Remove the harmless "STDIN unexpected end" message
        filtered_response = "\n".join(line for line in response_lines if "STDIN unexpected end" not in line)

        return filtered_response.strip()

def authenticate_and_menu():

    com_mode = input("Enter communication mode (PLAIN, MAC, ENCRYPT) (Default: PLAIN): ").strip() or "plain"
    key_type = input("Enter key type (DES, 2TDEA, 3TDEA, AES): ").strip()
    key = input("Enter 8, 16, or 24-byte hex key (no spaces): ").strip()

    # Authenticate
    auth_command = f"hf mfdes auth -t {key_type} -k {key} -m {com_mode}"
    auth_response = send_proxmark_command(auth_command)
    print(auth_response)
    # print("DEBUG: Raw Proxmark response:\n", repr(auth_response))

    # Check for Proxmark failure messages
    if "error" in auth_response.lower() or "must have" in auth_response.lower():
        print("❌ Authentication failed. Check your connection, mode, key type, and key.")
        return

    while True:
        # Get AIDs
        aids_command = f"hf mfdes getaids -n 0 -t {key_type} -k {key} -m {com_mode}"
        aids_response = send_proxmark_command(aids_command)

        # Check for communication mode errors
        com_mode_error_match = re.search(r"Wrong communication mode", aids_response)
        crc_error_match = re.search(r"CRC32 error", aids_response)
        if com_mode_error_match or crc_error_match:
            print("❌ Incorrect communication mode.\n")
            return

        print(aids_response)

        # Regex to match valid 6-character hex AIDs
        hex_pattern = re.compile(r"\b[0-9A-Fa-f]{6}\b")

        aids = []
        for line in aids_response.split("\n"):
            if "PM3 UART serial baudrate" in line:
                continue
            match = hex_pattern.search(line)
            if match:
                aids.append(match.group(0))

        if aids:  # Check if there are any AIDs
            print("\nAvailable AIDs:")
            for i, aid in enumerate(aids):
                print(f"{i + 1}. {aid}")
        else:
            print("\n❌ No AID found on the card.")

        print("\nChoose an option:")
        print("1. Select an AID")
        print("2. Create a new AID")
        print("3. Delete an AID")
        print("4. Format PICC")
        print("5. Show free memory")
        print("6. Change keys")
        print("7. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            selected_index = int(input("Select an available AID number (e.g., 1, 2, or 3): ")) - 1
            if selected_index < 0 or selected_index >= len(aids):
                print("\nInvalid selection.")
                continue

            selected_aid = aids[selected_index]
            print(f"\nSelecting AID: {selected_aid}")

            select_command = f"hf mfdes selectapp --aid {selected_aid} -t {key_type} -k {key} -m {com_mode}"
            select_response = send_proxmark_command(select_command)
            print(select_response)

            # Retrieve AID key 0
            aid_key_type = input(f"Enter AID encryption algorithm (DES, 2TDEA, 3TDEA, AES) (Default: {key_type.upper()}): ").strip() or key_type
            aid_key = input(f"Enter AID key (Default: {key}): ").strip() or key

            # Show file menu
            aid_file_menu(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)

        elif choice == "2":
            create_aid(key_type, key, com_mode)

        elif choice == "3":
            delete_aid(key_type, key, com_mode)

        elif choice == "4":
            format_picc(key_type, key, com_mode)

        elif choice == "5":
            free_memory(key_type, key, com_mode)

        elif choice == "6":
            change_key(key_type, key, com_mode)

        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

def aid_file_menu(selected_aid, key_type, key, com_mode, aid_key_type, aid_key):

    while True:
        print(f"\n[ AID {selected_aid} is open ]")
        print("\nChoose an operation:")
        print("1. List Files")
        print("2. Read a File")
        print("3. Create a File")
        print("4. Write to a File")
        print("5. Edit File Restrictions")
        print("6. Delete a File")
        print("7. Back")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            list_files(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "2":
            read_file(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "3":
            create_file(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "4":
            write_to_file(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "5":
            edit_file_restriction(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "6":
            delete_file(selected_aid, key_type, key, com_mode, aid_key_type, aid_key)
        elif choice == "7":
            print("Returning to AID selection...")
            break
        else:
            print("Invalid choice, please try again.")

def create_aid(key_type, key, com_mode):

    aid = input("Enter new AID (6 hex characters, e.g., 112233): ").strip()
    iso_fid = input("Enter ISO File ID (4 hex characters, e.g., 1234): ").strip()
    dstalgo = input(f"Enter encryption algorithm (DES, 2TDEA, 3TDEA, AES) (Default: {key_type.upper()}): ").strip() or key_type
    create_command = f"hf mfdes createapp -n 0 --aid {aid} --fid {iso_fid} --dstalgo {dstalgo} -t {key_type} -k {key} -m {com_mode} -a"
    response = send_proxmark_command(create_command)
    print(response)

def delete_aid(key_type, key, com_mode):

    aid = input("Enter AID to delete (6 hex characters): ").strip()
    delete_command = f"hf mfdes deleteapp --aid {aid} -n 0 -t {key_type} -k {key} -m {com_mode}"
    response = send_proxmark_command(delete_command)
    print(response)

def format_picc(key_type, key, com_mode):

    confirm = input("Are you sure you want to format the PICC? This will erase all data. (y/n): ").strip().lower()

    if confirm == "y":
        format_command = f"hf mfdes formatpicc -t {key_type} -k {key} -m {com_mode} -v"
        response = send_proxmark_command(format_command)
        print(response)
    elif confirm == "n":
        print("Formatting cancelled.")
    else:
        print("Invalid input. Please enter 'y' or 'n'.")

def free_memory(key_type, key, com_mode):

    memory_command = f"hf mfdes freemem -t {key_type} -k {key} -m {com_mode}"
    response = send_proxmark_command(memory_command)

    for line in response.splitlines():
        if "Free memory" in line:
            print(f"\n✅ {line}")
            return

    print("❌ Unable to retrieve free memory information.")

def change_key(key_type, key, com_mode):
    print("\nChange Key - Choose Target:")
    print("1. PICC (Card Master Key)")
    print("2. Application Key")

    target = input("Change key for (1/2)? (Default: 1): ").strip() or "1"
    aid = ""

    if target == "2":
        aid = input("Enter 6-digit AID (e.g., 010203): ").strip()

    print("\n!! Verify and securely store the new key !!")
    print("Key length guide:")
    print("  DES    : 8 bytes (16 hex chars)")
    print("  2TDEA  : 16 bytes (32 hex chars)")
    print("  3TDEA  : 24 bytes (48 hex chars)")
    print("  AES    : 16 bytes (32 hex chars)")

    newalgo = input(f"Enter new key encryption algorithm (DES, 2TDEA, 3TDEA, AES) "
                    f"(Default: {key_type.upper()}): ").strip() or key_type
    newkey = input(f"Enter new 8, 16, or 24-byte hex key (no spaces) (Default: {key}): ").strip() or key

    confirm = input("Are you sure you want to change the key? (Key 0) (y or n): ").strip().lower()

    if confirm == "y":
        changekey_command = f"hf mfdes changekey -n 0 -t {key_type} -k {key} -m {com_mode} " \
                            f"--newalgo {newalgo} --newkey {newkey} --newver 00 -v"
        if aid:
            app_key_type = input(f"Enter original application encryption algorithm (DES, 2TDEA, 3TDEA, AES) "
                             f"(Default: DES): ").strip() or "DES"
            app_key = input(f"Enter original application key "
                             f"(Default: 0000000000000000): ").strip() or "0000000000000000"
            changekey_command = f"hf mfdes changekey -n 0 -t {app_key_type} -k {app_key} -m {com_mode} " \
                                f"--newalgo {newalgo} --newkey {newkey} --newver 00 --aid {aid} -v"

        response = send_proxmark_command(changekey_command)
        print(response)
        print("\nReauthenticate with the master key.")
        sys.exit()

    elif confirm == "n":
        print("Cancelled.")
    else:
        print("Invalid input. Please enter 'y' or 'n'.")

def list_files(aid, key_type, key, com_mode, aid_key_type, aid_key):
    print("\nFetching file list...")
    command = f"hf mfdes getfileids --aid {aid} -t {aid_key_type} -k {aid_key} -m {com_mode}"
    response = send_proxmark_command(command)

    # Extract file IDs by looking for "File ID:" regex
    file_ids = []
    for line in response.splitlines():
        match = re.search(r"File ID:\s*([0-9A-Fa-f]{2})", line)
        if match:
            file_ids.append(match.group(1))

    if file_ids:
        print("\nAvailable File IDs:")
        for i, file_id in enumerate(file_ids, 1):
            print(f"{i}. {file_id}")
        return file_ids
    else:
        print("No files found in this AID.")
        return []

def read_file(aid, key_type, key, com_mode, aid_key_type, aid_key):

    file_id = input("Enter file ID to read: ").strip()

    # Get offset and ensure it's a 3-byte hex value (default: 000000)
    offset_input = input("Enter offset (default 0): ").strip() or "0"
    offset_hex = format(int(offset_input), '06X')  # Convert to 3-byte hex

    # Get length and ensure it's a 3-byte hex value (default: 000000 for full read)
    length_input = input("Enter length to read (e.g., 16 for 16 bytes, 64 for 64 bytes, default full read): ").strip() or "0"
    length_hex = format(int(length_input), '06X')  # Convert to 3-byte hex

    read_command = f"hf mfdes read --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} " \
                   f"--offset {offset_hex} --length {length_hex} -m {com_mode}"
    response = send_proxmark_command(read_command)

    # Extract and display file content
    print("\nFile Data:")
    for line in response.splitlines():
        if re.search(r"\| [0-9A-Fa-f]{2} .* \|", line):  # Matches data table format
            print(line)

    return response

def create_file(aid, key_type, key, com_mode, aid_key_type, aid_key):

    # Prompt for file ID in hex format
    file_id = input("Enter file ID (2 hex characters, e.g., 01, 02): ").strip()
    # Prompt for file size in KB, allowing for decimal values like 0.2KB
    file_size_kb_input = input("Enter file size in KB (e.g., .2 for 0.2KB, 1 for 1KB, 4 for 4KB, 16 for 16KB): ").strip()
    # Prefixes "00" to file_id for ISO file ID
    iso_file_id = f"00{file_id}"

    try:
        # Convert the input to a float
        file_size_kb = float(file_size_kb_input)

        if file_size_kb <= 0:
            raise ValueError("File size must be greater than 0.")

        # Convert KB to bytes (1 KB = 1024 bytes)
        file_size_bytes = int(file_size_kb * 1024)

        if file_size_bytes < 3:
            print("⚠️ File size is too small. Setting to minimum size of 3 bytes.")
            file_size_bytes = 3

        # Convert bytes to hexadecimal
        file_size_hex = format(file_size_bytes, 'X').upper().zfill(6)

        print(f"File size in bytes: {file_size_bytes} bytes")
        print(f"File size in hex: {file_size_hex}")

    except ValueError as e:
        print(f"Invalid file size: {e}")
        return

    create_command = f"hf mfdes createfile --aid {aid} --fid {file_id} --isofid {iso_file_id} " \
                     f"--size {file_size_hex} -t {aid_key_type} -k {aid_key} -m {com_mode}"
    response = send_proxmark_command(create_command)
    print(response)

def write_to_file(aid, key_type, key, com_mode, aid_key_type, aid_key):

    file_id = input("Enter file ID to write to: ").strip()

    # Get file size
    file_size_command = f"hf mfdes getfilesettings --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} -m {com_mode}"
    response = send_proxmark_command(file_size_command)

    # Extract the file size from the response
    file_size_match = re.search(r"File size \(bytes\)... (\d+) / 0x([0-9A-Fa-f]+)", response)
    if not file_size_match:
        print("❌ Unable to determine file size.")
        return

    file_size = int(file_size_match.group(1))  # Decimal file size

    print(f"✅ File size detected: {file_size} bytes")

    # Prompt user for data format choice (plain text or hex)
    while True:
        data_format = input("Enter data format (Type 1 for plain text, 2 for hex): ").strip()

        if data_format == "1":
            # Text input (no hex)
            write_data = input(f"Enter text to write (up to {file_size} bytes, no need for hex): ").strip()
            write_data_hex = write_data.encode().hex().upper()  # Convert to hex
            break

        elif data_format == "2":
            # Hex input
            write_data_hex = input(f"Enter hex data to write (up to {file_size * 2} hex chars): ").strip()
            if len(write_data_hex) % 2 != 0:  # Ensure it's a valid hex string
                print("❌ Invalid hex input. Please enter an even number of characters.")
            elif len(write_data_hex) // 2 > file_size:
                print(f"❌ Data exceeds file size limit of {file_size} bytes. Try again.")
            else:
                break
        else:
            print("❌ Invalid choice. Please choose 1 for text or 2 for hex.")

    write_command = f"hf mfdes write --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} -d {write_data_hex} -m {com_mode}"
    response = send_proxmark_command(write_command)
    print(response)

def edit_file_restriction(aid, key_type, key, com_mode, aid_key_type, aid_key):
    while True:
        print("\nNOTE: This only works if you have changed the default keys.")
        print("The Proxmark3 and other tools will automatically attempt to read files using DESFire default keys.")
        print("\nWould you like to apply or remove a key from the file?")
        print("1. Apply key 0 (Requires authentication for access)")
        print("2. Remove key (Make file freely accessible)")
        print("3. Back")

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == "3":
            print("Returning to the previous menu.")
            break

        file_id = input("Enter file ID to update: ").strip()

        if choice == "1":
            edit_file_command = f"hf mfdes chfilesettings --rawrights 0000 --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} -m {com_mode}"
            print("Applying key 0 for read, write, and change access. This ensures authentication is required to access the file.")

        elif choice == "2":
            # Must use encrypt communications mode to remove restrictions
            edit_file_command = f"hf mfdes chfilesettings --rawrights EEEE --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} -m encrypt"
            print("Removing key restrictions. File will be freely accessible.")

        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")
            continue

        response = send_proxmark_command(edit_file_command)
        print(response)
        break

def delete_file(aid, key_type, key, com_mode, aid_key_type, aid_key):

    file_id = input("Enter file ID to delete: ").strip()

    delete_command = f"hf mfdes deletefile --aid {aid} --fid {file_id} -t {aid_key_type} -k {aid_key} -m {com_mode}"
    response = send_proxmark_command(delete_command)
    print(response)

if __name__ == "__main__":
    authenticate_and_menu()
