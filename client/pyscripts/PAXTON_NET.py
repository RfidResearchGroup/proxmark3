# Author - Jareckib
# Based on Equipter's tutorial - Downgrade Paxton Net to EM410x
import sys
def hex_to_bin(hex_string):
    return ''.join(format(byte, '08b') for byte in bytearray.fromhex(hex_string))
def remove_last_two_bits(binary_str):
    return binary_str[:-2]
def split_into_5bit_chunks(binary_str):
    return [binary_str[i:i+5] for i in range(0, len(binary_str), 5)]
def remove_parity_bit(chunks):
    return [chunk[1:] for chunk in chunks if len(chunk) == 5]
def convert_to_hex(chunks):
    return [format(int(chunk, 2), 'X') for chunk in chunks]
def find_until_before_f(hex_values):
    result = []
    for value in hex_values:
        if value == 'F':
            break
        result.append(value)
    return result
def process_block(block):
    binary_str = hex_to_bin(block)
    binary_str = remove_last_two_bits(binary_str)
    chunks = split_into_5bit_chunks(binary_str)
    no_parity_chunks = remove_parity_bit(chunks)
    hex_values = convert_to_hex(no_parity_chunks)
    return hex_values
def calculate_id(blocks):
    all_hex_values = []
    for block in blocks:
        hex_values = process_block(block)
        all_hex_values.extend(hex_values)
    selected_hex_values = find_until_before_f(all_hex_values)
    if not selected_hex_values:
        raise ValueError("Error: No valid data found in blocks 4 and 5.")
    combined_hex = ''.join(selected_hex_values)
    if not combined_hex.isdigit():
        raise ValueError("Error: Invalid data in blocks 4 and 5.")
    decimal_id = int(combined_hex)
    stripped_hex_id = format(decimal_id, 'X').upper()
    padded_hex_id = stripped_hex_id.zfill(10)
    return combined_hex, decimal_id, stripped_hex_id, padded_hex_id
def input_block_data(block_number):
    while True:
        block_data = input("Enter data for block {} (4 bytes in hex): ".format(block_number)).strip()
        if len(block_data) != 8 or not all(c in '0123456789abcdefABCDEF' for c in block_data):
            print("Error: Data must be 4 bytes (8 characters) in hex. Try again.")
        else:
            return block_data
block_4 = input_block_data(4)
block_5 = input_block_data(5)

# Check if the second nibble of the second byte in block 5 is 'F'
if block_5[3] != 'F' and block_5[3] != 'f':
    print("This is not a Paxton Net2")
    sys.exit()

blocks = [
    block_4,
    block_5,
]
try:
    result_hex, result_decimal, stripped_hex_id, padded_hex_id = calculate_id(blocks)
    print('Calculations for block 4 and block 5:')
    print('Result (Net2 ID - decimal): {}'.format(result_decimal))
    print('Result (Net2 ID - hex): {}'.format(padded_hex_id))
    print('Use the following command in Proxmark3: lf em 410x clone --id {}'.format(padded_hex_id))
except ValueError as e:
    print(e)