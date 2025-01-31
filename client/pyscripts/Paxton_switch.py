# Author - jareckib
# Based on Equipter's tutorial - Downgrade Paxton Switch2 to EM410x
import sys
def hex_to_bin(hex_string):
    return ''.join(format(byte, '08b') for byte in bytearray.fromhex(hex_string))
def remove_last_two_bits(binary_str):
    return binary_str[:-2]
def split_into_5bit_chunks(binary_str):
    return [binary_str[i:i+5] for i in range(0, len(binary_str), 5)]
def remove_parity_bit(chunks):
    return [chunk[1:] for chunk in chunks if len(chunk) == 5]
def convert_to_decimal(chunks):
    return [int(chunk, 2) for chunk in chunks]
def process_block(block):
    binary_str = hex_to_bin(block)
    binary_str = remove_last_two_bits(binary_str)
    chunks = split_into_5bit_chunks(binary_str)
    no_parity_chunks = remove_parity_bit(chunks)
    decimal_values = convert_to_decimal(no_parity_chunks)
    return decimal_values
def calculate_id(blocks):
    all_decimal_values = []
    for block in blocks:
        decimal_values = process_block(block)
        all_decimal_values.extend(decimal_values)
    if len(all_decimal_values) < 15:
        raise ValueError("Error: Not enough data after processing blocks 4, 5, 6, and 7.")
    id_positions = [9, 11, 13, 15, 2, 4, 6, 8]
    id_numbers = [all_decimal_values[pos-1] for pos in id_positions]
    decimal_id = int(''.join(map(str, id_numbers)))
    padded_hex_id = format(decimal_id, 'X').upper().zfill(10)
    return decimal_id, padded_hex_id
def input_block_data(block_number):
    while True:
        block_data = input("Enter data for block {} (4 bytes in hex): ".format(block_number)).strip()
        if len(block_data) != 8 or not all(c in '0123456789abcdefABCDEF' for c in block_data):
            print("Error: Data must be 4 bytes (8 characters) in hex. Try again.")
        else:
            return block_data
block_4 = input_block_data(4)
block_5 = input_block_data(5)
block_6 = input_block_data(6)
block_7 = input_block_data(7)
blocks = [
    block_4,
    block_5,
    block_6,
    block_7,
]
try:
    decimal_id, padded_hex_id = calculate_id(blocks)
    print('Calculated data from blocks 4, 5, 6, 7:')
    print('Switch2 ID - decimal: {}'.format(decimal_id))
    print('Switch2 ID - hex: {}'.format(padded_hex_id))
    print('Use the following command in Proxmark3: lf em 410x clone --id {}'.format(padded_hex_id))
except ValueError as e:
    print(e)