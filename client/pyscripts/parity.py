# This code is contributed by
# Shubham Singh(SHUBHAMSINGH10)
# 2020, modified (@iceman1001)

import sys

# Python3 program to illustrate Compute the
# parity of a number using XOR
# Generating the look-up table while pre-processing
def P2(n, table):
    table.extend([n, n ^ 1, n ^ 1, n])
def P4(n, table):
    return (P2(n, table), P2(n ^ 1, table),
            P2(n ^ 1, table), P2(n, table))
def P6(n, table):
    return (P4(n, table), P4(n ^ 1, table),
            P4(n ^ 1, table), P4(n, table))
def LOOK_UP(table):
    return (P6(0, table), P6(1, table),
            P6(1, table), P6(0, table))

# LOOK_UP is the macro expansion to generate the table
table = [0] * 256
LOOK_UP(table)

# Function to find the parity
def Parity(num) :
    # Number is considered to be of 32 bits
    max = 16

    # Dividing the number o 8-bit
    # chunks while performing X-OR
    while (max >= 8):
        num = num ^ (num >> max)
        max = max // 2

    # Masking the number with 0xff (11111111)
    # to produce valid 8-bit result
    return table[num & 0xff]

def main():
    if(len(sys.argv) < 2):
        print("""
    \t{0} - Calculate parity of a given number

    Usage: {0} <2,10,16> <number>

    \t Specify type as in 2 Bin, 10 Decimal, 16 Hex, and  number in that particular format
    \t number can only be 32bit long.

    Example:

    \t{0} 10 1234

    Should produce the output:

    \tOdd parity\n""".format(sys.argv[0]))
        return 0


    numtype=  int(sys.argv[1], 10)
    print("numtype: {0}".format(numtype))
    input= int(sys.argv[2], numtype)
    print("num: {0} 0x{0:X}".format(input))

    #num = "001111100010100011101010111101011110"
    # Result is 1 for odd parity
    # 0 for even parity
#    result = Parity( int(input, numtype) )
    result = Parity(input)
    print("Odd parity") if result else print("Even parity")


if __name__ == "__main__":
    main()



