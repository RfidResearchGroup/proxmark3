#!/usr/bin/env python3

"""
HITAG2 cipher
Implemented by Aram Verstegen
"""
import random

def i4(x, a, b, c, d):
    return (((x >> a) & 1)*8)+((x >> b) & 1)*4+((x >> c) & 1)*2+((x >> d) & 1)


def f20_4(state):
    return ((0x3c65 >> i4(state,34,43,44,46)) & 1)

def f20_3(state):
    return (( 0xee5 >> i4(state,28,29,31,33)) & 1)

def f20_2(state):
    return (( 0xee5 >> i4(state,17,21,23,26)) & 1)

def f20_1(state):
    return (( 0xee5 >> i4(state, 8,12,14,15)) & 1)

def f20_0(state):
    return ((0x3c65 >> i4(state, 2, 3, 5, 6)) & 1)

def f20_last(s0,s1,s2,s3,s4):
    return (0xdd3929b >> ((s0 * 16)
                        + (s1 *  8)
                        + (s2 *  4)
                        + (s3 *  2)
                        + (s4 *  1))) & 1

def f20(state):
    return f20_last(f20_0(state), f20_1(state), f20_2(state), f20_3(state), f20_4(state))

def lfsr_bs(state, i):
    return (state[i+ 0] ^ state[i+ 2] ^ state[i+ 3] ^ state[i+ 6] ^
            state[i+ 7] ^ state[i+ 8] ^ state[i+16] ^ state[i+22] ^
            state[i+23] ^ state[i+26] ^ state[i+30] ^ state[i+41] ^
            state[i+42] ^ state[i+43] ^ state[i+46] ^ state[i+47])

def f20a_bs(a,b,c,d):
    return (~(((a|b)&c)^(a|d)^b)) # 6 ops
def f20b_bs(a,b,c,d):
    return (~(((d|c)&(a^b))^(d|a|b))) # 7 ops
def f20c_bs(a,b,c,d,e):
    return (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c)))) # 13 ops

def filter_bs(state, i):
    return (f20c_bs( f20a_bs(state[i+ 2],state[i+ 3],state[i+ 5],state[i+ 6]),
                     f20b_bs(state[i+ 8],state[i+12],state[i+14],state[i+15]),
                     f20b_bs(state[i+17],state[i+21],state[i+23],state[i+26]),
                     f20b_bs(state[i+28],state[i+29],state[i+31],state[i+33]),
                     f20a_bs(state[i+34],state[i+43],state[i+44],state[i+46])))

def unbitslice(s, n):
    return int(''.join(map(str,map(int,map(bool,s[n:n+48])))[::-1]),2)

def hitag2_init(key, uid, nonce):
    state = 0
    for i in range(32, 48):
        state = (state << 1) | ((key >> i) & 1)
    for i in range(0, 32):
        state = (state << 1) | ((uid >> i) & 1)
    #print '%012x' % state
    #print '%012x' % (int("{0:048b}".format(state)[::-1],2))
    for i in range(0, 32):
        nonce_bit = (f20(state) ^ ((nonce >> (31 - i)) & 1))
        #print nonce_bit
        state = (state >> 1) | (((nonce_bit ^ (key >> (31 - i))) & 1) << 47)
    #print '%012x' % state
    #print '%012x' % (int("{0:048b}".format(state)[::-1],2))
    return state

def lfsr_feedback(state):
    return (((state >>  0) ^ (state >>  2) ^ (state >>  3)
            ^ (state >>  6) ^ (state >>  7) ^ (state >>  8)
            ^ (state >> 16) ^ (state >> 22) ^ (state >> 23)
            ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
            ^ (state >> 42) ^ (state >> 43) ^ (state >> 46)
            ^ (state >> 47)) & 1)

def lfsr(state):
    return (state >>  1) + (lfsr_feedback(state) << 47)

def lfsr_feedback_inv(state):
    return (((state >>  47) ^ (state >>  1) ^ (state >>  2)
            ^ (state >>  5) ^ (state >>  6) ^ (state >>  7)
            ^ (state >> 15) ^ (state >> 21) ^ (state >> 22)
            ^ (state >> 25) ^ (state >> 29) ^ (state >> 40)
            ^ (state >> 41) ^ (state >> 42) ^ (state >> 45)
            ^ (state >> 46)) & 1)

def lfsr_inv(state):
    return ((state <<  1) + (lfsr_feedback_inv(state))) & ((1 << 48) - 1)

def hitag2(state, length=48):
    c = 0
    for i in range(0, length):
        c = (c << 1) | f20(state)
        #print ('%012x' % state)
        state = lfsr(state)
        #print ('%012x' % (int("{0:048b}".format(state)[::-1],2)))
        #print('%08X %08X' % (c, state))
    #print('final: %08X %08X' % (c, state))
    return c

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 4:
        key = int(sys.argv[1], 16)
        uid = int(sys.argv[2], 16)
        n = int(sys.argv[3])
        for i in range(n):
            nonce = random.randrange(2**32)
            state = hitag2_init(key, uid, nonce)
            print('%08X %08X' % (nonce, hitag2(state, 32) ^ 0xffffffff))

    elif len(sys.argv) == 5:
        key = int(sys.argv[1], 16)
        uid = int(sys.argv[2], 16)
        n = int(sys.argv[3])
        for i in range(n):
            nonceA = random.randrange(2**32)
            stateA = hitag2_init(key, uid, nonceA)
            csA = hitag2(stateA, 32) ^ 0xffffffff
            # print('%08X %08X' % (nonceA, csA))

            nonceB = random.randrange(2**32)
            stateB = hitag2_init(key, uid, nonceB)
            csB = hitag2(stateB, 32) ^ 0xffffffff
            print('./ht2crack5opencl %08X %08X %08X %08X %08X' % (uid, nonceA, csA, nonceB, csB))
            print('lf hitag lookup --uid %08X --nr %08X --ar %08X --key %012X' % (uid, nonceA, csA, key))
    else:
        print("Usage: python %s <key> <uid> <nr of nRaR to generate>" % sys.argv[0])
