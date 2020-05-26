
lrc= 0x00
for i in range(5):
    lrc ^= 42
print('\n final LRC XOR byte value: %02X\n' % (lrc))
