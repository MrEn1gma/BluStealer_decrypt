# DECRYPT SHELLCODE 1
shc = bytes.fromhex(open("tkqkwwdb.r", "r").read().replace("6988001444", "")[2:])

# DECRYPT SHELLCODE 2
def malware101_decrypt_shellcode2(inp_shellcode):
    for j in range(len(inp_shellcode)):
        v33 = inp_shellcode[j]
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 - 73) & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = v33 ^ 0xD
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = v33 ^ j & 0xff
        v33 = v33 + j & 0xff
        v33 = ((4 * v33) | (v33 >> 6)) & 0xff
        v33 = v33 ^ 0xBE
        v33 = v33 + 54
        v33 = ~v33 & 0xff
        v33 = v33 + j & 0xff
        v33 = v33 ^ 0xCB
        v33 = ~v33 & 0xff
        v33 = v33 ^ j & 0xff
        v33 = v33 + j & 0xff
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 = (v33 - 43 & (2 ** 32 - 1)) & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 - 3) & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = ((v33 << 7) | (v33 >> 1)) & 0xff
        v33 = v33 + j & 0xff
        v33 = ~v33 & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 += 73
        v33 = v33 ^ j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 ^= 0xA2
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = v33 + j & 0xff
        v33 = ~v33 & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 ^= 0x43
        v33 = ((v33 - 3) & (2 ** 32 - 1)) & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 = v33 + j & 0xff
        v33 = ((32 * v33) | (v33 >> 3)) & 0xff
        v33 = ~v33 & 0xff
        v33 = v33 + j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ((2 * v33) | (v33 >> 7)) & 0xff
        v33 = ~v33 & 0xff
        v33 = ((v33 - 27) & (2 ** 32 - 1)) & 0xff
        v33 = ((2 * v33) | (v33 >> 7)) & 0xff
        v33 = v33 + j & 0xff
        v33 = v33 ^ j & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 = ((v33 - 78) & (2 ** 32 - 1)) & 0xff
        v33 ^= 0xFB
        v33 = v33 + j & 0xff
        v33 = ~v33 & 0xff
        v33 += 16
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = ((2 * v33) | (v33 >> 7)) & 0xff
        v33 += 60
        v33 ^= 0x23
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 = ~v33 & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = ~v33 & 0xff
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = v33 ^ j & 0xff
        v33 = v33 + j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = v33 + j & 0xff
        v33 = v33 ^ j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 = v33 + j & 0xff
        v33 = ~v33 & 0xff
        v33 = v33 ^ j & 0xff
        v33 = ((v33 << 6) | (v33 >> 2)) & 0xff
        v33 = ~v33 & 0xff
        v33 = v33 + j & 0xff
        v33 = (-v33 & (2 ** 32 - 1)) & 0xff
        v33 ^= 0x27
        v33 += 33
        v33 ^= 0x14
        v33 = ((v33 - j) & (2 ** 32 - 1)) & 0xff
        v33 = ((v33 << 7) | (v33 >> 1)) & 0xff
        v33 = ((v33 - 31) & (2 ** 32 - 1)) & 0xff
        inp_shellcode[j] = v33 & 0xff
    return inp_shellcode

with open("tkqkwwdb.shc", "wb") as fo:
    fo.write(bytearray(shc))
    
fo.close()

shc2 = [i for i in open("ydvtsmv.s", "rb").read()]
with open("shc2_decrypted.bin", "wb") as fo:
    fo.write(malware101_decrypt_shellcode2(bytearray(shc2)))
    
fo.close()
print("OK.")