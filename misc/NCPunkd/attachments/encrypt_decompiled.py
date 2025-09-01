# decompyle3 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.20 (default, Jul 10 2025, 18:09:32) 
# [GCC 15.1.1 20250425]
# Embedded file name: encrypt.py
# Compiled at: 2025-07-10 18:03:40
# Size of source mod 2**32: 2310 bytes
import sys, base64

def _0x4a2b1f(s): # Caesar cipher with a shift of 1
    r = []
    for c in s:
        r.append(chr(ord(c) + 1))

    return "".join(r)


def _0x7c8d3e(data): # Multi-byte XOR with a fixed key
    k = [
     66,26,127,51,142,33,148,87]
    a = []
    for (i, b) in enumerate(data):
        a.append(b ^ k[i % len(k)])

    return bytes(a)


def _0x9f1e2d(text): # 4x4 matrix transformation
    m = []
    for _ in range(4): # Initialize a 4x4 matrix
        row = []
        for _ in range(4):
            row.append(0)

        m.append(row)

    p = text + "\x00" * (16 - len(text) % 16) # Pad the text to a multiple of 16 bytes
    bs = []
    for i in range(0, len(p), 16): # Process each 16-byte block
        block = p[i:i + 16]
        for _0x8a1ed4 in range(4):
            for _0x2b5fd4 in range(4):
                m[_0x8a1ed4][_0x2b5fd4] = ord(block[_0x8a1ed4 * 4 + _0x2b5fd4])

        for _ in range(3): # Perform the transformation 3 times
            temp = m[0][0]
            m[0][0] = m[1][1]
            m[1][1] = m[2][2]
            m[2][2] = m[3][3]
            m[3][3] = temp
            for _0x8a1ed4 in range(4): # Shift each row to the left
                m[_0x8a1ed4] = m[_0x8a1ed4][1:] + [m[_0x8a1ed4][0]]

        br = []
        for _0x8a1ed4 in range(4): # Convert the matrix back to a byte array
            for _0x2b5fd4 in range(4):
                br.append(m[_0x8a1ed4][_0x2b5fd4])

        bs.append(bytes(br))

    return (b'').join(bs) # Join all blocks into a single byte string


class _0x5e3a7c: # Simple LCG with fixed parameters

    def __init__(self):
        self.x = 25214903917
        self.y = 11
        self.z = 281474976710656

    def _0x2f4e1b(self, s):
        self.x = s

    def _0x6d8c9a(self): # next rand num using x= (x * a + c) mod m
        self.x = self.x * 25214903917 + 11 & 281474976710655
        return self.x >> 16


def _0x3b9f2e(data, s): # Pseudo-random XOR operation using the LCG defined above
    _0x2fde4c = _0x5e3a7c()
    _0x2fde4c._0x2f4e1b(s)
    r = []
    for b in data:
        rand_val = _0x2fde4c._0x6d8c9a() & 255
        r.append(b ^ rand_val)

    return bytes(r)


def _0x3efde3(_0x5b9c2f): # main encryption function
    _0xfe093c = _0x4a2b1f(_0x5b9c2f) # apply Caesar cipher
    _0x4d22aa = _0xfe093c[::-1] # eeverse the string
    _0xc8b3f1 = _0x9f1e2d(_0x4d22aa) # apply the 4x4 matrix transformation
    _0x7e5a10 = _0x7c8d3e(_0xc8b3f1) # apply the multi-byte XOR
    s = len(_0x5b9c2f) * 1337 + ord(_0x5b9c2f[0]) * 42 # seed derived from length and first char ord
    _0x1d9b4e = _0x3b9f2e(_0x7e5a10, s) # pseudo-random XOR using LCG and seed
    final = base64.b64encode(_0x1d9b4e).decode() # final encoding to base64
    print(f"Encrypted: {final}")
    return final


def main():
    if len(sys.argv) != 2:
        sys.exit(1)
    _0x3efde3(sys.argv[1])


if __name__ == "__main__":
    main()

# okay decompiling encrypt.pyc
