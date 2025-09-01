#!/usr/bin/env python3
import sys
import base64

def reverse_caesar(s): # reverse the +1 Caesar cipher
    return ''.join(chr(ord(c) - 1) for c in s)

def reverse_xor_key(data): # reverse the multi-byte XOR with fixed key
    k = [0x42, 0x1a, 0x7f, 0x33, 0x8e, 0x21, 0x94, 0x57]
    result = []
    for i, b in enumerate(data):
        result.append(b ^ k[i % len(k)])
    return bytes(result)

def reverse_matrix_transform(data): # reverse the 4x4 matrix transformation
    result = []
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        matrix = [[0 for _ in range(4)] for _ in range(4)] # rebuild from block
        for row in range(4):
            for col in range(4):
                matrix[row][col] = block[row*4 + col]
        for _ in range(3): # reverse the 3 iterations
            # shift right instead of left
            for row in range(4):
                matrix[row] = [matrix[row][-1]] + matrix[row][:-1]
            # reverse diagonal rotation
            temp = matrix[3][3]
            matrix[3][3] = matrix[2][2]
            matrix[2][2] = matrix[1][1]
            matrix[1][1] = matrix[0][0]
            matrix[0][0] = temp
        # convert back to bytes
        block_result = []
        for row in range(4):
            for col in range(4):
                block_result.append(matrix[row][col])
        result.extend(block_result)
    return bytes(result)

class ReverseLCG: # simple LCG with fixed parameters
    def __init__(self):
        self.x = 0x5DEECE66D
        self.y = 0xB
        self.z = 0x1000000000000
        
    def seed(self, seed_val):
        self.x = seed_val
        
    def next_rand(self):
        self.x = (self.x * 0x5DEECE66D + 0xB) & 0xFFFFFFFFFFFF
        return self.x >> 16

def reverse_random_xor(data, seed): # reverse the pseudo-random XOR
    rng = ReverseLCG()
    rng.seed(seed)
    result = []
    for b in data:
        rand_val = rng.next_rand() & 0xFF
        result.append(b ^ rand_val)
    return bytes(result)

def decrypt(encrypted_b64): # decrypt the given base64-encoded string
    print("Attempting to decrypt:", encrypted_b64)
    # decode base64
    try:
        stage5_data = base64.b64decode(encrypted_b64)
    except:
        print("Invalid base64!")
        return None
    # try different combinations of length and first character
    for length in range(1, 60):  # reasonable length range
        for first_char_ord in range(32, 127):  # printable ASCII
            try:
                # calculate seed like in original
                seed = length * 1337 + first_char_ord * 42
                stage4_data = reverse_random_xor(stage5_data, seed)
                stage3_data = reverse_xor_key(stage4_data)
                stage2_data = reverse_matrix_transform(stage3_data)
                stage2_str = stage2_data.decode().rstrip('\x00')
                stage1_str = stage2_str[::-1]
                plaintext = reverse_caesar(stage1_str)
                # check if result makes sense
                if len(plaintext) == length and ord(plaintext[0]) == first_char_ord:
                    # additional validation: check if it's printable
                    if all(32 <= ord(c) <= 126 for c in plaintext):
                        print(f"Found valid plaintext: {plaintext}")
                        return plaintext
            except Exception as e:
                continue
    print("Could not decrypt, no valid plaintext found")
    return None

def main():
    if len(sys.argv) != 2:
        sys.exit(1)
    encrypted = sys.argv[1]
    result = decrypt(encrypted)
    if not result:
        print("Decryption failed.")

if __name__ == "__main__":
    main()