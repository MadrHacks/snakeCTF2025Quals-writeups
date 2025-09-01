#!/usr/bin/env python3
import os

import numpy as np
import sys

path = sys.argv[1]
scramble_map = [15, 21, 2, 18, 6, 27, 7, 17, 13, 24, 26, 4, 29, 16, 20, 5, 22, 31, 11, 10, 12, 28, 3, 19, 14, 30, 8, 25,
                1, 0, 23, 9]

inverse_scramble = [0] * 32
for i, v in enumerate(scramble_map):
    inverse_scramble[v] = i


def unscramble_block(block_data, block_id, key):
    scrambled = np.array(list(block_data), dtype=np.uint8)
    shared_data = np.zeros(32, dtype=np.uint8)

    for i in range(32):
        shared_data[i] = scrambled[inverse_scramble[i]]

    mod_block = block_id ^ 17
    for i in range(32):
        shared_data[i] ^= ord(key[(block_id + i + (7 * mod_block)) % 8])

    return shared_data


def hex_to_bytes(hex_string):
    hex_values = hex_string.strip().split()
    return np.array([int(byte, 16) for byte in hex_values], dtype=np.uint8)


def main():
    positions = [29, 28, 2, 22, 11, 15, 4, 6]
    format = b"snakeCTF"

    # Read hex from file
    with open(os.path.join(path, 'output.txt'), "r") as f:
        hex_string = f.read()

    data = hex_to_bytes(hex_string)
    assert len(data) == 256

    key = ''.join([chr(data[positions[i]] ^ format[i]) for i in range(8)])

    key = key[1:] + key[0]  # (for block 0 the key index is +7)

    print(key)

    num_blocks = 8
    block_size = 32

    original_data = np.zeros_like(data)

    for block_id in range(num_blocks):
        start = block_id * block_size
        end = start + block_size
        block = data[start:end]
        unscrambled_block = unscramble_block(block, block_id, key)
        original_data[start:end] = unscrambled_block

    # Convert bytes to string and strip padding
    original_str = ''.join(chr(b) for b in original_data).rstrip('-')
    print(original_str)


if __name__ == "__main__":
    main()
