#!/usr/bin/env python3

import sys
from os import path
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
EXPONENT = 3


def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2


def merge(chunk1, chunk2):
    return chunk1 * P + chunk2


def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P


def gg(x):
    digest = sha256(int(x).to_bytes(256)).digest()
    return int.from_bytes(digest) % P


def transformInv(yL, yR, cons, i):
    xL = yR
    if i % 11 == 0:
        xR = (yL - ff(xL)) % P
    else:
        xR = (yL - gg(xL)) % P
    xR = (xR - cons[i]) % P
    return xL, xR


def decrypt(output, rounds):
    cons = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(rounds)]
    yL, yR = split(output)
    for i in range(rounds - 1, -1, -1):
        if i % 5 == 0:
            yL, yR = transformInv(yL, yR, cons, i)
        else:
            yR, yL = transformInv(yR, yL, cons, i)
    input = merge(yL, yR)
    return input


if __name__ == "__main__":
    out_dir = sys.argv[1]
    with open(path.join(out_dir, "out.txt"), "r") as f:
        ciphertext = eval(f.readline())

    for rounds in range(26, 54):
        recovered = decrypt(ciphertext, rounds)
        flag = recovered.to_bytes(64)
        if b"snakeCTF{" in flag:
            print(flag.decode())
            break
