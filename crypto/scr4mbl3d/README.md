# Scr4mbl3d [_snakeCTF 2025 Quals_]

**Category**: Crypto

## Description

I like to confuse people. (Or I'm the one confused?)

## Solution

The challenge consists in a custom cipher made voluntarily confusing with uselessy-complex operations mixed with non-invertible ones (like hashing), to purposely give the idea to the person solving it that it cannot be inverted.
However, the cipher is based on the Feistel structure which is invertible independently of the operations used inside, thus the *flag* can be recovered just by doing the operations backwards, obtaining back the plaintext.

[Here](./attachments/solve.py) is the solver code.
