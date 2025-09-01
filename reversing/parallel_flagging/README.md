# Parallel Flagging [_snakeCTF 2025 Quals_]

**Category**: reversing

## Description

The best way to encrypt a flag is to encrypt all of it at the same time, no?

## Solution

By reversing the main function it can be seen that:

- the input is padded to 256 bytes with '-'
- is divided in blocks of 32 bytes
- each block is passed to a function "kernel" with an 8 bytes key taken from _env_

There is no need to reverse the function kernel since it's easy to understand that it's a xor + scramble by testing with different inputs. We can obtain the key knowing that the flag must start with snakeCTF.

Once we have the xor stream just xoring the output from _output.txt_ gives us the flag.

[Here](./attachments/solve.py) is the solver code.

