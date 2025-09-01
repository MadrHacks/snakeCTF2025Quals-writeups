# Trusted [_snakeCTF 2025 Quals_]

**Category**: pwn
**Author**: c0mm4nd_

## Description

Yet another shellcode runner

Please note that the contents of `default_progs` and `public.pem` (and consequently of `private.pem`) are different on remote

## Solution

The challenge allows the creation and execution of "programs" which can be either decrypted, encrypted or signed and encrypted. The main gimmick is that both normal encrypted and decrypted programs are ran under a seccomp sandbox restrincting the available syscalls to the bare minimum. Signed encrypted programs run without this restriction, but it's not possible for the user to load them as it does not have the required private key to generate the signature.

Three example programs, one for each category are loaded at startup, although they are not distributed to the players.

The main vulnerability lies in the Keystore class, as the way it handles the storage for the AES keys can lead to an integer overflow, eventually causing previous keys to be overwritten.

Due to the fact that the signature validation on signed programs happens before decryption, it is possible to change a signed program's key to change its code without invalidating its signature.

Through trial and error, it is possible to brute the key such that two bytes in two different offset of a block are set to specific bytes.

Of course doing this requires a loaded signed-encrypted program and knowledge of its encrypted content. The challenge already loads a valid signed-encrypted program at startup, and for leaking its contents it is possible to exploit the fact that FDs aren't closed when running the other kinds of program under the sandbox, so it is possible to just `write` the encrypted code of the signed-encrypted program.

As for the brute, a good candidate is forcing a 4-byte relative jump instruction. Chaining this with the fact that trying to run a signed-encrypted without it being validated still makes its mapping executable, and that programs are loaded through `mmap` (which is deterministic), it is possible to jump to arbitrary code.

Please check out [solve.py](attachments/solve.py) for further details.
