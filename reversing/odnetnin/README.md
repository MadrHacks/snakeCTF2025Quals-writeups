# Odnet Nin [_snakeCTF 2025 Quals_]

**Category**: Reversing
**Author**: rw-r-r-0644, EliusSolis

## Description

    I want to emulate a console called Odnet Nin but i need an internal secret key.
    Fortunately i know of a friend that owns a real console but it will only run signed games and third party games can't access the key.

    Can you help me?

## Analysis

The challenge is composed of two services, coderunner and codechecker. coderunner provides a simple emulator for a custom architecture, executing signed binaries in a custom packaging format; it includes a syscall (0x53) that will copy the flag to the vm memory. codechecker will sign any binary for coderunner, provided that it does not detect any call to syscall 0x53.  

We can start by reverse engineering `libminivm`. From `minivm_init`, we can find the size of the state struct and identify an area where syscall function pointers are located. From the call in `minivm_run`, we can identify the state stepping function and subsequently the code implementing individual instructions. It's a relatively simple 16-bit ISA with 16 identically sized 16-bit instructions. The opcode is identified by the first 4 bits of the instructions; the rest is decoded in three different ways (depending on the opcode group):

#### Type A: register-register operations
```
[15-12] [11-8] [7-4] [3-0]
 OPCODE   RD    RA   RB
```
#### Type B: memory operations
```
[15-12] [11-8] [7-4] [3-0]
 OPCODE   RD    RA   IMM4
```
#### Type C: register-immediate operations
```
[15-12] [11-8] [7-0]
 OPCODE   RD   IMM8
```

IDA and Ghidra will try (with varying degrees of success) to interpret the three instruction jump tables as switches. Type B and type C instructions often sign-extend IMM4 and IMM8 fields to larger bit widths; care must be taken to correctly interpret the resulting values. From opcodes 6 and 7, we can identify a state region accessed by memory instructions, separate from the instruction area; the VM has two separate 64 KiB address spaces for code and data.  

Eventually, the semantics of all of the 16 instructions can be reconstructed (for reference, see [ISA.md](./attachments/ISA.md)). With the information about the state struct gained while analysing the instructions, we can also explore the three default syscalls registered in `minivm_init`: syscall 1 terminates the program by setting a flag which stops the `minivm_run` loop, syscall 2 outputs the sign-extended register 0 content to stdout with putchar, and syscall 3 reads a character from stdin with getchar and stores it in register 0.  
  
Moving on to `libpkg`, we can identify three main functions referenced in coderunner and codechecker:
- `pkg_load`, which loads a pkg payload on a minivm
- `pkg_verify`, which verifies the pkg signature against a given public key
- `pkg_sign`, which signs a pkg with the provided private key
  
The struct of a pkg can be, for the most part, reconstructed from the simple `pkg_load` function: there's a 4-byte magic value (which must contain 'SNAK'), followed by two 16-bit words representing respectively the VM code length and data length, and (after a 276-byte space) finally the concatenated VM code and data memory contents.


## Solution
`codechecker` rejects a minivm program if an invocation of syscall 0x53 is detected during a simple test execution. While this could work for fully-deterministic programs, syscall 3 (`sys_getchar`) introduces an element of user-controlled variability (and while the code area cannot be modified during execution, `codechecker` does not attempt to statically analyse the binary).  

We can thus easily bypass the check by coding up a minivm program that will invoke syscall 0x53 only for certain user inputs (for instance, we can halt execution if the user inputs the char 'A', and print the flag for any other user input):  
```
payload_code = b""
payload_code += b"\xF0\x03"  # 0000: sys_getchar
payload_code += b"\xA0\xBF"  # 0002: addi r0, #-0x41
payload_code += b"\xD0\x01"  # 0004: bnz r0, +1*2 -> 0008
payload_code += b"\xF0\x01"  # 0006: sys_hlt
payload_code += b"\xF0\x53"  # 0008: sys_getSystemSecret
payload_code += b"\x83\xF8"  # 000A: li r3, #-8
payload_code += b"\x82\x02"  # 000C: li r2, #1
payload_code += b"\x60\x20"  # 0010: ldr r0, [r2]
payload_code += b"\x50\x03"  # 0012: shl r0, r0, r3
payload_code += b'\xD0\x01'  # 0014: bnz r0, +1*2 -> 0018
payload_code += b"\xF0\x01"  # 0016: sys_hlt
payload_code += b"\xF0\x02"  # 0018: sys_putchar
payload_code += b"\xA2\x01"  # 001A: addi r2, #1
payload_code += b"\xBF\xF9"  # 001C: b pc-7*2 -> 0010
```

`codechecker` will happily sign this program as long as we send the char 'A' as input to the program. We can then submit the signed program to `coderunner`, send a different input char to the program, and get the flag! [Here](./attachments/solve.py) is the full solver code.

## Solution 2
Fun fact: you can also solve this challenge _without_ `codechecker`!  

This was, in fact, the solution that we had originally planned for this challenge, though a mix of rushing, holidays, somewhat broken rewriting and poor communications eventually led to the flawed challenge release. Oh well. I guess there's a lesson for me in there somewhere ^^"  

If you want, you can have a go at it on your own!  
Otherwise, you can find the alternate solution [here](./attachments/spoiler_solve2.zip).
