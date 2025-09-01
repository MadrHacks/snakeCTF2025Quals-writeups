from pwn import *

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL

if __name__ == '__main__':
    io = remote(HOST, PORT, ssl=SSL)
    pts = [b'aa'*16] * 2
    io.sendlineafter(b'hex): ', b''.join(pts))
    io.recvuntil(b'hex): ')
    res = io.recvline(False).decode()

    solver = process(['./solver', res])
    token = solver.recvline(False).decode()

    io.sendlineafter(b'guess: ', token.encode())
    io.recvuntil(b'flag: ')
    print(io.recvline(False).decode())