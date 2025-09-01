#!/usr/bin/env python3

from pwn import *
from base64 import b64encode


host = args.HOST if args.HOST else "localhost"
port = args.PORT if args.PORT else 1337
ssl = args.SSL if args.SSL else None
team_token = args.TOKEN if args.TOKEN else None

io = remote(host, port, ssl=ssl)
if team_token:
    io.sendlineafter(b"enter your team token: ", team_token.encode())

exploit = b64encode(open("./solve.js", "rb").read())

io.sendlineafter(b"exploit: ", exploit)
io.interactive()
