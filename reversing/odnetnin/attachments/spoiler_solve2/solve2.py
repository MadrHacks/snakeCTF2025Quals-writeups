#!/usr/bin/env python3
import random
from pwn import *
import base64
import hashlib

# generate spoof signature
N = 0xc22b661e87384e674547040b2f320b27a5b446e9a969dd6f0f9e13cb7c01a1c2f893a6b2e5ba39bb496ccdf785293d43c7c4a68980fad987f2203aa934d0a7ac226712e5b7572b7ed6092025b346c9cb3367bac1be68eeb1db02b1f66e0234bdafbd1953fd77315105a0718d2b67fde574a6b54e1cc15ad3800083f35c512ea900a261cd991db4c8e3c23381774814d065b990c15146b109ea53d0b9114403be1337b18b18023bbce9559cd7ca9b13b305fff9f9a4cd2488161750fce34f5398a039462f2bd168b231b5dcc8f7b10a36dec2a777c1bc4eab446dbe73bad2945257063ef960d42dfb57dd5ec2fb1b7abe3b07743e7b9cc08b955a5250b0c2e353
e = 0x10001

print("searching fake signature...")
while True:
    sig = random.randint(2, N - 1)
    dec_int = pow(sig, e, N)
    dec = dec_int.to_bytes(2048 // 8)

    if dec[0] != 0x00 or dec[1] != 0x02:
        continue

    for i in range(2, len(dec)):
        if dec[i] == 0:
            break
    else:
        print("found!")
        break
print("sig:", hex(sig))

# VM payload
payload_code = b""
payload_code += b"\xf0\x53"  # sys_getSystemSecret
payload_code += b"\x83\xf8"  # li r3, #-8
payload_code += b"\x82\x02"  # li r2, #1
payload_code += b"\x81\x40"  # li r1, #25
payload_code += b"\x60\x20"  # ldr r0, [r2]
payload_code += b"\x50\x03"  # shl r0, r0, r3
payload_code += b"\xf0\x02"  # sys_putchar
payload_code += b"\xa2\x01"  # addi r2, #1
payload_code += b"\xa1\xff"  # addi r1, #-1
payload_code += b"\xd1\xfa"  # bnz r1, $-6
payload_code += b"\xf0\x01"  # sys_halt

payload_data = b""

payload = payload_code + payload_data
assert b"\x00" not in payload

# make pkg header
hdr = b"SNAK"
hdr += p16(len(payload_code))
hdr += p16(len(payload_data))
hdr += hashlib.sha1(payload).digest()

# make fake decrypted ASN.1 block
fake_asn1 = bytes.fromhex('3021300906052b0e03021a05000414') # ASN.1 SHA1
fake_asn1 += hashlib.sha1(hdr).digest()  # SHA1 digest

# generate final pkg
pkg = hdr
pkg += sig.to_bytes(2048 // 8, "big")
pkg += payload
pkg += b"\x00"
pkg += fake_asn1

# print base64 encoded payload
base64_payload = base64.b64encode(pkg)
print("exploit pkg:", base64_payload.decode())


r = remote(args.HOST, args.PORT, ssl=args.SSL)
r.sendlineafter(b"pkg", base64_payload)
print(r.recvuntil(b"ended").decode())
