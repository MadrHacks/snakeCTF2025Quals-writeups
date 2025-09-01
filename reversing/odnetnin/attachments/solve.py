from pwn import *
import base64

# VM payload
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

payload_data = b""

payload = payload_code + payload_data

# make pkg header
hdr = b"SNAK"
hdr += p16(len(payload_code))
hdr += p16(len(payload_data))
hdr += hashlib.sha1(payload).digest()

pkg = hdr + bytes(256) + payload

base64_pkg = base64.b64encode(pkg)
print('exploit pkg:', base64_pkg.decode())
