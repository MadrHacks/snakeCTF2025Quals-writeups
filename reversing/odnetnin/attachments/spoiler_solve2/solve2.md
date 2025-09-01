## Analysis 2
As you might've noticed, there's in fact a fairly significant part of libpkg that has so far been missing from our analysis: that is, package signatures! The library suspiciously opted to implement RSA PKCS#1.5 padding and ASN.1 DER parsing on its own.  
  
The package signature scheme implemented by libpkg is fairly straightforward. The first part of the binary is a 28-byte pkg header, composed of:  
`[ magic : 4 ] [ code_len : 2 ] [ data_len : 2 ] [ payload_sha1 : 20 ]`

Following the pkg header, there's a 256-byte RSA2048 signature of the pkg header SHA1 hash. After the pkg header, there's the payload composed of minivm code and data area contents. The final binary is thus of the following form:  
`[ pkg_header : 28 ] [ pkg_signature : 256 ] [ pkg_payload ]`

In theory, as long as the RSA2048 signature is properly validated, it should not be possible to modify either the pkg header or the payload (due to the pkg header's `payload_sha1` field).

To verify a package, libpkg first computes the SHA1 checksum of the pkg header. The RSA2048 signature is decrypted in place; libpkg then validates and skips the PKCS#1.5 padding. Finally, the correct header SHA1 sequence is extracted from the DER ASN.1, and compared with the computed pkg header checksum.  
Once the pkg header is successfully validated, the pkg payload SHA1 is also validated against the correct SHA1 saved in the pkg header.

## Solution 2
There's a flaw in the PKCS#1.5 unpadding and the ASN.1 DER parsing implementations: they are both completely devoid of any kind of bounds checking!  
Moreover, the PKCS#1.5 implementation will accept padding mode 2 (any number of non-zero bytes, followed by 0x00), which should not be used for signatures (which are expected to use padding mode 1: any number of 0xFF bytes followed by 0x00).  
  
The combination of these two issues allows us to completely bypass the RSA2048 signature verification implemented in pkg_verify.
We achieve this by constructing an RSA signature that decrypts to the following form:

`0x00 0x02 [254 non-zero bytes]`

This can be done through simple brute-force, as any random signature has probability of about 1/256 * 1/256 * (255/256)**254 of matching the expected format (usually less than 200k attempts are necessary).  

The first two bytes identify PKCS#1.5 mode 2, whereas the rest of the signature is considered padding. PKCS#1.5 unpadding will skip all of the 254 non-zero bytes of the signature and keep going well outside of the `pkg_signature` area until it eventually stumbles upon a 0x00 byte; ASN.1 DER parsing will start at that offet.  

With such a signature, we can craft a valid package as follows:
```python
payload = payload_code + payload_data
assert b'\x00' not in payload

hdr = b'SNAK' + p16(len(payload_code)) + p16(len(payload_data)) + sha1(payload)
fake_asn1 = bytes.fromehex('3021300906052b0e03021a05000414') + sha1(hdr)
pkg = hdr + evil_sig + payload + b'\x00' + fake_asn1
```

Note that the crafted `fake_asn1` is placed after, rather than inside of, the payload: this is because it contains the SHA1 of the header, which depends on the SHA1 of the payload itself. This also means that care must be taken to ensure that our payload does not contain any 0x00 byte in either code or data areas, to ensure that is skipped by PKCS#1.5 unpadding.  

Finally, after writing a payload that calls the syscall 0x53 and outputs the result, we can submit it to `coderunner` and get our flag!
[Here](./solve2.py) is the full solver code.