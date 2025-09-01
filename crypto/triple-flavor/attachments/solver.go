package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func truncatedSHA256(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:16]
}

func xor(a, b []byte) []byte {
	l := min(len(b), len(a))
	res := make([]byte, l)
	for i := range res {
		res[i] = a[i] ^ b[i]
	}
	return res
}

func nextProduct(a []byte, r int) func() []byte {
	p := make([]byte, r)
	x := make([]int, len(p))
	return func() []byte {
		p := p[:len(x)]
		for i, xi := range x {
			p[i] = a[xi]
		}
		for i := len(x) - 1; i >= 0; i-- {
			x[i]++
			if x[i] < len(a) {
				break
			}
			x[i] = 0
			if i <= 0 {
				x = x[0:0]
				break
			}
		}
		return p
	}
}

func main() {
	const SEED_LEN = 5

	data, _ := hex.DecodeString(os.Args[1])
	alph := []byte("abcdefghijklmnopqrstuvwxyz0123456789")

	iv1 := data[:16]
	iv2 := data[16:32]
	ct := data[32:64]

	iv2_mod_1 := make([]byte, len(iv2)+1)
	iv2_mod_2 := make([]byte, len(iv2)+1)
	copy(iv2_mod_1, iv2)
	copy(iv2_mod_2, iv2)
	iv2_mod_1[len(iv2)] = byte(0)
	iv2_mod_2[len(iv2)] = byte(1)
	twk_0 := truncatedSHA256(iv2_mod_1)
	twker := xor(twk_0, truncatedSHA256(iv2_mod_2))

	cors := make(map[string]string)
	np := nextProduct(alph, SEED_LEN)
	encIV := make([]byte, aes.BlockSize)
	encEncIV := make([]byte, aes.BlockSize)

	for seed := np(); len(seed) > 0; seed = np() {
		k2 := truncatedSHA256(seed)
		cipher, err := aes.NewCipher(k2)
		if err != nil {
			panic(err)
		}
		cipher.Encrypt(encIV, iv1)
		cipher.Encrypt(encEncIV, encIV)
		tmp := xor(encIV, encEncIV)
		cors[hex.EncodeToString(xor(tmp, twker))] = string(seed)
	}

	np = nextProduct(alph, SEED_LEN)
	tmp2 := make([]byte, aes.BlockSize)
	tmp3 := make([]byte, aes.BlockSize)
	var token2, token3 string

	for seed := np(); len(seed) > 0; seed = np() {
		k3 := truncatedSHA256(seed)
		cipher, err := aes.NewCipher(k3)
		if err != nil {
			panic(err)
		}

		cipher.Encrypt(tmp2, xor(ct[:16], iv2))
		cipher.Encrypt(tmp3, xor(ct[16:], tmp2))
		mitm := hex.EncodeToString(xor(tmp2, tmp3))
		v, ok := cors[mitm]
		if ok {
			token2 = v
			token3 = string(seed)
			break
		}
	}
	k3 := truncatedSHA256([]byte(token3))
	k2 := truncatedSHA256([]byte(token2))

	CBCBlock, err := aes.NewCipher(k3)
	if err != nil {
		panic(err)
	}

	OFBBlock, err := aes.NewCipher(k2)
	if err != nil {
		panic(err)
	}

	modeCBC := cipher.NewCBCEncrypter(CBCBlock, iv2)
	stremOFB := cipher.NewOFB(OFBBlock, iv1)

	pt := make([]byte, aes.BlockSize)
	modeCBC.CryptBlocks(pt, ct[:16])
	pt = xor(pt, twk_0)
	stremOFB.XORKeyStream(pt, pt)

	np = nextProduct(alph, SEED_LEN)
	tmp4 := make([]byte, aes.BlockSize)

	for seed := np(); len(seed) > 0; seed = np() {
		k1 := truncatedSHA256(seed)
		cipher, err := aes.NewCipher(k1)
		if err != nil {
			panic(err)
		}
		cipher.Decrypt(tmp4, pt)
		if hex.EncodeToString(tmp4) == strings.Repeat("aa", 16) {
			fmt.Println(string(seed) + token2 + token3)
			break
		}
	}
}
