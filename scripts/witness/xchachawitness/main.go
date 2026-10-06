// golang.org/x/crypto's XChaCha20, XChaCha20-Poly1305 and HChaCha20, one
// request a line, for scripts/make_xchacha_vectors.py:
//
//	hchacha KEY NONCE16             -> subkey
//	stream KEY NONCE24 COUNTER IN   -> keystream XOR IN
//	seal KEY NONCE24 AAD IN         -> ciphertext || tag
//
// Hex in and out; "-" is empty.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

func unhex(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for in.Scan() {
		f := strings.Fields(in.Text())
		var out []byte
		switch f[0] {
		case "hchacha":
			o, err := chacha20.HChaCha20(unhex(f[1]), unhex(f[2]))
			if err != nil {
				panic(err)
			}
			out = o
		case "stream":
			c, err := chacha20.NewUnauthenticatedCipher(unhex(f[1]), unhex(f[2]))
			if err != nil {
				panic(err)
			}
			n, _ := strconv.ParseUint(f[3], 10, 32)
			c.SetCounter(uint32(n))
			src := unhex(f[4])
			out = make([]byte, len(src))
			c.XORKeyStream(out, src)
		case "seal":
			a, err := chacha20poly1305.NewX(unhex(f[1]))
			if err != nil {
				panic(err)
			}
			out = a.Seal(nil, unhex(f[2]), unhex(f[4]), unhex(f[3]))
		}
		fmt.Printf("%x\n", out)
	}
}
