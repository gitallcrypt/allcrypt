// golang.org/x/crypto's NaCl packages, one request a line, for
// scripts/make_nacl_vectors.py:
//
//	hsalsa KEY IN16                 -> HSalsa20 output
//	secretbox KEY NONCE MSG         -> tag || ciphertext
//	secretbox_open KEY NONCE BOX    -> message, or FAIL
//	beforenm PK SK                  -> box key
//	box PK SK NONCE MSG             -> tag || ciphertext
//	box_open PK SK NONCE BOX        -> message, or FAIL
//	seal PK MSG                     -> sealed box (random ephemeral key)
//	seal_open PK SK SEALED          -> message, or FAIL
//	sign SEED MSG                   -> signature || message
//	sign_open PK SIGNED             -> message, or FAIL
//	auth KEY MSG                    -> HMAC-SHA-512-256 tag
//
// Hex in and out; "-" is empty.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/salsa20/salsa"
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

func k32(s string) *[32]byte {
	var k [32]byte
	copy(k[:], unhex(s))
	return &k
}

func n24(s string) *[24]byte {
	var n [24]byte
	copy(n[:], unhex(s))
	return &n
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<24), 1<<24)
	for in.Scan() {
		f := strings.Fields(in.Text())
		var out []byte
		ok := true
		switch f[0] {
		case "hsalsa":
			var o [32]byte
			var i [16]byte
			copy(i[:], unhex(f[2]))
			salsa.HSalsa20(&o, &i, k32(f[1]), &salsa.Sigma)
			out = o[:]
		case "secretbox":
			out = secretbox.Seal(nil, unhex(f[3]), n24(f[2]), k32(f[1]))
		case "secretbox_open":
			out, ok = secretbox.Open(nil, unhex(f[3]), n24(f[2]), k32(f[1]))
		case "beforenm":
			var k [32]byte
			box.Precompute(&k, k32(f[1]), k32(f[2]))
			out = k[:]
		case "box":
			out = box.Seal(nil, unhex(f[4]), n24(f[3]), k32(f[1]), k32(f[2]))
		case "box_open":
			out, ok = box.Open(nil, unhex(f[4]), n24(f[3]), k32(f[1]), k32(f[2]))
		case "seal":
			var err error
			out, err = box.SealAnonymous(nil, unhex(f[2]), k32(f[1]), rand.Reader)
			ok = err == nil
		case "seal_open":
			out, ok = box.OpenAnonymous(nil, unhex(f[3]), k32(f[1]), k32(f[2]))
		case "sign":
			private := ed25519.NewKeyFromSeed(unhex(f[1]))
			var key [64]byte
			copy(key[:], private)
			out = sign.Sign(nil, unhex(f[2]), &key)
		case "sign_open":
			out, ok = sign.Open(nil, unhex(f[2]), k32(f[1]))
		case "auth":
			var key [32]byte
			copy(key[:], unhex(f[1]))
			tag := auth.Sum(unhex(f[2]), &key)
			out = tag[:]
		default:
			panic("unknown request " + f[0])
		}
		if !ok {
			fmt.Println("FAIL")
		} else if len(out) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(hex.EncodeToString(out))
		}
	}
}
