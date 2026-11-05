// pedroalbanese/trivium as a witness: `stream trivium <key hex> <iv hex>
// <length>` per line; the first <length> bytes of keystream in hex, or
// "error ...". build.sh copies the package's trivium.go beside this file
// as package trivium.
//
// The package loads the key and IV as the Trivium specification writes
// them, where the eSTREAM submission and its test vectors - and allcrypt -
// load them in the opposite order, both by byte and by bit. This driver
// turns one into the other exactly as the package's own test does for the
// eSTREAM vectors: the bytes reversed, and the bits of each byte reversed.
// The keystream bytes need no conversion.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"hwwitness/trivium"
)

func reverse(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = r<<1 | (b>>uint(i))&1
	}
	return r
}

func load(h string) ([trivium.KeyLength]byte, bool) {
	var out [trivium.KeyLength]byte
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != trivium.KeyLength {
		return out, false
	}
	for i, b := range raw {
		out[trivium.KeyLength-1-i] = reverse(b)
	}
	return out, true
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 1<<16)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		f := strings.Fields(in.Text())
		answer := "error request"
		if len(f) == 5 && f[0] == "stream" {
			if f[1] != "trivium" {
				answer = "error unsupported"
			} else {
				key, okKey := load(f[2])
				iv, okIV := load(f[3])
				n, err := strconv.Atoi(f[4])
				if !okKey || !okIV || err != nil {
					answer = "error key or iv length"
				} else {
					t := trivium.NewTrivium(key, iv)
					ks := make([]byte, n)
					for i := range ks {
						ks[i] = t.NextByte()
					}
					answer = hex.EncodeToString(ks)
				}
			}
		}
		fmt.Fprintln(out, answer)
		out.Flush()
	}
}
