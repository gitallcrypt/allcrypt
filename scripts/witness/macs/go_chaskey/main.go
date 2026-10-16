// dgryski/go-chaskey as a witness: `chaskey <rounds> <key hex> <msg hex>`
// per line ("-" for empty), rounds 8 or 12; the 16 byte tag in hex, or
// "error ...".
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	chaskey "github.com/dgryski/go-chaskey"
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
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) != 4 || f[0] != "chaskey" || len(f[2]) != 32 {
			fmt.Fprintln(out, "error request")
			out.Flush()
			continue
		}
		k := unhex(f[2])
		var key [4]uint32
		for i := range key {
			key[i] = binary.LittleEndian.Uint32(k[4*i:])
		}
		var h *chaskey.H
		switch f[1] {
		case "8":
			h = chaskey.New(key)
		case "12":
			h = chaskey.New12(key)
		default:
			fmt.Fprintln(out, "error unsupported")
			out.Flush()
			continue
		}
		fmt.Fprintln(out, hex.EncodeToString(h.MAC(unhex(f[3]), nil)))
		out.Flush()
	}
}
