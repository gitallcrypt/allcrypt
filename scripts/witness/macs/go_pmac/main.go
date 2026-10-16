// miscreant.go's PMAC as a witness: `pmac aes <key hex> <msg hex>` per
// line ("-" for empty), the tag in hex, or "error ...". AES only.
package main

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/miscreant/miscreant.go/pmac"
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
	in.Buffer(make([]byte, 1<<20), 1<<22)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) != 4 || f[0] != "pmac" {
			fmt.Fprintln(out, "error request")
		} else if f[1] != "aes" {
			fmt.Fprintln(out, "error unsupported")
		} else if c, err := aes.NewCipher(unhex(f[2])); err != nil {
			fmt.Fprintln(out, "error", err)
		} else {
			m := pmac.New(c)
			m.Write(unhex(f[3]))
			fmt.Fprintln(out, hex.EncodeToString(m.Sum(nil)))
		}
		out.Flush()
	}
}
