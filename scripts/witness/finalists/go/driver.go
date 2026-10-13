// dchest's pure Go BLAKE-224, -256 (blake256) and BLAKE-384, -512
// (blake512). One request per line on stdin, "NAME PATH", answered with
// the lowercase hex digest of the file's bytes under NAME, or "error".
// The data goes in in pieces of 1, 2, 3 ... bytes.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/dchest/blake256"
	"github.com/dchest/blake512"
)

func main() {
	makers := map[string]func() hash.Hash{
		"blake224": blake256.New224, "blake256": blake256.New,
		"blake384": blake512.New384, "blake512": blake512.New,
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		if len(fields) != 2 || makers[fields[0]] == nil {
			fmt.Println("error")
			continue
		}
		data, err := os.ReadFile(fields[1])
		if err != nil {
			fmt.Println("error")
			continue
		}
		h := makers[fields[0]]()
		for at, step := 0, 1; at < len(data); at, step = at+step, step+1 {
			h.Write(data[at:min(at+step, len(data))])
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
	}
}
