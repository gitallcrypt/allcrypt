// go-krypto's LSH (RyuaNerin/go-krypto), pure Go, at the six sizes the
// standard names. One request per line on stdin, "lshWIDTH_BITS PATH",
// answered with the lowercase hex digest of the file's bytes, or "error".
// The data goes in in pieces of 1, 2, 3 ... bytes.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/RyuaNerin/go-krypto/lsh256"
	"github.com/RyuaNerin/go-krypto/lsh512"
)

func main() {
	makers := map[string]func() hash.Hash{
		"lsh256_224": lsh256.New224, "lsh256_256": lsh256.New,
		"lsh512_224": lsh512.New224, "lsh512_256": lsh512.New256,
		"lsh512_384": lsh512.New384, "lsh512_512": lsh512.New,
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
