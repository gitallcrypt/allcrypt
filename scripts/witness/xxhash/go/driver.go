// Four Go xxHash packages, one per witness, named by the first argument:
// oneofone (OneOfOne/xxhash: xxh32, xxh64), cespare (cespare/xxhash v2:
// xxh64), pierrec (pierrec/xxHash: xxh32, xxh64) and zeebo (zeebo/xxh3:
// xxh3, xxh128). Built for GOARCH=386, where each takes its portable Go
// path - zeebo/xxh3's vector code is amd64 and arm64 only, and needs a
// CPU feature package this build does not fetch.
//
// One request per line on stdin, "NAME KEY PATH", KEY "seed:" and
// sixteen hex digits; answered with the big endian hash of the file's
// bytes as lowercase hex, or "error". None of the four takes an XXH3
// secret. The data goes in in pieces of 1, 2, 3 ... bytes.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"

	"github.com/OneOfOne/xxhash"
	cespare "github.com/cespare/xxhash/v2"
	"github.com/pierrec/xxHash/xxHash32"
	"github.com/pierrec/xxHash/xxHash64"
	"github.com/zeebo/xxh3"
)

func hasher(witness, name string, seed uint64) hash.Hash {
	small := seed <= 0xffffffff
	switch {
	case witness == "oneofone" && name == "xxh32" && small:
		return xxhash.NewS32(uint32(seed))
	case witness == "oneofone" && name == "xxh64":
		return xxhash.NewS64(seed)
	case witness == "cespare" && name == "xxh64":
		return cespare.NewWithSeed(seed)
	case witness == "pierrec" && name == "xxh32" && small:
		return xxHash32.New(uint32(seed))
	case witness == "pierrec" && name == "xxh64":
		return xxHash64.New(seed)
	case witness == "zeebo" && name == "xxh3":
		return xxh3.NewSeed(seed)
	case witness == "zeebo" && name == "xxh128":
		return xxh3.NewSeed128(seed)
	}
	return nil
}

func answer(witness, name, key, path string) string {
	digits, ok := strings.CutPrefix(key, "seed:")
	if !ok || len(digits) != 16 {
		return "error"
	}
	seed, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return "error"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "error"
	}
	h := hasher(witness, name, seed)
	if h == nil {
		return "error"
	}
	for at, step := 0, 1; at < len(data); at, step = at+step, step+1 {
		h.Write(data[at:min(at+step, len(data))])
	}
	// The value, big endian. Sum is no help for that: pierrec/xxHash's
	// appends it little endian, the others big endian.
	var sum []byte
	switch v := h.(type) {
	case hash.Hash32:
		sum = binary.BigEndian.AppendUint32(nil, v.Sum32())
	case hash.Hash64:
		sum = binary.BigEndian.AppendUint64(nil, v.Sum64())
	default:
		sum = h.Sum(nil) // zeebo/xxh3's 128 bits: high half first
	}
	return hex.EncodeToString(sum)
}

func main() {
	witness := os.Args[1]
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 1<<16)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		parts := strings.Fields(in.Text())
		if len(parts) != 3 {
			fmt.Fprintln(out, "error")
		} else {
			fmt.Fprintln(out, answer(witness, parts[0], parts[1], parts[2]))
		}
		out.Flush()
	}
}
