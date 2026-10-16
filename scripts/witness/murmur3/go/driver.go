// Two Go MurmurHash3 packages, one per witness, named by the first
// argument: spaolacci (spaolacci/murmur3) and twmb (twmb/murmur3), each
// with x86_32 and x64_128 and neither with x86_128. Built for GOARCH=386,
// where twmb/murmur3 takes its Go path rather than its amd64 assembly.
//
// One request per line on stdin, "NAME KEY PATH", KEY "seed:" and eight
// hex digits; answered with the hash of the file's bytes, each word big
// endian, first word first, or "error". The data goes in in pieces of 1,
// 2, 3 ... bytes.
package main

import (
	"bufio"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"

	spaolacci "github.com/spaolacci/murmur3"
	twmb "github.com/twmb/murmur3"
)

type hash128 interface {
	hash.Hash
	Sum128() (uint64, uint64)
}

func pieces(h hash.Hash, data []byte) {
	for at, step := 0, 1; at < len(data); at, step = at+step, step+1 {
		h.Write(data[at:min(at+step, len(data))])
	}
}

func answer(witness, name, key, path string) string {
	digits, ok := strings.CutPrefix(key, "seed:")
	if !ok || len(digits) != 8 {
		return "error"
	}
	seed64, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return "error"
	}
	seed := uint32(seed64)
	data, err := os.ReadFile(path)
	if err != nil {
		return "error"
	}
	switch name {
	case "murmur3_32":
		var h hash.Hash32
		if witness == "spaolacci" {
			h = spaolacci.New32WithSeed(seed)
		} else {
			h = twmb.SeedNew32(seed)
		}
		pieces(h, data)
		return fmt.Sprintf("%08x", h.Sum32())
	case "murmur3_x64_128":
		var h hash128
		if witness == "spaolacci" {
			h = spaolacci.New128WithSeed(seed)
		} else {
			// twmb/murmur3 seeds the two halves apart; the reference
			// seeds both with the one 32 bit seed.
			h = twmb.SeedNew128(uint64(seed), uint64(seed))
		}
		pieces(h, data)
		h1, h2 := h.Sum128()
		return fmt.Sprintf("%016x%016x", h1, h2)
	}
	return "error"
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
