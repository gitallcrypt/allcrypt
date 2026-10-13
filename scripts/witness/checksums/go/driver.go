// The checksums in Go's standard library: crc32 and crc32c (hash/crc32's
// IEEE and Castagnoli tables), adler32, and hash/fnv's FNV-1 and FNV-1a at
// 32, 64 and 128 bits as fnvVARIANT_BITS. One request per line on stdin, "NAME
// PATH", answered with the checksum of the file's bytes as lowercase big
// endian hex (the hash's Sum), or "error". The data goes in in pieces of
// 1, 2, 3 ... bytes.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
	"os"
	"strings"
)

func named(name string) hash.Hash {
	switch name {
	case "crc32":
		return crc32.NewIEEE()
	case "crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "adler32":
		return adler32.New()
	case "fnv1_32":
		return fnv.New32()
	case "fnv1a_32":
		return fnv.New32a()
	case "fnv1_64":
		return fnv.New64()
	case "fnv1a_64":
		return fnv.New64a()
	case "fnv1_128":
		return fnv.New128()
	case "fnv1a_128":
		return fnv.New128a()
	}
	return nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 8192), 8192)
	for in.Scan() {
		parts := strings.Fields(in.Text())
		if len(parts) != 2 {
			fmt.Println("error")
			continue
		}
		h := named(parts[0])
		data, err := os.ReadFile(parts[1])
		if h == nil || err != nil {
			fmt.Println("error")
			continue
		}
		for at, step := 0, 1; at < len(data); at, step = at+step, step+1 {
			h.Write(data[at:min(at+step, len(data))])
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
	}
}
