// gVisor's Jenkins one-at-a-time (gvisor.dev/gvisor/pkg/tcpip/hash/jenkins),
// which gVisor's TCP stack uses. Its state is the exported Sum32 type, so
// a seed is a starting value. One request per line on stdin, "NAME KEY
// PATH", NAME joaat and KEY "seed:" and eight hex digits; answered with
// the hash of the file's bytes as lowercase big endian hex, or "error".
// The data goes in in pieces of 1, 2, 3 ... bytes.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
)

func answer(name, key, path string) string {
	digits, ok := strings.CutPrefix(key, "seed:")
	if name != "joaat" || !ok || len(digits) != 8 {
		return "error"
	}
	seed, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return "error"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "error"
	}
	h := jenkins.Sum32(seed)
	for at, step := 0, 1; at < len(data); at, step = at+step, step+1 {
		h.Write(data[at:min(at+step, len(data))])
	}
	return fmt.Sprintf("%08x", h.Sum32())
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 1<<16)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		parts := strings.Fields(in.Text())
		if len(parts) != 3 {
			fmt.Fprintln(out, "error")
		} else {
			fmt.Fprintln(out, answer(parts[0], parts[1], parts[2]))
		}
		out.Flush()
	}
}
