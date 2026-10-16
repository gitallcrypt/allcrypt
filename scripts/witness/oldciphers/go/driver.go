// go-krypto's block ciphers (RyuaNerin/go-krypto), pure Go, and
// Nirusu/PRESENT.go's PRESENT as a witness speaking ../nessie/driver.h's
// request format. The cipher is the one argument - lea, hight or
// present - and requests are one per line on stdin,
//
//     enc <key hex> <block hex>          one block
//     dec <key hex> <block hex>
//     enc-n <key hex> <block hex> <n>    the block encrypted n times over
//     dec-n <key hex> <block hex> <n>
//
// answered with the result in lowercase hex, or "error lengths" or
// "error op".
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"crypto/cipher"

	present "github.com/Nirusu/PRESENT.go"
	"github.com/RyuaNerin/go-krypto/hight"
	"github.com/RyuaNerin/go-krypto/lea"
)

var ciphers = map[string]struct {
	new   func([]byte) (cipher.Block, error)
	block int
}{
	"lea":   {lea.NewCipher, lea.BlockSize},
	"hight": {hight.NewCipher, hight.BlockSize},
	// PRESENT's 31 rounds. The package keeps the round count in a global
	// that NewCipher sets, so a program uses one round count.
	"present": {func(key []byte) (cipher.Block, error) { return present.NewCipher(key, 31) },
		present.BlockSize},
}

func main() {
	if len(os.Args) != 2 || ciphers[os.Args[1]].new == nil {
		fmt.Fprintln(os.Stderr, "usage: driver lea|hight|present")
		os.Exit(2)
	}
	chosen := ciphers[os.Args[1]]
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) < 3 {
			fmt.Fprintln(out, "error op")
			continue
		}
		op := f[0]
		iterated := op == "enc-n" || op == "dec-n"
		decrypting := op == "dec" || op == "dec-n"
		if !iterated && op != "enc" && op != "dec" {
			fmt.Fprintln(out, "error op")
			continue
		}
		key, err1 := hex.DecodeString(f[1])
		block, err2 := hex.DecodeString(f[2])
		count := 1
		if iterated {
			n, err := strconv.Atoi(strings.Join(f[3:], ""))
			if len(f) != 4 || err != nil || n < 1 {
				err1 = fmt.Errorf("count")
			}
			count = n
		} else if len(f) != 3 {
			err1 = fmt.Errorf("fields")
		}
		if err1 != nil || err2 != nil || len(block) != chosen.block {
			fmt.Fprintln(out, "error lengths")
			continue
		}
		c, err := chosen.new(key)
		if err != nil {
			fmt.Fprintln(out, "error lengths")
			continue
		}
		for i := 0; i < count; i++ {
			if decrypting {
				c.Decrypt(block, block)
			} else {
				c.Encrypt(block, block)
			}
		}
		fmt.Fprintln(out, hex.EncodeToString(block))
	}
}
